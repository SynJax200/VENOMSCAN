# Production deployment runbook

Step-by-step plan to take VENOMSCAN from this repository to a public HTTPS
installation on a VPS. Every command assumes the repository root as the working
directory. Follow the sections in order; each ends with a check you can verify.

**Target topology:** one VPS running the prod compose stack (Caddy, web, api,
worker, postgres, redis). Only Caddy publishes host ports (80/443). TLS is issued
by Caddy through ACME as soon as `DOMAIN` resolves to the host.

> **Using the deployment bundle?** This runbook is the manual path. The bundle
> adds two helpers: `./install.sh` (checks Docker/ports/DNS, generates secrets,
> downloads Nuclei, builds and starts the stack, waits for health) and
> `./smoke.sh` (container, TLS, header, health, login, integrations and
> registration-state checks). Everything below still applies for the manual
> steps and the 18-point acceptance list.

---

## 0. Pre-flight

- VPS: Ubuntu 22.04/24.04, 4 vCPU, 8 GB RAM, 40 GB disk (images include Chromium
  and the Nuclei binary), public IPv4 (IPv6 optional).
- DNS control for the domain you will use.
- The repository on the host (`git clone <repo-url>` or `rsync` it).
- Outbound HTTPS from the host (Docker pulls, uv/pip/npm during `--build`).
- Targets you intend to scan are **owned by you or covered by written authorization**.

---

## 1. DNS

1. Create an `A` record `@` (or the chosen subdomain) → the VPS IPv4. Add an
   `AAAA` only if the host has working IPv6.
2. Optional `CNAME www` → `yourdomain.example`.
3. Wait for propagation and confirm from your workstation:

```bash
dig +short scan.example.com        # must print the VPS IP
```

**Check:** the record resolves to the VPS before starting the stack — Caddy
requests the certificate on first start.

---

## 2. Host preparation and firewall

```bash
sudo apt update && sudo apt upgrade -y
curl -fsSL https://get.docker.com | sudo sh          # Docker Engine + compose plugin
sudo usermod -aG docker "$USER" && newgrp docker
docker compose version

sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 443/udp
sudo ufw enable
```

- Publish nothing else: the compose file exposes ports only on `caddy`.
- Docker inserts its own forwarding rules ahead of `ufw`, so keep the compose
  ports at 80/443 and do not add `ports:` to api/web/postgres/redis/worker.
- SSH hardening (optional but recommended): key-only auth, disable password login.

**Check:** `ss -tlnp | grep -E ':(80|443)\s'` is empty before the stack starts.

---

## 3. Code, env file and secret rotation

```bash
git clone <repo-url> venomscan && cd venomscan
cp infra/compose/.env.prod.example infra/compose/.env.prod
chmod 600 infra/compose/.env.prod
```

Generate fresh secrets (never reuse the example values):

```bash
openssl rand -hex 32      # SECRET_KEY
openssl rand -hex 24      # POSTGRES_PASSWORD
```

Edit `infra/compose/.env.prod`:

| Variable | Value | Notes |
| --- | --- | --- |
| `DOMAIN` | `scan.example.com` | Public hostname from step 1 |
| `ACME_EMAIL` | monitored mailbox | Let's Encrypt expiry notices |
| `API_BASE` | `https://scan.example.com` | Exact origin, no trailing slash |
| `WEB_BASE` | `https://scan.example.com` | Same origin as `API_BASE` |
| `CORS_ORIGINS` | `https://scan.example.com` | Must match exactly or the UI calls fail CSRF/origin checks |
| `SECRET_KEY` | `openssl rand -hex 32` | Rotating invalidates sessions, CSRF tokens and every signed report link |
| `POSTGRES_PASSWORD` | `openssl rand -hex 24` | Only used when the DB volume is first initialized |
| `ALLOW_PRIVATE_TARGETS` | `false` | Keep false on an internet-facing host |
| `ALLOW_REGISTRATION` | `false` (set `true` only for onboarding) | See step 7 |
| `TRUSTED_PROXIES` | empty | Private/loopback peers (Caddy) are trusted automatically |
| `AI_ALLOWED_HOSTS` | `api.openai.com,api.anthropic.com` | Cloud AI base URLs must be HTTPS and match |
| `LLM_API_KEY` | provider key (optional) | Empty keeps the deterministic analysis path |
| `OOB_ENABLED` | `false` on a public VPS | See the OOB note in step 9 |
| `NUCLEI_ENABLED` | `true` | Needs the binary from step 4 |

Rotate `POSTGRES_PASSWORD` **before** the first `up`; changing it afterwards
requires `ALTER ROLE` inside the running database.

**Check:** `grep -E '^(DOMAIN|SECRET_KEY|POSTGRES_PASSWORD)=' infra/compose/.env.prod`
shows your values (do not paste secrets into tickets or chat).

---

## 4. Nuclei binary and templates

The stack mounts a review-approved Linux binary at `/opt/nuclei` and the bundled
templates at `/nuclei-templates`.

```bash
mkdir -p .nuclei-bin
curl -fsSL -o /tmp/nuclei.zip \
  https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_amd64.zip
unzip -o /tmp/nuclei.zip -d .nuclei-bin && chmod 755 .nuclei-bin/nuclei
.nuclei-bin/nuclei -version                 # expect v3.11.1
```

- The templates directory shipped in the repo (`nuclei-templates/`) is mounted
  read-only; review any template you add — third-party templates carry their own
  licenses and may be aggressive.
- On an ARM VPS use the `linux_arm64` asset and confirm the architecture of your
  host first (`uname -m`).

**Check:** `.nuclei-bin/nuclei -version` prints the version on the host.

---

## 5. First start

```bash
docker compose --env-file infra/compose/.env.prod \
  -f infra/compose/docker-compose.prod.yml up -d --build
docker compose --env-file infra/compose/.env.prod \
  -f infra/compose/docker-compose.prod.yml ps
```

- Build takes several minutes (Python venv, Next production build, Playwright
  Chromium).
- `postgres` and `redis` must report healthy before `api` starts; `caddy` starts
  once `api` is healthy.

**Check:** all services `Up`; `curl -sS https://scan.example.com/healthz`
returns `{"status":"ok",...}`.

---

## 6. TLS verification

```bash
curl -sSI https://scan.example.com | sed -n '1p;/strict-transport/p;/x-content-type/p;/^server/Ip'
echo | openssl s_client -connect scan.example.com:443 -servername scan.example.com 2>/dev/null \
  | openssl x509 -noout -issuer -subject -dates
```

Expect: `HTTP/2 200`, an HSTS header, `X-Content-Type-Options: nosniff`, no
`Server:` header, and a certificate issued by Let's Encrypt (R/E-series) for your
domain. Renewal is automatic; ports 80/443 must stay reachable for renewals.

**Check:** certificate issuer and subject match the domain, not `localhost`.

---

## 7. Onboarding users and closing sign-up

1. Set `ALLOW_REGISTRATION=true` in `infra/compose/.env.prod` and apply it:

```bash
docker compose --env-file infra/compose/.env.prod \
  -f infra/compose/docker-compose.prod.yml up -d api
```

2. Open `https://scan.example.com`, register the accounts your team needs
   (registration is CSRF-protected and audited as `auth.register`). The first
   account becomes the administrator; everyone after that is a regular user.
3. Set `ALLOW_REGISTRATION=false` in `infra/compose/.env.prod` and apply it:

```bash
docker compose --env-file infra/compose/.env.prod \
  -f infra/compose/docker-compose.prod.yml up -d api
```

**Check:** a new `POST /api/auth/register` returns `403 Registration is closed on
this installation`; existing users still log in.

---

## 8. Demo data removal

A fresh VPS deployment contains **no** demo data; the demo user and target are
only created when someone runs `uv run python -m venomscan_api.seed` manually.
If this host was previously used as a trial and you ran that command (or set
`SEED_TARGET_URL`), remove the demo rows before handover:

```bash
docker compose --env-file infra/compose/.env.prod \
  -f infra/compose/docker-compose.prod.yml exec -T postgres \
  psql -U venom -d venomscan -c \
  "DELETE FROM audit_events WHERE actor_id = (SELECT id FROM users WHERE email='demo@venomscan.local');
   DELETE FROM users WHERE email='demo@venomscan.local';"
```

Deleting the user cascades to their targets, scans, findings, endpoints, reports
and AI analyses. Also rotate `SECRET_KEY`, `POSTGRES_PASSWORD` and any provider
key that was used during the trial, and remove `demo@venomscan.local` credentials
from any notes.

**Check:** Settings/Dashboard shows only team-owned targets and no `Demo Analyst`.

---

## 9. Out-of-band (OOB) listener

The OOB listener used to verify SSRF/XXE callbacks binds inside the worker
container on a random port and is **not reachable from the internet** in this
topology. On a public VPS set `OOB_ENABLED=false`; SSRF findings are then
confirmed by response evidence (status, latency, body) instead of a callback.
If you need OOB verification, expose a dedicated port range and set
`OOB_PUBLIC_BASE_URL` to a hostname resolving to the worker — until then, treat
OOB as a local-lab feature.

**Check:** `OOB_ENABLED=false` is present in the api and worker environment
(`docker compose ... config | grep OOB_ENABLED`).

---

## 10. Backups

```bash
scripts/backup.sh     # backups/venomscan-<UTC>.dump.gz + .sha256
```

- Schedule daily (cron/systemd) and copy the artifacts off-host; they contain
  reports, the audit trail, authorization records and encrypted credential blobs
  (encrypted with `SECRET_KEY` — back that key up separately, it is not in the DB).
- Restore drill quarterly: stop `api worker web`, run
  `scripts/restore.sh backups/<file>.dump.gz`, start them again, verify
  `/healthz` and one report's SHA-256.

**Check:** a restore drill on a scratch volume succeeds once before go-live.

---

## 11. Post-deploy verification checklist

Run through this list against the public hostname; all must pass before handover.

| # | Check | How | Expected |
| --- | --- | --- | --- |
| 1 | Health | `curl -sS https://<domain>/healthz` | `status: ok`, current version |
| 2 | TLS | section 6 | valid Let's Encrypt cert, HSTS present, no `Server` header |
| 3 | UI loads | open `https://<domain>` | login page renders; no console errors |
| 4 | Auth | register/login, refresh page | session survives reload; logout returns 401 on `/api/auth/me` |
| 5 | CSRF | POST without `X-CSRF-Token` | `403` |
| 6 | Registration closed | step 7 | `403 Registration is closed` |
| 7 | Target onboarding | add a target you own, complete ownership verification | target shows verified, expiry date set |
| 8 | Safe scan | run a `safe` scan on that verified target | completes; findings render with evidence |
| 9 | Active scan | run `active` with the consent checkbox | completes; Nuclei findings (`nuclei.*`) appear |
| 10 | Integrations | Settings → Integrations | Nuclei `enabled` + `binary_present`; templates present |
| 11 | Reports | create PDF, open the signed link | PDF downloads; tampering with the token returns `403`; SHA-256 matches |
| 12 | Audit | Activity page | register, login, target, scan and report actions all listed |
| 13 | Lockout | 5 failed logins for one account | `429` with `Retry-After`; another account from the same IP can still sign in |
| 14 | SSE | open a running scan | timeline updates live (no buffering) |
| 15 | Worker | `docker compose ... logs worker` | no tracebacks; scan tasks executed |
| 16 | Restart resilience | `docker compose ... restart api` | stack returns healthy; sessions survive (Redis-backed auth state) |
| 17 | Backup | `scripts/backup.sh` | dump + checksum written; file size non-zero |
| 18 | Demo removed | step 8 | no demo target/user |

API equivalents for 4–13 are in `scripts/load_test.py` (login + dashboard p95).
SSE can be checked with `curl -N https://<domain>/api/scans/<id>/events/stream`
after logging in and passing the `vs_session` cookie.

---

## 12. Upgrades and routine operations

```bash
scripts/backup.sh
git pull
docker compose --env-file infra/compose/.env.prod \
  -f infra/compose/docker-compose.prod.yml up -d --build
docker compose --env-file infra/compose/.env.prod \
  -f infra/compose/docker-compose.prod.yml ps
```

- Startup is idempotent: tables and additive columns are created automatically;
  take the backup first anyway.
- Watch `docker compose ... logs -f api worker` and `/audit` after each upgrade.
- Cap Docker logs on the host (e.g. `/etc/docker/daemon.json` with
  `"log-driver":"json-file","log-opts":{"max-size":"20m","max-file":"5"}`) so
  months of scan logs cannot fill the disk.
- Keep `ALLOW_PRIVATE_TARGETS=false`, rotate `SECRET_KEY` only when you intend to
  invalidate every session and signed report link, and re-run section 11 after
  major upgrades.

---

## Rollback

1. `docker compose ... down` (volumes persist).
2. `git checkout <previous-tag>` and `up -d --build`.
3. If a schema/data problem remains, restore the pre-upgrade backup (step 10).
