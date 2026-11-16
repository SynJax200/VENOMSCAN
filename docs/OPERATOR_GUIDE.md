# VENOMSCAN operator guide

Audience: the person running a VENOMSCAN installation for a team. For the assessment
workflow see [USER_GUIDE.md](USER_GUIDE.md); for the safety contract see
[SAFETY.md](SAFETY.md).

## 1. Requirements

- Docker Engine 24+ with Compose v2 (production), or Python 3.12 + Node 22 + uv (local dev)
- Linux host with ≥4 GB RAM and ≥2 vCPU for the production stack (Chromium, PDF rendering
  and concurrent scans are memory-hungry)
- A hostname with a DNS record pointing at the host, for automatic TLS
- Open egress to the targets you are authorized to test; inbound 80/443 for Caddy

## 2. Local development

```bash
cp .env.example .env                 # edit SECRET_KEY and datastore URLs
make db-up                           # Postgres :55432, Redis :56379
uv sync --all-packages
make api                             # http://127.0.0.1:8000
make web                             # http://localhost:3000
uv run python -m venomscan_api.seed  # demo user + verified local target + one scan
```

Demo credentials: `demo@venomscan.local` / `Venom-demo-123`. The seed scan targets the
API's own `/demo` fixture, so `ALLOW_PRIVATE_TARGETS=true` is required for it.
PDF reports need Chromium: `uv run playwright install chromium`.

## 3. Production deployment

Full step-by-step runbook (DNS, firewall, secrets, first start, TLS verification,
demo removal, post-deploy checklist): [DEPLOYMENT.md](DEPLOYMENT.md).

```bash
cp infra/compose/.env.prod.example infra/compose/.env.prod
$EDITOR infra/compose/.env.prod      # SECRET_KEY, POSTGRES_PASSWORD, DOMAIN, ACME_EMAIL
docker compose --env-file infra/compose/.env.prod \
  -f infra/compose/docker-compose.prod.yml up -d --build
```

Services and trust boundaries:

| Service | Purpose | Exposure |
| --- | --- | --- |
| `caddy` | TLS termination, HSTS, reverse proxy | 80/443 only |
| `web` | Next.js UI | internal 3000 |
| `api` | FastAPI control plane, report rendering | internal 8000 |
| `worker` | Celery scans (autoscale 2–6, recycles every 50 tasks) | internal |
| `postgres` | All state, including reports and audit | internal 5432 |
| `redis` | Celery broker + result backend | internal 6379 |

`SECRET_KEY` must be ≥32 random bytes (`openssl rand -hex 32`). Changing it invalidates
sessions, CSRF tokens **and every signed report link** — that is the revocation mechanism.
Set `COOKIE_SECURE=true` (already forced in the compose file) and `CORS_ORIGINS` to the
exact public origin.

Startup is idempotent: the API creates missing tables and additive columns/indexes. No
migration tool is required for upgrades, but take a backup first (below).

### TLS

Caddy obtains and renews certificates for `DOMAIN` automatically. For an internal trial
set `DOMAIN=localhost`; Caddy uses its local CA. Export and trust the root:

```bash
docker compose -f infra/compose/docker-compose.prod.yml \
  cp caddy:/data/caddy/pki/authorities/local/root.crt ./venomscan-local-ca.crt
```

For a public install, before the first start:

- Point an A/AAAA record for `DOMAIN` at the host and open 80/443 (HTTP-01/TLS-ALPN
  challenges, then renewals).
- Set `API_BASE`, `WEB_BASE` and `CORS_ORIGINS` to `https://<DOMAIN>` (exact origin, no
  trailing slash) — they feed session cookies, CSRF origin checks and generated report links.
- Set `ACME_EMAIL` to a monitored address and, for OOB checks, `OOB_PUBLIC_BASE_URL` to a
  hostname that resolves to this server.
- Keep `ALLOW_PRIVATE_TARGETS=false` and remove the demo seed/credentials before onboarding
  real users; rotate every placeholder secret.
- Register the team's accounts, then set `ALLOW_REGISTRATION=false` and restart `api` so the
  public host stops accepting new sign-ups.

Server-sent events are excluded from gzip at both layers and the Caddy route uses
`flush_interval -1` so scan timelines stream in real time.

### Demo data (optional)

The compose file defaults `SEED_TARGET_URL=http://api:8000/demo`, so a trial install can
scan its own fixture:

```bash
docker compose --env-file infra/compose/.env.prod \
  -f infra/compose/docker-compose.prod.yml exec api \
  /app/.venv/bin/python -m venomscan_api.seed
```

This creates `demo@venomscan.local` / `Venom-demo-123`, a verified target and one safe scan.
It only works when `ALLOW_PRIVATE_TARGETS=true` (a local trial — never on an internet-facing
install). Remove the demo user and target before handing the instance to real users.

### Optional integrations

- **Nuclei** — put a reviewed Linux binary at `<NUCLEI_BIN_DIR>/nuclei` (default
  `./.nuclei-bin`, mounted read-only at `/opt/nuclei`), keep reviewed templates in
  `NUCLEI_TEMPLATES_HOST`, then set `NUCLEI_ENABLED=true`. Build the binary with
  `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o .nuclei-bin/nuclei
  github.com/projectdiscovery/nuclei/v3/cmd/nuclei` or download the matching release
  archive. It only runs during `active` scans and only with the configured severities.
  Verify with Settings → Integrations.
- **Plugins** — mount a directory at `/plugins` and set `PLUGIN_DIRS`. Discovery never
  executes code; execution is subprocess-isolated. See
  [PLUGIN_AUTHORING.md](PLUGIN_AUTHORING.md).
- **Upstream proxy** — set `UPSTREAM_PROXY_URL` (http/https only) when outbound traffic
  must traverse a corporate proxy. Redirects are still scope- and SSRF-checked.
- **LLM** — configure in Settings → AI intelligence (key stored Fernet-encrypted) or with
  `LLM_*` variables. Leaving the key empty keeps deterministic analysis only.
- **Out-of-band listener** — `OOB_PUBLIC_BASE_URL` must be reachable by the targets under
  test for SSRF/XXE verification. Keep it loopback-only for local labs.

## 4. Monitoring and routine checks

- `GET /healthz` returns `{"status":"ok","version":…}`; the API container healthcheck uses it.
- `docker compose ... logs -f api worker` for scan errors and plugin warnings.
- Settings → Integrations shows whether Nuclei/Burp/proxy/plugins are active.
- Activity (`/audit`) shows every authorization, scan, import/export and report action.
- Dashboard p95 budget: run `uv run python scripts/load_test.py --scans 5` against a
  running instance. It fails if dashboard p95 exceeds 300 ms or a request errors.

## 5. Backup and restore runbook

**Backup** (reports, audit, credentials metadata and authorization history live in Postgres):

```bash
scripts/backup.sh
# → backups/venomscan-<UTC timestamp>.dump.gz and a .sha256 file
```

Schedule it daily with cron/systemd and copy backups off-host. The script also triggers a
Redis `SAVE`; scans themselves are restartable artifacts and are not preserved mid-run.

**Restore** (test quarterly):

1. Stop writers: `docker compose ... stop api worker web`.
2. Verify and restore: `scripts/restore.sh backups/venomscan-<stamp>.dump.gz`
   (`pg_restore --clean --if-exists`; the script refuses without a matching checksum when
   one exists).
3. Start writers: `docker compose ... start web api worker`.
4. Check `GET /healthz`; download a JSON or HTML report and confirm `sha256sum` matches the
   digest shown in the UI (`X-Content-SHA256`); PDFs carry the model digest in their footer
   but their file bytes depend on the renderer. Confirm login and `/audit` look correct.

The database password and `SECRET_KEY` are **not** in the dump. Store them in your password
manager; restoring with a different `SECRET_KEY` is fine but invalidates sessions and signed
links.

## 6. Upgrades

1. Back up first (`scripts/backup.sh`).
2. `git pull` and review `CHANGELOG`-style notes in [ROADMAP.md](ROADMAP.md).
3. `docker compose ... up -d --build`.
4. Run `uv run python -m pytest tests` and `cd apps/web && npm run build` when building from
   source outside Docker.
5. Verify: login, one safe scan against a lab target, one report download.

## 7. Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `409 Target is not verified` | Authorization missing/expired | Re-verify from the target page |
| `400 Active profile requires consent` | API-level consent missing | Re-submit with the consent checkbox |
| PDF report returns `503` | Chromium not installed in the API image | Rebuild the backend image (installs Chromium) |
| Scan stays queued | `TASK_MODE=celery` but no worker, or Redis down | Start `worker`, check `REDIS_URL` |
| SSE timeline frozen | Proxy buffering | Keep `flush_interval -1` for the stream route and `X-Accel-Buffering: no` |
| Nuclei never runs | Disabled, not active profile, or binary/templates missing | Settings → Integrations; see `NUCLEI_*` |
| Plugin ignored | Bad metadata or duplicate id | Check the warning in the scan timeline and `/learning` plugin catalogue |
| Burp import `422` | At least one URL is outside scope | Export only in-scope issues; imports are all-or-nothing |
| Target unreachable | SSRF guard blocking private ranges | Only for labs: `ALLOW_PRIVATE_TARGETS=true` |

## 8. Security hygiene

- Keep datastores off the public network; the compose file does this by default.
- Rotate `SECRET_KEY` and integration keys after any suspected exposure.
- Do not enable `ALLOW_PRIVATE_TARGETS` on internet-facing installs.
- Review third-party Nuclei templates and plugins before use; each has its own license.
- Treat Burp exports, report links and findings as client-sensitive data.
