# VENOMSCAN

AI-assisted web security assessment platform for authorized testing — built for S&S Researcher.

VENOMSCAN combines reconnaissance, attack-surface discovery, passive and controlled active
checks, evidence-based verification, AI explanation and reporting. The scanning engine is a
standalone Python package with no dependency on the API or the web app.

> Only scan systems you own or are explicitly authorized to test. VENOMSCAN enforces scope and
> authorization in code, but the legal responsibility for a scan remains with the operator.

## Stack

| Layer      | Technology                                                |
| ---------- | --------------------------------------------------------- |
| Web        | Next.js 15 (App Router), TypeScript, Tailwind + shadcn/ui (Radix), Recharts, React Flow |
| API        | Python 3.12, FastAPI, SQLAlchemy 2, Pydantic v2             |
| Engine     | `venomscan-engine` (standalone package, httpx, cryptography) |
| Workers    | Celery + Redis                                              |
| Datastore  | PostgreSQL                                                  |
| Infra      | Docker Compose (Postgres 55432, Redis 56379)                |

## Status

| Phase | Scope | State |
| ----- | ----- | ----- |
| 0 | Monorepo, auth, targets, scan lifecycle, dashboard | Done |
| 1 | Authorization gate, SSE, passive checks, findings UI | Done |
| 2 | Crawler + full recon + attack-surface graph | Done — Juice Shop container integration verified |
| 3 | Safe vulnerability modules, verifier, dedupe, settings, learning mode | Done — curated learning tracks, per-user progress, evidence walkthroughs and graded practice |
| 4 | Active checks, API security, Playwright | Done — active checks incl. DOM XSS, SSRF/XXE out-of-band and IDOR/function authz, API security, kill switch and budget UI |
| 5 | AI intelligence engine | Done — recon-grounded prompts, three provider adapters with retries, grounding + output contracts, deterministic fallback, eight features, retrieval-scoped assistant, analysis reuse and provider self-test |
| 6–7 | Reports, integrations, hardening, deployment | Done — four report formats with signed links + SHA-256, scan comparison, Nuclei/Burp import-export, offline tech→CVE intel, learning mode; STRIDE threat model, plugin subprocess isolation, perf tuning, prod compose + Caddy TLS, backup/restore, operator/user/plugin/SAFETY docs |

`uv run python -m pytest` currently runs 546 backend tests (engine, API and import-boundary
suites, plus a gated browser E2E); `npm run build` is green. Every client-PDF requirement is
tracked row-by-row with code and test evidence in [docs/ACCEPTANCE_MATRIX.md](docs/ACCEPTANCE_MATRIX.md)
(147 met, 3 theme rows waived by the client, 0 open).
The web UI uses the Jet Black / Cerulean Blue / Neon Rose theme with layered aurora
gradients, a drifting grid, a scanline sweep, animated gradient headlines and page
transitions; every animation is disabled under `prefers-reduced-motion`. The dashboard shows
a per-target overview (scans, findings, latest status, last activity) and a vulnerability
split that toggles between OWASP 2021 categories and individual check ids.

## Checks and safe defaults

The engine registry discovers and validates 34 check modules (`venom.auth.pages`,
`venom.cache`, `venom.clickjacking`, `venom.cookies.flags`, `venom.cors.misconfig`,
`venom.csrf.token`, `venom.files.exposed`, `venom.headers.missing`,
`venom.info.dirlist`, `venom.info.errors`, `venom.info.server`, `venom.methods`,
`venom.redirect.open`, `venom.secrets.js`, `venom.session`, `venom.tls.weak`,
`venom.api.auth`, `venom.api.docs`, `venom.api.sensitive`, `venom.api.spec`,
`venom.api.unauth`, `venom.api.jwt`, `venom.api.graphql`, plus the active-only
`venom.xss.reflected`, `venom.xss.dom`, `venom.sqli.error`, `venom.sqli.time`,
`venom.ssrf`, `venom.xxe`, `venom.ssti`, `venom.lfi.path`, `venom.api.ratelimit`,
`venom.idor` and `venom.authz.function`).
Each module declares its id, profile, severity and an `async run(ctx)` contract; a bad
contract or duplicate id fails at import time. Probe-based checks stay read-only and use
canary origins/hosts, never the target's own mutation endpoints.

API security reads the OpenAPI/Swagger document discovered during the crawl (routes,
servers, declared security schemes) without extra requests, samples capped JSON responses
for credential shapes (JWT, cloud keys, private keys — masked, never stored raw) and
exposes an API-surface card on the scan page. `venom.api.ratelimit` is active-only: it
sends at most 6 sequential GETs to one parameter-free API route and reports a suspected
finding only when no 429 or Retry-After appears.

API posture is computed once during the crawl (`engine/venomscan_engine/intel/api.py`)
from every spec document, whether it was probed or merely linked from a crawled page:
global security inheritance with per-operation overrides, state-changing operations
declared public, `apiKey` transported in the query string, OAuth implicit grants,
cross-origin `servers` and deprecated operations. `venom.api.spec` reports the declared
risk (MEDIUM for unauthenticated writes, LOW for the rest), while `venom.api.unauth`
live-confirms one such protected GET per scan (at most 4 probes, template paths skipped)
and only reports JSON answers that arrive without credentials. JWTs found in sampled API
responses, cookies and query strings are decoded offline (`intel/jwt.py`): `alg=none`,
sensitive claims, external key URLs, tokens in URLs, missing or >30-day expiry and
expired tokens become `venom.api.jwt` findings keyed by a sha256 fingerprint — raw tokens
are never stored or reported. `venom.api.graphql` confirms candidates taken from JS
strings and endpoint paths with a GET `{__typename}` probe, then reads introspection and
GraphQL IDE markers; the POST form is only used on the active profile with consent. The
scan page shows an "API security intelligence" cell (public writes/reads, key in query,
JWT flags, GraphQL confirmation) and both report formats carry the same summary.

`venom.sqli.time` compares the fastest of two clean requests with up to three bounded
sleep payloads (`SLEEP`, `pg_sleep`, `WAITFOR DELAY`); it reports only when the same payload
adds at least 3 s in 2 of 3 attempts, so one slow response cannot produce a finding. Both
SQL checks share the request budget and the operator kill switch.

When `SCAN_SPA_ENABLED=true` the crawler also renders the target once in headless Chromium:
it captures links that only exist after JavaScript runs, `fetch`/XHR calls and their methods,
navigates at most three additional same-origin routes sequentially, aborts out-of-scope and
non-GET browser requests, and stores a `recon.spa` summary (`routes`, `xhr`, `navigated`,
`stopped`). Missing Chromium degrades to a warning.

After verification and de-duplication the deterministic correlation engine
(`engine/venomscan_engine/correlate/`) re-scores findings that form a documented attack path:
credentialed injection (×1.25), injection/authorization gaps on admin URLs (×1.2),
unauthenticated API exposure (×1.15) and leaked JS secrets next to exposed files (×1.15).
A rule fires only when both the gate and the trigger were observed; each finding is boosted
once with the strongest matching multiplier, clipped at 10 with severity re-derived, and the
narrative lands in `recon.correlation`.

Active probes are double-gated: the API rejects an `active` scan without
`active_consent=true` (HTTP 400) and the orchestrator re-checks consent before running any
check. Probes are bounded on every axis — at most 4 XSS points within 12 requests (control,
payload, second variant), 4 SQL error points (control, quote, repeat), 3 template points
with two expressions each, 2 traversal attempts with a clean control and 2 XML body probes —
skip sensitive
parameters (`token`, `password`, `csrf`, ...) and destructive paths
(`logout`, `pay`, `delete`, ...), and still travel through the scope allowlist, SSRF guard,
rate limiter and request budget. Evidence never stores file contents or secret values.
`venom.xss.dom` is the only check that opens a browser: headless Chromium (Playwright) loads
at most two crawled pages with a canary custom element in one GET parameter, aborts every
request outside the scope, over a non-HTTP scheme, with a non-GET/HEAD method, or for a
media/font asset, and reports only when the element materialises in the live DOM. Pages where
the server itself reflects the marker are left to `venom.xss.reflected`. If Playwright or its
Chromium build is missing, the check emits a warning and the rest of the scan continues.
`venom.ssrf` replaces only URL-shaped GET parameters (name or value looks like a URL) on at
most two endpoints with a callback URL carrying a deterministic token. The runner's
out-of-band listener records the hit and the check only reports when that token receives a
callback during the scan; bodies are drained, never stored. The listener binds loopback with
an ephemeral port by default — set `OOB_BIND_HOST` / `OOB_PUBLIC_BASE_URL` when the target
must reach it over a network — and `OOB_ENABLED=false` disables the check with a warning.
`venom.xxe` POSTs a minimal XML document that declares an external entity aimed at the same
listener on at most two crawled endpoints that accept XML (an XML/`soap`/`saml` parameter
name, an XML/spec/upload path, or an XML content type). It reports only when the listener
records the entity fetch during the scan, and the finding keeps the callback method/path
and source IP but never the parsed document or response body. Raw POST bodies still flow
through `SafeHttpClient`, so scope, SSRF, rate and budget rules apply unchanged.

`venom.idor` and `venom.authz.function` run only in active scans that have at least two
encrypted test accounts configured. IDOR requests a numeric/UUID object as the owner and as
the second account, and reports only when both responses are 2xx and both contain the
owner's identity marker; function authz asks the lowest-privilege account for up to two
admin-shaped paths and reports a suspected finding when the response is 2xx and is not a
login page. Personal data is never stored — evidence keeps status codes, the marker that
matched and a `body_stored: false` flag. Account headers are Fernet-encrypted at rest,
masked in every API response, and decrypted only inside the runner.

## Verification hardening

Active findings are confirmed, not guessed. Each injection check sends a benign control
request first and skips the parameter when the control itself is anomalous. A WAF/block
response (`403`/`406`/`429`, or block markers such as "request blocked", "captcha",
"mod_security" or "cloudflare ray id") never confirms a finding.
`venom.xss.reflected` reflects a control token before testing and requires both payload
variants (`vs<token>` and `"><vs<token>x>`) to appear raw; one variant only yields a
suspected finding. `venom.sqli.error` requires the clean value to stay error-free and the
same DB error family to reproduce on a second quote probe. `venom.ssti` evaluates two
distinct arithmetic expressions and rejects responses that merely echo the literal payload.
`venom.lfi.path` only reports when the traversal response matches a system-file signature
that the clean control response does not.

`verify/verifier.py` enforces a per-check response-evidence contract (reflection counts,
error family, evaluated values, matched file and control cleanliness, out-of-band callbacks,
identity markers). Deterministic passive checks are verified on their prefix; an exploit
finding that claims verified without its required evidence is downgraded to suspected with
confidence capped at 5, and `recon.verification` records verified/suspected/rejected/
downgraded counts. The verification event, the scan page "Verification" cell and the
Markdown/HTML report headers all surface this summary.

## AI intelligence

`engine/venomscan_engine/ai/` is provider-agnostic and fully usable without a model.
`build_provider()` returns an adapter for any OpenAI-compatible endpoint, Anthropic or a
local Ollama server, or `None` when no key is configured. Prompts (`prompt_version`
`2026-11-16.2`) wrap all scan facts in `<untrusted_target_data>` with explicit
ignore-embedded-instructions guidance, and request one JSON object matching a Pydantic
schema. Provider calls retry transport errors, 408/429 and 5xx responses once (honouring
`Retry-After` for at most two seconds) before degrading to the deterministic builders in
`fallback.py`.

Scan intelligence is promoted into the prompt itself. `context.recon_digest()` compacts and
redacts DNS/email-authentication, IP/ASN, TLS, WAF, crawl, JS, endpoint clusters, API
contract, JWT/GraphQL, OSINT exposure, directory probes, archive history, verification and
correlation-chain data into capped sections; finding analyses receive only the sections
relevant to their check family (`venom.api*` → API intel, `venom.headers*` → WAF/TLS), while
scan summaries and `correlate` see the whole digest. Every digest section becomes a
`recon:<section>` evidence ref, and its URLs extend the grounding allowlist. The fallback
builders reuse the same digest, so even provider-less answers carry verification counts,
exposure notes and attack-path lines.

The assistant (`retrieval.py`) scores findings, endpoints and recon sections against the
question before the provider call, keeps at least the four highest-risk findings, and
restricts citations to refs the scan actually recorded. `GroundingValidator` rejects
invented URLs, CVEs and unknown refs; `features.check_contract()` additionally rejects
inconsistent model output: a verified finding cannot be called a likely false positive
(nor a rejected one unlikely), prioritization ids/titles must match the scan exactly with no
duplicates, and remediation must return actionable steps. Any provider error, invalid JSON,
grounding failure or contract violation degrades to the deterministic builders instead of
failing the request.

Eight features (`explanation`, `fp_review`, `summary`, `prioritize`, `surface_summary`,
`remediation`, `correlate`, `education`) plus a scoped assistant are exposed under
`/api/findings/{id}/ai/{kind}`, `/api/scans/{id}/ai/{kind}`, `/api/checks/{id}/ai/education`
and `/api/assistant`. The assistant refuses external targets, destructive intent and
prompt-injection attempts before any provider call. Every analysis is persisted with
provider, model, prompt version, `grounded` and `fallback` flags plus a `meta.cache_key`;
successful provider analyses are reused inside `AI_CACHE_TTL_SECONDS` (default 900) instead
of re-billing the model, while fallback rows are never treated as cache hits. `POST
/api/settings/ai/test` sends one tiny structured probe to the configured provider and reports
`configured`/`reachable`/latency without touching the target; the settings page exposes it as
a **Test provider** button, and the assistant renders its evidence refs as citation chips.

`GET /api/checks` serves the catalogue with learning notes. `GET/PUT /api/settings` stores
the workspace default profile and disabled modules (validated against the registry), which
the scan runner applies to every scan. Findings are deduplicated inside a scan and merged
across scans by dedup key; the list shows a `×N` occurrence badge and finding details embed
the plain-language learning note for the originating check.

## Reports, integrations and learning

Every completed scan can be exported as JSON, HTML, Markdown or PDF from the scan page or
the Reports page. All four formats render the same canonical `ReportModel`; the JSON download
returns the exact canonical bytes that were hashed, so `sha256sum` reproduces the stored
digest (PDF embeds a different byte stream but the same model digest is shown in the UI).
Reports are persisted with size, SHA-256 and expiry, and can be shared through an HMAC-signed
link (`?token=<id>.<expires>.<sig>`, `hmac.compare_digest` + expiry → 403 when tampered or
expired). HTML previews are served under a restrictive CSP.

The scan page also compares two completed scans of a target (new / fixed / persisting by
`dedup_key`), shows offline tech→CVE matches from a bundled NVD-style snapshot (no network
call at render time), and offers a Burp XML export for issue-tracker handoff.

Integrations are optional and off unless configured: Nuclei runs only for `active` scans with
consent, when `NUCLEI_ENABLED=true` and `NUCLEI_BINARY`/`NUCLEI_TEMPLATES` point at existing
absolute paths (the prod compose mounts a host binary from `NUCLEI_BIN_DIR` at `/opt/nuclei`;
severity whitelist, rate 1–20, timeout 5–180 s, ≤500 findings, scrubbed environment), and Burp
XML/JSON imports (≤5 MB) are scope-checked URL by URL — a single out-of-scope URL rejects the
whole import with HTTP 422 and no traffic is ever sent. `UPSTREAM_PROXY_URL` routes scanner
traffic through a validated HTTP(S) proxy without disclosing credentials to logs. Settings shows
the live integration status.

## Learning mode

`/api/learning/paths` serves six curated tracks over all 34 checks (surface, transport,
browser, access, discovery, injection), each lesson carrying an objective plus the registry's
what/why/verify notes; the curriculum fails loudly if a track references an unknown check, and
any check not yet placed in a track lands in an automatic `extended` track so coverage never
regresses. `PUT /api/learning/progress/{check_id}` stores `in_progress`/`completed` per user
(`learning_progress`, unique on user + check) and `not_started` deletes the row; every change
writes a `learning.progress` audit event. The web page shows overall and per-track progress
bars that survive reload.

`GET /api/learning/practice` lists verified findings on targets the caller owns;
`POST /api/learning/findings/{id}/walkthrough` turns one into a five-step walkthrough (scope,
reproduce, read the signal, judge, remediate) whose evidence comes from the stored request and
response evidence with `Authorization`, `Cookie`, `Set-Cookie`, token/session keys and
sensitive URL query parameters redacted. `POST /api/learning/findings/{id}/exercises` returns
deterministic, evidence-grounded practice questions: which evidence key was captured, which
manual verification belongs to the check, the correct walkthrough order, and a risk ordering
of sibling findings in the same scan. Answers ship with explanations and are graded in the
browser; the API logs `learning.walkthrough`/`learning.exercises` audit events and never
exposes findings outside the caller's targets (404 otherwise). The check catalogue and plugin
list remain on the same page.

## Reconnaissance & attack surface

Every scan crawls through the same `SafeHttpClient` chokepoint with profile caps
(`passive` 5 pages / depth 1, `safe` 22 / 2, `active` 35 / 3). It honours robots.txt
(longest-match), ingests sitemaps, records forms and their parameters, harvests endpoints
from JS files and inline scripts, probes a curated read-only GET wordlist, and expands any
OpenAPI/Swagger spec it finds.

The directory prober (`crawl.dirs`, `SCAN_DIRS_ENABLED`) walks roughly 140 high-value paths
ordered by value density (security.txt, `.env`, `/admin`, `/api`, docs, actuator, backups,
infra tooling…) with hard caps — 24 probes on `safe`, 40 on `active`, none on `passive`.
A random-path baseline filters soft-404s by body fingerprint and redirect target, robots.txt
disallow rules are honoured, and probe time is charged against the scan budget. Each
discovery lands in the endpoint table with `source=dirs`, and query/form/cookie/header hints
are summarised in a `surface` artifact for the checks and the scan page.

Reconnaissance adds DNS records (A/AAAA/CNAME/NS/MX/TXT plus SOA, SRV for SIP/XMPP and
autodiscover, PTR for the first addresses), parsed SPF and DMARC policies (`p`, `sp`, `pct`,
alignment, `rua`/`ruf`) with a registrable-domain fallback for subdomain hosts, and DKIM
probes for common provider selectors (revoked keys are flagged). It fingerprints WAF/CDN
from headers and cookies, classifies IPs with reverse-DNS hosting hints plus Team Cymru
ASN/prefix/country lookups, sweeps a bounded 16-address slice of the target's own /24 with
PTR queries on active scans, merges passive subdomains from crt.sh and Cert Spotter, resolves
domain registration via IANA's RDAP bootstrap with a port-43 WHOIS fallback (registry →
registrar server), and lists archived URLs from the Wayback CDX index and urlscan.io without
fetching them. Optional Shodan/Censys host lookups run only when an API key is configured,
and their results are labelled as third-party OSINT rather than scan evidence. The scan
detail page shows a Reconnaissance card, a filterable React Flow attack-surface graph and the
full endpoint table. Each endpoint is tagged `live` only when the scanner received a real
response; JS-harvested routes, form actions and API-spec operations stay `unverified` until a
check fetches them. The endpoint table, graph (dashed nodes) and reports show the split so
downstream active checks only act on observed evidence, and regex fragments from bundled route
tables are filtered out of JS harvesting.

JS intelligence is computed offline from the scripts the crawler already fetched — no extra
requests. Each bundle contributes source-map provenance (`sourceMappingURL`, inline `data:`
maps ignored, same-origin vs third-party), HTTP verbs from `fetch`/`axios`/`XMLHttpRequest`
(so a harvested `/api/save` is recorded as `POST`), template parameter names from
`${id}`/`:id`/`{id}` placeholders, sensitive paths (`/admin`, `/internal`, `/graphql`, …),
and third-party hosts. `recon.js_intel` collects the summary with per-URL methods capped at
200 entries. `recon.endpoint_intel` groups the discovered surface into templates
(`/api/orders/{id}`) by masking numeric, UUID, hex and long-token segments, and reports
cluster count, parameterised templates, API-like clusters and up to 40 templates with their
methods and sources. The scan page surfaces both as a "JS bundle intelligence" cell and an
"Endpoint clusters" table, and the Markdown/HTML reports render the same sections.

Sign-in is throttled per account and per IP: five failures lock the account for 15 minutes
while the shared-IP window stays higher (20) so one locked account cannot lock out a whole
NAT; both limits are configurable and blocked attempts are audit-logged, with the activity
page showing failed and throttled sign-ins. With `LOGIN_STATE_BACKEND=redis` (the prod
compose default) the counters are shared by every API worker; if Redis is down the guard
falls back to per-process state instead of failing sign-in.

OSINT lookups talk to crt.sh, Cert Spotter, the Wayback CDX index, urlscan.io, optional
Shodan/Censys (key-gated) and the registry RDAP endpoint — never to the target — and can be
disabled with `SCAN_OSINT_ENABLED=false`; archive listing toggles separately with
`SCAN_HISTORY_ENABLED`. They only run for registrable public domains and are skipped for
IP-literal targets. Archived and third-party URLs are listed for investigation and are never
fetched by the scanner.

## Repository layout

```
engine/     venomscan-engine — safety chokepoint, recon, crawl, checks, verify, pipeline, CLI, AI
apps/api/   FastAPI control plane — auth, targets, authorization gate, scans, SSE, reports, integrations
apps/web/   Next.js dashboard
workers/    Celery app and scan tasks
tests/      unit/engine, unit/api, architecture (import-boundary) tests
docs/       ARCHITECTURE, MODULES, REPO-STRUCTURE, ROADMAP, SAFETY, THREAT_MODEL, guides
infra/      compose (dev + prod), Dockerfiles, Caddyfile
scripts/    seed, load test, backup/restore
```

## Quickstart (local)

```bash
cp .env.example .env          # set SECRET_KEY, and ALLOW_PRIVATE_TARGETS=true for local labs
make setup                    # uv sync --all-packages && npm install
uv run playwright install chromium   # browser for the DOM XSS check (active profile)
make db-up                    # postgres + redis
make seed                     # demo user + verified local target
make api                      # http://127.0.0.1:8000
make web                      # http://localhost:3000
```

`make seed` requires `DEMO_PASSWORD` (12+ characters) and creates
`demo@venomscan.local` with that password. `.env.example` enables the fixture with
`DEMO_ENABLED=true`; production always disables it. The seeded target is the API's own
`/demo` fixture, which deliberately returns an insecure
`session_id` cookie, missing hardening headers, a reflected/SSTI/SQL-error search route, a
client-side DOM sink (`/demo/dom`), a URL fetcher (`/demo/proxy`) and JSON endpoints carrying
a fake JWT, so safe and active self-checks produce real findings.

**Windows hosts with Application Control policies** — some native launchers are blocked. The
Makefile already runs Uvicorn and Celery as modules (`python -m uvicorn`, `python -m celery`),
and `.env.example` uses the pure-Python `pg8000` Postgres driver. Switch back to
`postgresql+psycopg` in Docker/Linux deployments for best performance.

## Production and load testing

```bash
cp infra/compose/.env.prod.example infra/compose/.env.prod   # SECRET_KEY, POSTGRES_PASSWORD, DOMAIN
docker compose -f infra/compose/docker-compose.prod.yml up -d --build
scripts/backup.sh   # pg_dump + redis SAVE + sha256 checksums
scripts/restore.sh  # verifies checksums, pg_restore --clean
```

Caddy terminates TLS, adds HSTS/security headers and flushes SSE responses; the API and web
containers run as non-root. `make load-test` hammers the dashboard read paths and launches five
concurrent scans, failing when dashboard p95 exceeds 300 ms. Deployment and restore details
live in [docs/OPERATOR_GUIDE.md](docs/OPERATOR_GUIDE.md).

The stack was built and exercised on 2026-11-15: Caddy served the API over TLS, a seeded
Celery scan completed with 9 findings, all four report formats generated (JSON hash matched
the stored digest), SSE streamed live events, an isolated plugin ran, and a backup → mutate →
restore cycle preserved every report with its hash intact.

## Scan lifecycle

```
queued → authorizing → recon → crawling → analyzing → verifying → correlating → reporting → completed
                                                                                        ↘ failed / cancelled
```

Progress is streamed over SSE (`GET /api/scans/{id}/events/stream?after=N`) with a polling
fallback in the UI. Findings are deduplicated on `sha1(check_id | normalized_url | parameter |
payload)` and scored with `risk = impact × (0.6 + 0.4 × confidence/10)`.

## Profiles

| Profile   | Behaviour                                                              |
| --------- | ---------------------------------------------------------------------- |
| `passive` | Header, cookie, TLS, transport and version checks. Read-only.          |
| `safe`    | Passive plus non-destructive discovery and validation.                 |
| `active`  | Controlled active probes. Requires `active_consent=true` on scan create.|

Default profile is `safe`. Active mode is refused with HTTP 400 without explicit consent.

## Safety model

- **Authorization gate** — a target must be verified via DNS TXT (`_venomscan.<host>`),
  `/.well-known/venomscan-verify.txt`, or manual attestation before any scan is created (HTTP 409
  otherwise). Authorizations expire after 90 days and are audited.
- **Scope enforcement** — every outbound request goes through `SafeHttpClient`, which validates
  scheme, host and port against the scope and re-validates every redirect hop (max 5).
- **SSRF protection** — loopback, RFC1918, link-local, CGNAT, multicast, reserved and cloud
  metadata addresses (`169.254.169.254`, `fd00:ec2::254`) are blocked unless
  `ALLOW_PRIVATE_TARGETS=true` and the operator has deliberately enabled a lab.
- **Budgets** — per-scan request cap, wall-clock deadline and token-bucket rate limit; the
  scan page shows requests used against the request cap once a scan completes.
- **Kill switch** — cancelling a scan persists the new status, and the engine polls it every
  500 ms before every outbound request, so traffic stops within about a second.
- **OSINT boundary** — subdomain, archive and registration lookups go to fixed metadata
  services (crt.sh, Cert Spotter, Wayback CDX, urlscan.io, IANA RDAP and Shodan/Censys when
  keys are set), use their own hardened client with timeouts and response-size caps, and
  never contact the target. Disable with `SCAN_OSINT_ENABLED=false` (and archive listing
  with `SCAN_HISTORY_ENABLED=false`).
- **OOB boundary** — the SSRF/XXE listener collects only requests whose path carries a token
  issued by the scan that is waiting on it, drains request bodies without storing them, and
  binds loopback by default. It is not a general-purpose request bin; hits are capped and
  discarded with the process.
- **Non-destructive by default** — no writes, no brute force, no payloads that alter state.
- **Tenancy** — every target, scan, finding and audit row is scoped to the owning user.
- **Audit log** — auth, authorization and scan events are appended and readable at `/audit`.

## Engine CLI

```bash
uv run venomscan https://example.com --profile safe --max-requests 60 --rps 3
```

Prints a JSON `ScanResult` on stdout and phase progress on stderr. This is the fastest way to
exercise the engine without the API.

## Testing

```bash
uv run pytest        # engine + API + architecture boundary tests
uv run ruff check .  # lint
cd apps/web && npm run build
```

`tests/architecture/test_import_boundary.py` fails the build if the engine ever imports
`venomscan_api` or `venomscan_workers`, keeping the scanner independently deployable.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — components, trust boundaries, risk model
- [docs/MODULES.md](docs/MODULES.md) — module inventory and check catalogue
- [docs/REPO-STRUCTURE.md](docs/REPO-STRUCTURE.md) — file-by-file responsibilities
- [docs/ROADMAP.md](docs/ROADMAP.md) — delivery phases
- [docs/SAFETY.md](docs/SAFETY.md) — operator safety rules and enforced guardrails
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — STRIDE threat model for the platform
- [docs/OPERATOR_GUIDE.md](docs/OPERATOR_GUIDE.md) — production deploy, TLS, backup/restore
- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) — step-by-step VPS/DNS/ACME runbook and post-deploy checklist
- [docs/USER_GUIDE.md](docs/USER_GUIDE.md) — targets, scans, reports, learning mode
- [docs/PLUGIN_AUTHORING.md](docs/PLUGIN_AUTHORING.md) — writing isolated analysis plugins
- [docs/ACCEPTANCE_MATRIX.md](docs/ACCEPTANCE_MATRIX.md) — client requirement matrix with per-row evidence
- [NOTICE.md](NOTICE.md) — third-party attribution and licence review notes

## Licence

Released under the [MIT licence](LICENSE). Third-party components keep their own licences; the
review notes live in [NOTICE.md](NOTICE.md).

Running the software against a target does not grant permission to test that target — every scan
still requires the operator to attest authorization (see [docs/SAFETY.md](docs/SAFETY.md)).
