# VENOMSCAN — Module & Check Inventory

Every module below is independently loadable and testable. `Profile` is the minimum scan
profile required. `FP` is the expected false-positive risk before verification.
Verification rules are defined in ARCHITECTURE §9.

Profiles: `passive` (no probing, 1–2 GETs) · `safe` (default, non-destructive probing) ·
`active` (payload-based, explicit opt-in).

---

## A. Reconnaissance (`w-recon`, passive/safe)

| ID | Module | Output | Profile | Notes |
|---|---|---|---|---|
| `recon.dns` | DNS enumeration | A, AAAA, MX, NS, TXT, CNAME, SOA, PTR (first 3 addresses), SRV (`_sip._tcp`, `_sip._udp`, `_xmpp-server._tcp`, `_autodiscover._tcp`), SPF and DMARC (apex fallback for `www.`) | passive | dnspython in a worker thread; one deadline for all record types |
| `recon.subdomains` | Subdomain discovery | host list + source | passive | Certificate transparency (crt.sh), passive DNS sources; DNS brute only with `--brute` and a small curated list |
| `recon.whois` | WHOIS | registrar, dates, org, nameservers | passive | RDAP first, then port-43 WHOIS fallback (IANA referral → registry → registrar server); never raises |
| `recon.ip` | IP intelligence | ASN, AS name, netblock/prefix, country, geo, rDNS, hosting flag | passive | Team Cymru DNS origin/ASN lookups for public IPs (≤ 4, IPv4 + IPv6); no API keys |
| `recon.tech` | Technology fingerprint | name, version, category, confidence | passive | headers, cookies, body markers, favicon hash, JS globals |
| `recon.server` | Web server identification | server, framework, language hints | passive | banner + error-page signatures |
| `recon.waf` | WAF/CDN identification | vendor, confidence | passive | response-header + challenge-page signatures |
| `recon.tls` | TLS/SSL analysis | protocol, cipher, cert chain, SANs, expiry, HSTS | passive | `sslyze`-style checks reimplemented with `ssl` + `cryptography` |

---

## B. Crawling & attack surface (`w-recon`)

| ID | Module | Output | Profile | Limits |
|---|---|---|---|---|
| `crawl.spider` | BFS crawler | URLs, status, content-type, depth | safe | depth ≤ 3, ≤ 500 pages, robots.txt respected by default |
| `crawl.forms` | Form detection | action, method, fields, types, CSRF token presence | safe | — |
| `crawl.params` | Parameter extraction | name, location, sample value, type hint | safe | merges query/body/header/cookie |
| `crawl.js` | JavaScript analysis | endpoints, fetch/axios calls, source maps, secret-like strings | safe | regex + AST-lite; bundles ≤ 2 MB each |
| `crawl.api` | API endpoint discovery | OpenAPI/Swagger/GraphQL endpoints | safe | probes `/openapi.json`, `/swagger.json`, `/api-docs`, `/graphql` |
| `crawl.dirs` | Directory/file discovery | paths with status + content type | safe | curated ~140-entry read-only GET wordlist ordered by value density; soft-404 baseline (`/_venomscan-<token>`) filtered by body fingerprint and redirect target; robots.txt disallow honoured; probe caps passive 0 / safe 24 / active 40 (`SCAN_DIRS_ENABLED`); request and time budgets enforced |
| `crawl.sitemap` | Sitemap/robots analysis | declared paths, disallowed paths (useful intel) | passive | — |
| `crawl.spa` | SPA route capture | client-side routes, XHR calls | safe | Playwright; enabled by `SCAN_SPA_ENABLED`; 60 s cap, one page, ≤3 extra route navigations, out-of-scope/non-GET browser requests aborted, degrades with a warning when Chromium is absent |

After crawling, `surface` aggregates query parameters, form fields, cookie names and header candidates (`origin`, `referer`, `user-agent`, `x-forwarded-*`, …) from every discovery source for the check modules and the scan UI.

---

## C. Vulnerability checks — passive/safe

| ID | Check | Profile | FP | Verification |
|---|---|---|---|---|
| `venom.headers.missing` | Missing/insecure security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP) | passive | low | header absence confirmed on 2 URLs |
| `venom.cookies.flags` | Cookie missing Secure/HttpOnly/SameSite | passive | low | Set-Cookie parse |
| `venom.tls.weak` | Deprecated TLS (1.0/1.1), weak ciphers, expiring/expired cert, hostname mismatch | passive | low | direct handshake |
| `venom.info.server_banner` | Version/banner disclosure | passive | low | — |
| `venom.info.errors` | Verbose error / stack traces | safe | medium | trigger with malformed input, diff vs baseline |
| `venom.info.dirlist` | Directory listing enabled | safe | low | title/body signature |
| `venom.files.exposed` | `.git/`, `.env`, backups, `phpinfo`, source maps | safe | medium | 200 + content signature match, never download secrets |
| `venom.secrets.js` | Hardcoded secrets in JS | safe | medium | provider-pattern + entropy; masked evidence; optional active validation **off** by default |
| `venom.cors.misconfig` | Reflected origin, `null` origin, wildcard + credentials | safe | low | controlled Origin header |
| `venom.csrf.token` | State-changing form without anti-CSRF token | safe | medium | form metadata only, no submission |
| `venom.clickjacking` | Missing frame protections | passive | low | — |
| `venom.methods` | TRACE/OPTIONS/PUT enabled | safe | low | `OPTIONS` + `TRACE` only |
| `venom.redirect.open` | Open redirect | safe (canary) | medium | redirect target must be our OOB host or `/`-relative canary |
| `venom.auth.pages` | Login surface: no HTTPS, autocomplete on password, GET credentials, default paths | safe | medium | heuristics only; no credential submission |
| `venom.session` | Cookie scope/domain overly broad, session cookie on HTTP, predictable format | safe | medium | — |
| `venom.cache` | Sensitive pages cacheable | safe | medium | `Cache-Control` checks on auth-ish URLs |

## D. Vulnerability checks — active (opt-in, verified targets only)

| ID | Check | Profile | FP | Verification |
|---|---|---|---|---|
| `venom.xss.reflected` | Reflected XSS | active | medium | unique marker reflected in executable context, 2× stable |
| `venom.xss.dom` | DOM XSS | active | medium | Playwright sets a canary element through a URL parameter; the element must appear in the live DOM |
| `venom.sqli.error` | Error-based SQLi | active | high | paired quote/boolean differential, 3× stable |
| `venom.sqli.time` | Time-based SQLi | active | high | bounded `SLEEP`/`pg_sleep`/`WAITFOR` payloads; baseline = fastest of two clean requests; ≥3 s over baseline in 2 of 3 attempts, 2 parameters max |
| `venom.sqli.time` | Time-based SQLi | active | high | ≥3 s delay over baseline in 2/3 attempts |
| `venom.ssti` | SSTI | active | medium | arithmetic payload evaluates (`{{7*7}}` → 49) in response |
| `venom.lfi` | Local file inclusion / traversal | active | medium | known-file signature (e.g. `/etc/passwd` root line) |
| `venom.ssrf` | SSRF | active | medium | URL-shaped GET parameter swapped for a tokenised OOB callback; listener must record it during the scan |
| `venom.xxe` | XXE | active | high | XML-accepting POST endpoint gets an entity-declaring document aimed at the scan's OOB listener; the entity fetch must arrive during the scan |
| `venom.idor` | IDOR / broken object authz | active | high | two provided test accounts → cross-role response comparison |
| `venom.authz.function` | Missing function-level authz | active | medium | role pair: privileged action returns 2xx for low-priv role |

**Never automated:** credential brute force, destructive file writes, command injection
execution, SQL data extraction. Command-injection *detection* is limited to time-delay
canaries and is disabled by default.

---

## E. API security (`w-active` for authz/rate limit, else safe)

| ID | Module | Output | Profile |
|---|---|---|---|
| `api.openapi` | OpenAPI/Swagger discovery + parse | endpoints, params, auth schemes, servers | safe |
| `api.map` | API endpoint mapping | method/route table, versioning, deprecated routes | safe |
| `api.auth` | Authentication configuration | scheme, token location, expiry headers, HTTPS enforcement | safe |
| `api.authz` | Authorization testing | role-pair matrix (needs test creds) | active |
| `api.ratelimit` | Rate-limit assessment | bounded burst (≤20 req), observes 429/Retry-After | active |
| `api.sensitive` | Sensitive data exposure | PII/secret patterns in JSON responses (masked) | safe |
| `api.cors` | CORS configuration analysis | permissive policy per endpoint | safe |

---

## F. AI intelligence engine (`w-ai`, optional)

Always available: every feature below runs deterministically with no API key. An LLM
provider is a quality boost, never a dependency.

| Kind | Scope | Input | Output | Endpoint |
|---|---|---|---|---|
| `explanation` | finding | finding + evidence + request/response | plain-language summary + why it matters | `POST /api/findings/{id}/ai/explanation` |
| `fp_review` | finding | finding + paired request/response | `fp_likelihood` 0–1 + reasoning, sets `ai_priority=review` when high | `POST /api/findings/{id}/ai/fp_review` |
| `remediation` | finding | finding + detected technologies | ordered, framework-aware fix steps | `POST /api/findings/{id}/ai/remediation` |
| `summary` | scan | aggregates (counts, severities, top risks) | executive headline + priorities | `POST /api/scans/{id}/ai/summary` |
| `prioritize` | scan | findings + risk scores | advisory order + reasons (deterministic base retained) | `POST /api/scans/{id}/ai/prioritize` |
| `surface_summary` | scan | endpoints + technologies | cluster summaries + next-step hints | `POST /api/scans/{id}/ai/surface_summary` |
| `correlate` | scan | findings grouped by artefact | cross-finding narrative chain | `POST /api/scans/{id}/ai/correlate` |
| `assistant` | scan | operator question + scan findings/endpoints | answer, retrieval citations, no tools | `POST /api/assistant` |

Read-back: `GET /api/findings/{id}/ai` (last 20) and `GET /api/scans/{id}/ai` (last 30).
Foreign or unknown resources return 404; unknown kinds return 422.

Providers: `openai_compat` (default), `anthropic`, `ollama`. Selected from `LLM_*`
environment variables or the in-app AI setting, whose API key is Fernet-encrypted at rest.
No configured key → provider is `None` and every call runs the deterministic path.

Guardrails: JSON-only structured output per kind; untrusted target data is fenced inside
`<untrusted_target_data>`; `GroundingValidator` rejects invented URLs, CVEs and refs;
`evidence_refs` must be a subset of refs actually present in the scan data; one attempt per
call — any provider or validation failure degrades straight to the deterministic fallback
(no retry, so a slow or wrong model never delays a scan); the assistant refuses
out-of-scope targets, destructive intent and prompt-injection without calling the provider;
every call is audited (`ai.analysis`, `ai.assistant`).

Persistence: `ai_analyses` rows store `scan_id`, nullable `finding_id` (null for
scan-level and assistant rows), `kind`, `provider`, `model`, `prompt_version`, `grounded`,
`fallback` and the validated `payload` JSON, so the UI can label each result as
"model grounded" or "deterministic fallback".

Learning mode is not an LLM call: `checks/learning.py` ships fixed per-check explanations
returned with the registry, so teaching text never depends on a provider.

---

## G. Verification, correlation & dedupe

| Module | Responsibility |
|---|---|
| `verify.verifier` | repeat tests, compute confidence, assign `suspected/verified/rejected` |
| `verify.dedupe` | `dedup_key` computation, cross-scan merge, `first_seen/last_seen` |
| `correlate.rules` | four documented attack-path rules with context multipliers: credentialed injection (1.25), admin surface (1.2), unauthenticated API (1.15), leaked-secret chain (1.15) |
| `correlate.engine` | fires a chain only when gate and trigger were both observed, re-scores every trigger once with the strongest multiplier, clips at 10 and re-derives severity; writes `recon.correlation` (`chains`, `boosted_findings`, `max_multiplier`) and emits a `correlating/attack_paths` event |

---

## H. Integrations

| Integration | Behaviour | Guardrails |
|---|---|---|
| **Nuclei** | Operator-installed binary run during `active` scans; JSONL output mapped to `nuclei.*` findings | absolute binary + template dir must exist, severity whitelist (`info/low/medium/high/critical`), rate limit 1–20/s, timeout 5–180 s, max 500 findings, env allowlist, 2 MB output cap, every URL re-validated against scope |
| **Burp Suite** | XML/JSON import as a completed `import` scan; XML export of any scan | body ≤5 MB, all-or-nothing scope check (one out-of-scope URL → `422`, nothing imported), 5 MB cap, standard-library XML parsing, findings deduped and re-scored |
| **Upstream proxy** | Routes engine egress through an operator proxy | http/https only (`validate_proxy_url`), no effect on scope/SSRF checks, redirects re-validated per hop |
| **Analysis plugins** | AST discovery + subprocess execution of `run(payload)` | `python -I` child, scrubbed env, temp cwd, POSIX memory/CPU limits, hard timeout, no network client, scoped payload, parent re-scores and drops out-of-scope URLs, ≤25/plugin and ≤50/scan |

Engine modules: `integrations/nuclei.py`, `integrations/burp.py`,
`plugins/{spec,runner,worker}.py`. API surface: `GET /api/integrations`,
`POST /api/targets/{id}/integrations/burp/import`,
`GET /api/scans/{id}/integrations/burp/export`, `GET /api/checks/plugins`.
UI: Settings → Integrations, target page import card, scan page export button,
Learning → Analysis plugins.

---

## I. Reporting

| Format | Renderer | Notes |
|---|---|---|
| JSON | `reports/renderers.render_json` | canonical model, sorted keys, compact separators |
| Markdown | `reports/renderers.render_markdown` | wiki/ticket friendly |
| HTML | `reports/renderers.render_html` | self-contained print CSS, escaped fields, SHA-256 footer |
| PDF | `reports/renderers.render_pdf` | Playwright Chromium A4, header/footer, returns `503` when Chromium is absent |

One `ReportModel` (`reports/model.py`) feeds all four formats. `canonical_json(model)` is
hashed with SHA-256; the digest is stored, returned as `X-Content-SHA256` and displayed in
the UI. Reports live in the `reports` table (`content` BLOB, `model_json`, `sha256`, `size`,
`expires_at`).

API: `POST /api/scans/{id}/reports` (completed scans only), `GET /api/reports`,
`GET /api/reports/{id}`, `…/preview` (CSP + frame options), `…/download` (session), and
`…/signed/{token}` (HMAC-SHA256 over `report_id.expires`, constant-time compare, expiry
check, 403 otherwise). UI: `/reports` list + generator and a Reports card on the scan page.

Each finding block: name, severity, CVSS vector/score, URL, parameter, description, redacted
evidence, confidence, verification status, impact, remediation, references, CWE/OWASP; scan-level
AI analyses are included when present.

---

## J. Learning mode

- `checks/learning.py` supplies `what` / `why` / `verify` for every registered check; the
  `/api/checks` catalogue exposes it and the `/learning` page renders it with profile and
  text filters.
- The same page lists analysis plugins, their timeouts/memory caps and discovery problems.
- Offline **technology → CVE** intel (`intel/`, curated snapshot) appears on the scan page
  via `GET /api/scans/{id}/intel`; version-range matches are triage input, not proof.
- Findings and the AI blocks add "how to reproduce manually" and remediation guidance.
- Guarded lab guidance only: checks run against targets the operator verifies; the demo
  fixtures are served by the API itself.

---

## K. Security, performance and operations

- **Audit redaction** — `services/audit.redact_detail` masks sensitive keys recursively and
  `safety/redact.redact_text` scrubs header-shaped credentials from free text.
- **Login throttling** — `LoginGuard` keeps a rolling window per account
  (`LOGIN_MAX_ATTEMPTS`, default 5/5 min → `LOGIN_LOCKOUT_SECONDS`, default 900) and a separate,
  higher per-IP threshold (`LOGIN_IP_MAX_ATTEMPTS`, default 20) so one locked account cannot
  block every user behind the same NAT. Blocked attempts return 429 + `Retry-After` and are
  audited as `auth.login.blocked` / `auth.login.failed`.
  `LOGIN_STATE_BACKEND=redis` (default in the prod compose) shares the counters across API
  workers through hashed keys (`venomscan:login:*`, no email PII) and degrades to per-process
  state if Redis is unreachable; `memory` stays correct for a single worker.
- **Indexes** — additive covering indexes created at startup for findings, scans,
  endpoints, technologies, reports and AI analyses; `init_db` also adds new columns.
- **Aggregates** — scan/target/dashboard counts use `GROUP BY` instead of lazy-loading
  every finding or scan (no N+1).
- **Compression & streaming** — gzip for JSON ≥1 KB (SSE excluded); SSE sends a `retry`
  hint, 200-event batches, keep-alives, `no-transform` and `X-Accel-Buffering: no`.
- **Workers** — Celery soft/hard limits (540/600 s), autoscale 2–6, `max-tasks-per-child=50`,
  visibility timeout 3600 s; `make worker-scale` for prefork autoscaling.
- **Deployment** — `infra/docker/Dockerfile.backend` + `Dockerfile.web`,
  `infra/compose/docker-compose.prod.yml`, `infra/caddy/Caddyfile` (TLS, HSTS, SSE-friendly
  proxy), `infra/compose/.env.prod.example`.
- **Backup/restore** — `scripts/backup.sh` (pg_dump + SHA-256 + Redis SAVE) and
  `scripts/restore.sh` (checksum verify + `pg_restore --clean`), runbook in
  [OPERATOR_GUIDE.md](OPERATOR_GUIDE.md).
- **Load test** — `scripts/load_test.py` measures p50/p95/p99 for dashboard/scans/targets
  and can launch concurrent scans; fails above the 300 ms dashboard p95 budget.
- **Threat model** — [THREAT_MODEL.md](THREAT_MODEL.md) STRIDE table, trust boundaries,
  review checklist and known gaps; [SAFETY.md](SAFETY.md) is the enforced contract.
