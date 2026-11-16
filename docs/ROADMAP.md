# VENOMSCAN — Development Roadmap

**Approach:** vertical slices. Each phase ends with a runnable application you can open in
a browser and a green test suite. No phase is a UI-only mock — every screen is backed by
real persisted data.

Estimates are focused development days for one senior dev. They assume no scope creep.

---

## Phase 0 — Foundation (2–3 days)

**Deliverables**
- Monorepo scaffold (web, api, engine, workers), `uv` workspaces, pnpm workspace.
- `docker-compose.dev.yml`: postgres, redis, api, web, one worker.
- Alembic baseline migration; core tables: users, organizations, targets, authorizations.
- Settings via pydantic-settings + `.env.example`; structured logging; audit table.
- CI: ruff + mypy (engine), eslint + tsc (web), pytest, import-boundary test.
- Health endpoints, `/metrics`, basic error envelope (RFC7807).

**Acceptance**
`docker compose up` yields a working API at `localhost:8000/docs`, migrations applied,
`make test` green, import-boundary test proves `engine/` cannot import `api/`.

---

## Phase 1 — Auth, targets, scan shell, vertical slice (4–5 days)

**Deliverables**
- Email/password auth (scrypt), JWT access+refresh in httpOnly cookies, CSRF protection.
- Target CRUD + authorization flow (DNS TXT, `.well-known` file, manual attestation).
- Scan CRUD + state machine + Celery dispatch + Redis pub/sub + SSE endpoint.
- Dashboard shell with real counts; scan wizard; scan detail with phase timeline.
- **Two real passive checks wired end-to-end:** `venom.headers.missing`, `venom.tls.weak`.
- Finding persistence, dedupe key, severity badges, finding detail page.
- Playwright e2e: register → add target → attest → run scan → see findings.

**Acceptance**
A verified target scans end-to-end in under 60 s, findings appear live over SSE and
survive a page reload, unverified targets are refused with a clear error, all e2e tests pass.

**This is the demo milestone: it looks and behaves like the product.**

---

## Phase 2 — Reconnaissance + crawler + attack surface (5–6 days) — DONE

**Delivered**
- Crawler (`engine/venomscan_engine/crawl/`): robots.txt longest-match policy, sitemap
  ingestion, BFS with depth/page caps, form + parameter capture, JS file and inline-JS
  endpoint harvesting, bounded path probing, OpenAPI/Swagger spec expansion.
- DNS recon (`recon/dns.py`) and IP intelligence (`recon/ip_intel.py`): A/AAAA/CNAME/NS/MX/TXT,
  address classification and reverse-DNS hosting hints; deadline-bounded and fail-soft.
- WAF/CDN fingerprinting (`recon/waf.py`) from response headers, cookies and server banners.
- Passive subdomains from certificate transparency (`recon/osint.py`) and registration
  metadata through IANA's RDAP bootstrap, behind `SCAN_OSINT_ENABLED`.
- Endpoint `depth`/`parameters` and the full per-scan `recon` payload persisted and exposed
  through the API.
- Scan UI: Reconnaissance card (DNS, IP, WAF, transport, subdomains, registration, crawl,
  robots & specs), a filterable React Flow attack-surface graph (60-node cap, two-column
  per-source layout) and the endpoint table.
- Tests: crawl, DNS, IP intel, WAF, OSINT and pipeline wiring (80 backend tests total).

**Remaining**
- None. The Juice Shop container integration test ran on 2026-11-15 (see evidence below).

**Acceptance evidence**
- `bkimminich/juice-shop` container behind the compose network, target `http://juice-shop:3000`
  (manual attestation, `ALLOW_PRIVATE_TARGETS=true` for the lab). Safe scan `8697ad7f…`
  completed in ~15 s within budget (22 requests) and produced four real findings: plaintext
  transport 8.0 high, missing CSP 5.28 medium, missing hardening headers 2.4 low and unsafe
  HTTP methods 2.2 low — no invented findings on a hardened-elsewhere real app.
- Crawl/robots/sitemap/JS-harvest fixtures and every recon module keep their unit tests.

**Deliverables**
- All recon modules (DNS, subdomains, WHOIS, IP intel, tech, server, WAF, TLS).
- Crawler with budgets, robots.txt, forms, params, JS endpoint extraction, sitemap,
  API spec discovery, bounded directory probing.
- Endpoint/technology persistence; React Flow surface graph with filters.
- Recon tab: tech stack, headers, TLS detail, WAF, DNS records.
- Unit tests against fixture targets; integration test against Juice Shop.

**Acceptance**
Crawl caps are respected (depth/page/request budgets), the surface graph renders ≥50 nodes
smoothly, every recon module has tests, no request bypasses `SafeHttpClient`.

---

## Phase 3 — Safe vulnerability modules + verification (6–7 days) — DONE

**Delivered**
- Registry (`checks/registry.py`): `pkgutil` module discovery, id/attribute/profile/severity
  contract validation at import time, duplicate-id guard, `checks_for_profile(profile, disabled)`
  and a catalogue with learning notes.
- 16 registered checks covering headers/HSTS/hardening, cookies, TLS, server disclosure,
  verbose errors, directory listing, exposed files, JS secrets, CORS, CSRF tokens,
  clickjacking, HTTP methods, open redirect canaries, auth-page hygiene, cache policy and
  session-cookie scope. Probe checks use canaries and skip HTML fallbacks; secret matches are
  masked in evidence.
- Verifier auto-verifies deterministic checks and keeps heuristic ones suspected;
  risk = impact × (0.6 + 0.4 × confidence/10); within-scan dedupe unchanged, with cross-scan
  merge by dedup key and an `occurrences` count in the findings API and UI.
- `GET /api/checks`, `GET/PUT /api/settings` (workspace profile + disabled modules, validated
  against the registry, CSRF-protected, audited), applied by the runner to every scan.
- Settings page (profile picker, module toggles, dirty tracking) and learning-mode panel on
  finding details. All 16 catalogue entries carry real what/why/verify copy.
- Tests: 25 safe-check fixture tests including a clean-fixture pass across every safe check,
  a catalogue learning-copy guard, and API tests for settings persistence and cross-scan merge
  (107 backend tests total).

**Acceptance evidence**
- Clean fixture produces no findings from any of the 16 checks; each positive test pairs with
  a negative. Live demo scans produced only real, evidence-backed findings.
- Two consecutive safe scans of the demo target collapse into one row per dedup key with
  `occurrences` incrementing; findings never duplicate across scans.
- Live UI verification: settings save/restore persisted, disabled `venom.clickjacking` was
  absent from the next scan, and learning copy renders on the finding detail page.

---

## Phase 4 — Active checks, API security, Playwright (5–6 days) — DONE

**Delivered**
- Consent gate at two layers: `POST /api/scans` rejects `profile=active` without
  `active_consent=true` (HTTP 400) and `run_scan()` raises `PermissionError` if consent is
  missing, so a direct engine call cannot bypass it.
- Shared probe helpers (`checks/probes.py`): deterministic sha1 canaries (stable dedup keys),
  one GET parameter per endpoint, same-scope filtering, and a skip list for sensitive
  parameters (`token`, `password`, `csrf`, ...) and destructive paths
  (`logout`, `pay`, `delete`, ...).
- Seven active modules: `venom.xss.reflected` (raw reflection, verified), `venom.xss.dom`
  (headless Chromium confirms a canary element reaches a client-side HTML sink, verified),
  `venom.sqli.error` (error-signature families, suspected), `venom.ssti` (deterministic
  arithmetic evaluation, verified), `venom.ssrf` (token callback on a process-local
  out-of-band listener, verified), `venom.xxe` (entity-declaring XML document POSTed to
  XML-accepting endpoints, entity fetch confirmed by the same listener, verified) and
  `venom.lfi.path` (traversal match, file contents never stored).
- SSRF out-of-band listener (`engine/venomscan_engine/oob.py`): token-scoped HTTP listener,
  loopback + ephemeral port by default, bodies drained and never stored, capped hits;
  `venom.ssrf` only probes URL-shaped GET parameters (name or value) on at most two
  endpoints, waits 3 s per callback and never counts a hit recorded before its own probe.
  `venom.xxe` reuses the listener, probes at most two XML-accepting POST/PUT endpoints and
  reports only on a callback; `SafeHttpClient.request()` gained a raw `content` body so the
  XML still passes scope, SSRF, rate, budget and cancel checks.
  `OOB_ENABLED=false` (or a port that cannot bind) degrades to a warning, not a failed scan.
- Hard caps per scan: 4 XSS canaries, 2 browser pages for DOM XSS, 2 SSRF callbacks, 2 XML
  body probes, 4 SQL quotes, 3 template expressions, 2 traversal attempts; every request
  still flows through
  scope, SSRF guard, rate limiting and budget. The Playwright route guard aborts any browser
  request that is out of scope, non-HTTP, non-GET/HEAD or a media/font asset, and only the
  main page is kept open.
- API security (safe): the crawler parses OpenAPI/Swagger documents into a summary
  (routes, operations, servers, declared security schemes) and keeps capped JSON response
  samples; `venom.api.docs` flags public specs, `venom.api.auth` flags undocumented auth
  or plaintext server URLs, `venom.api.sensitive` flags credential-shaped JSON values with
  masked-only evidence. Active `venom.api.ratelimit` sends at most 6 sequential GETs to one
  parameter-free API route and reports a suspected finding only without 429/Retry-After.
- Test-account credentials: up to three accounts, each a label, role, identity marker and
  free-form headers. Values are Fernet-encrypted (key derived from `SECRET_KEY`), only
  header *names* are returned by the API, and the runner decrypts them for active scans.
- `venom.idor` (active, high): with two accounts, requests a numeric/UUID object endpoint as
  the owner and as the other account; reports verified only when both responses are 2xx and
  both carry the owner's identity marker. `venom.authz.function` (active, medium): the
  lowest-privilege account requests up to two admin-shaped paths and a 2xx non-login
  response becomes a suspected finding. Both warn instead of failing when the accounts are
  missing and never store response bodies.
- Scan page gains an "API surface" recon card (spec, routes, auth, documented calls).
- Kill switch: `venomscan_engine.control.ScanCancelled` plus a `cancel_check` callable that
  `SafeHttpClient` evaluates before every request and redirect hop; the API runner polls the
  scan row every 500 ms. Cancelling also aborts the check loop, so no new target traffic is
  generated after the operator stops the scan.
- Budget surfacing: completed scans persist `max_requests`, `max_seconds` and `rps` alongside
  the request count, and the scan page renders "requests used / cap".
- Wizard consent checkbox with explicit authorization copy and cap disclosure; settings page
  labels active as opt-in per scan; learning notes for every module.
- Neon animated theme: aurora blobs, drifting grid, scanline, animated gradient headings,
  neon cards/buttons/progress and page transitions, all disabled under
  `prefers-reduced-motion`.
- Demo fixture adds a reflected/SSTI error-prone search route, a client-side `innerHTML` sink
  (`/demo/dom`), a URL fetcher (`/demo/proxy`), an entity-resolving XML endpoint (`/demo/xml`),
  a clean JSON API route and a profile route carrying a fake JWT so safe and active checks
  have live evidence.
- Tests: 3 kill-switch tests (client, pipeline, runner), 5 DOM XSS tests (real-browser
  positive, `textContent` negative, server reflection skip, budget stop, URL encoding), 4 OOB
  listener tests, 7 SSRF tests (callback positive, no-callback negative, missing listener,
  non-URL parameters, URL-shaped values, endpoint cap, budget stop) and 6 XXE tests
  (callback positive, no-callback negative, missing listener, non-XML endpoint skip, endpoint
  cap, budget stop), plus raw-body forwarding/drop-on-redirect in the HTTP client, 8 IDOR/
  authz tests and 3 credential API tests — 192 backend tests total.

**Remaining**
- None. The optional Juice Shop integration test from Phase 2 moves to Phase 6.

**Acceptance evidence**
- Live active scan of the demo fixture with consent produced `venom.xss.reflected` (7.68,
  verified), `venom.ssti` (7.68, verified), `venom.api.sensitive` (7.68, verified, masked),
  `venom.sqli.error` (5.06, suspected), `venom.xss.dom` (5.06, verified, evidence
  `html-element-created`, no body stored), `venom.ssrf` (5.28, verified: the listener
  recorded a GET to `/oob/<token>` from `127.0.0.1` on the per-scan ephemeral port),
  `venom.xxe` (7.68, verified: POST `/demo/xml` with an entity-declaring XML document, the
  listener recorded the entity fetch as `callback_path /oob/<token>` from `127.0.0.1`,
  `body_stored: false`, finding method `POST`),
  `venom.api.docs` (2.40, verified), `venom.api.auth` (2.20, verified) and
  `venom.api.ratelimit` (2.00, suspected); the same request without consent returned HTTP 400
  and an unverified target returned HTTP 409. The scan emitted zero warnings, so the browser
  and the listener both ran and every other check completed.
- A safe-profile scan produced the three safe API checks and neither `venom.api.ratelimit`
  nor any injection check, confirming profile gating.
- Cancelling a running active scan flipped it to `cancelled` in 0.33 s and the event count
  stayed frozen at 10 for the following 2.5 s, proving no further phases or requests ran.
- A completed safe scan exposed `20 / 120` requests and the budget values in its stats.
- `venom.lfi.path` ran with no finding on the clean fixture (negative behaviour confirmed).
- IDOR/authz live scan (`1fa08f8c-cb02-4028-b1d8-52e606031427`, consented active profile,
  accounts alice/bob with `X-Demo-User`): 53 requests, 18 findings, zero warnings.
  `venom.idor` verified 7.68 at `/demo/api/orders/1` (evidence
  `identity_exposed_to_other: true`, `body_stored: false`, request recorded both accounts);
  `venom.authz.function` suspected 4.62 at `/demo/admin` (`login_page_detected: false`,
  `role: user`). Settings shows both accounts with header names only, never values.
- 192 backend tests pass, `ruff check .` is clean, `tsc --noEmit` and `npm run build` are green.

---

## Phase 5 — AI intelligence engine (4–5 days) — DONE

**Delivered**
- `engine/venomscan_engine/ai/` is standalone (no API/worker imports). `LLMProvider` protocol
  (`complete(system, user, schema, max_tokens) -> BaseModel`) with three adapters:
  OpenAI-compatible (`/chat/completions`, JSON mode), Anthropic (`/v1/messages`) and Ollama
  (`/api/chat`, `format=json`, no key). `build_provider()` returns `None` when a cloud key is
  missing instead of raising.
- Prompts are versioned (`PROMPT_VERSION = 2026-11-15.1`), request a single JSON object and
  wrap every scan fact in `<untrusted_target_data>` with instructions to ignore embedded
  directives. The model has no tools and no network access beyond the provider call.
- `GroundingValidator` rejects any URL the scan never observed, any CVE not present in the
  finding references, and any evidence ref/finding id outside the allowed set. There is no
  retry: a bad or slow model degrades immediately, so AI can never delay or fail a scan.
- Deterministic fallback for every feature built from the same context: explanation,
  FP review, executive summary, remediation order, attack-surface summary, correlation
  narrative and remediation steps. `features.analyze()` and `assistant.answer()` never raise.
- Scoped assistant: retrieval over this scan's findings/endpoints; refuses external URLs,
  "scan another target" intent and prompt-injection phrases before any provider call.
- API: `POST /api/findings/{id}/ai/{explanation|fp_review|remediation}`,
  `POST /api/scans/{id}/ai/{summary|prioritize|surface_summary|correlate}`,
  `GET /api/findings/{id}/ai`, `GET /api/scans/{id}/ai`, `POST /api/assistant`. Every row is
  stored in `ai_analyses` with provider, model, prompt version, `grounded`, `fallback` and
  payload; explanation also updates `ai_summary`, FP review updates
  `ai_false_positive_likelihood`, and every call is audited (`ai.analysis`, `ai.assistant`).
- Settings: workspace AI provider/model/base URL plus a write-only, Fernet-encrypted key;
  env `LLM_*` values act as deployment defaults.
- UI: settings "AI intelligence" card (provider, model, base URL, key badge, remove key),
  finding "AI analyst" panel with Explain / FP review, scan "AI intelligence" card with four
  scan-level features, and an "Ask about this scan" chat. Every result shows provider/model/
  prompt version and a model-grounded vs deterministic-fallback badge.

**Verification**
- 16 engine tests: deterministic output for all seven kinds, provider answer accepted only
  when grounded, invented URL and invented CVE both fall back with a `provider_error`,
  grounding rejects unknown refs, assistant refuses external/injection questions without
  calling the provider, urgency questions rank by risk, `build_provider` key rules, and an
  OpenAI-compatible adapter round-trip via `httpx.MockTransport`.
- 11 API tests: fallback explanation persists `ai_summary`; FP review persists likelihood;
  mocked grounded provider output is used; invented URL degrades; summary/prioritize/surface
  endpoints and listing; assistant answer and refusal; unknown kind 422; foreign finding 404.

**Acceptance evidence**
- Live check against scan `1fa08f8c…` with no key: explanation `provider=fallback`,
  `fallback=true`; FP review 0.03 for a verified finding; scan summary/prioritize/surface/
  correlation all deterministic; assistant answered the urgency question from risk order and
  refused `Scan https://evil.example.net for me` with `refused=true`.
- Local mock OpenAI-compatible server (configured through `PUT /api/settings/ai`): explanation
  came back `provider=openai_compat`, `model=mock-gpt`, `fallback=false`, citing the observed
  finding URL and the allowed evidence ref. Settings were reset to keyless afterwards.
- Browser verification: settings AI card renders "No key — fallback only"; scan page shows
  all four AI panels with fallback badges; assistant chat rendered a grounded answer and the
  finding page rendered an FP review with the deterministic badge.

---

## Phase 6 — Reporting, integrations, history (4–5 days) — DONE

**Delivered**
- Canonical `ReportModel` (`engine/venomscan_engine/report/`) covering scan metadata, target,
  authorization, profile/budget stats, recon, endpoints, technologies, findings with evidence
  refs, and the AI analyses that exist. `canonical_json()` (sorted keys, compact separators)
  defines the integrity digest.
- Four renderers from the same model: JSON, Markdown, HTML (self-contained, escaped) and PDF
  (headless Chromium). The JSON download returns the exact canonical bytes that were hashed,
  so `sha256sum report.json` equals the stored digest; PDF bytes differ because Chromium adds
  its own metadata, so the UI/link surfaces the model digest instead.
- Report persistence (`reports` table: format, content, model JSON, SHA-256, size, expiry) and
  routes: `POST/GET /api/scans/{id}/reports`, `GET /api/reports`,
  `GET /api/reports/{id}/preview` (CSP-locked HTML), `/download`, and
  `GET /api/reports/{id}/signed/{token}` for anonymous sharing. Tokens are
  `HMAC-SHA256(secret, "{report_id}.{expires}")` as `id.expires.sig`, checked with
  `hmac.compare_digest`; tampered or expired tokens return 403. Default lifetime
  `REPORT_LINK_HOURS=168`; every generation and signed download is audited.
- Scan comparison: `GET /api/scans/{id}/compare?against=<scan_id>` classifies findings as new,
  fixed or persisting by `dedup_key` for the same target.
- Integrations (`GET /api/integrations`, settings card): Nuclei runs only when
  `NUCLEI_BINARY`/`NUCLEI_TEMPLATES` are existing absolute paths (severity whitelist, rate
  1–20, timeout 5–180 s, ≤500 findings, scrubbed environment, 2 MB output cap); Burp XML/JSON
  import (≤5 MB, all-or-nothing scope check → HTTP 422, no traffic sent) and XML export
  (`GET /api/scans/{id}/integrations/burp/export`); optional `UPSTREAM_PROXY_URL` validated
  and applied inside `SafeHttpClient` without creds in logs.
- Offline tech→CVE intel: bundled snapshot matched against a scan's technologies
  (`GET /api/scans/{id}/intel`), with `version_unknown` markers and CVE references; no network
  call at render time.
- UI: Reports page (`/reports`, generate + list + copy signed link), scan page
  Reports / Compare / Tech intel / Burp export cards, target page Burp import card,
  Settings integrations card, and a Learning page (`/learning`) listing all 29 checks with
  what/why/verify notes plus the plugin catalogue.

**Verification**
- Live: JSON/Markdown/HTML/PDF generated for scan `40b90317…` with distinct SHA-256 digests;
  downloaded JSON hash matched the stored digest (`sha-ok True`); HTML preview served under
  CSP; signed link opened anonymously and a tampered token returned 403.
- Live: comparison of two scans reported `0 new · 0 fixed · 9 persisting`; intel panel showed
  the offline snapshot date; Burp export downloaded; Burp import in the browser reported
  `Imported 1 finding(s), skipped 0, out of scope 0. No traffic was sent.` and created scan
  `a7bd5925…`; an out-of-scope URL was rejected with a clear all-or-nothing message.
- Browser: `/reports`, `/learning` (29 cards + plugin), scan extras and settings integration
  panel render with live data.
- Tests: report model/renderers, persistence, signed tokens (valid/expired/tampered), JSON
  digest equality, comparison, intel snapshot, Nuclei/Burp unit and API tests (mocked binary).

**Remaining**
- PDF print layout has a header test and live generation, but no manual visual review yet.
- Nuclei real-binary run and the Juice Shop integration test still need external tooling.

---

## Phase 7 — Hardening, optimization, deployment (4–5 days) — DONE

**Delivered**
- Threat model (`docs/THREAT_MODEL.md`): STRIDE per component (web, API, engine, workers,
  Postgres, Redis, plugins) with mitigations mapped to code; security review of auth, scope,
  SSRF, secrets and plugin boundaries in `docs/SAFETY.md`.
- Plugin isolation: AST discovery plus a subprocess worker
  (`python -I -m venomscan_engine.plugins.worker`) with a scrubbed environment, temporary cwd,
  JSON-only stdin/stdout contract, timeout kill, POSIX `RLIMIT_AS`/CPU, scoped payload and
  ≤25 findings/plugin, ≤50/scan, all re-scored by the engine. No credentials in plugin env.
- Secret-redaction audit: evidence never stores raw secret values (JS secrets, API samples,
  credentials are masked), responses log size/status only, and the audit log records actions
  without payload secrets.
- Performance: additive `CREATE INDEX IF NOT EXISTS` indexes for findings/scans/endpoints/
  technologies/reports/AI analyses; `GZipMiddleware(minimum_size=1024)` (SSE excluded);
  aggregate GROUP BY counts instead of loading relationship lists; `selectinload` on
  scan/target lists to remove N+1s; SSE gains `retry: 3000`, `no-transform` and
  `X-Accel-Buffering: no`; Celery soft/hard time limits, `max-tasks-per-child`, memory cap and
  `worker-scale` target (`--autoscale=6,2`).
- Load test `scripts/load_test.py` (`make load-test`): authenticated hammer of dashboard,
  scan-list and target-list plus N concurrent scans, reporting p50/p95/p99 and a 300 ms budget
  gate.
- Production deployment: `infra/docker/Dockerfile.backend`, `Dockerfile.web` (standalone
  Next build), `infra/compose/docker-compose.prod.yml`, `infra/caddy/Caddyfile` (TLS, HSTS and
  security headers, SSE flush, `/api/*` split), plus `scripts/backup.sh` and
  `scripts/restore.sh` with checksum verification and a restore runbook
  (`docs/OPERATOR_GUIDE.md`). `SEED_TARGET_URL` lets a Docker trial seed a target reachable
  from the worker (`http://api:8000/demo` by default in compose).
- Docs: `docs/SAFETY.md`, `docs/THREAT_MODEL.md`, `docs/OPERATOR_GUIDE.md`,
  `docs/USER_GUIDE.md`, `docs/PLUGIN_AUTHORING.md`, and MODULES §H–K.

**Verification**
- Load test (2026-11-15, local dev, seeded demo target): `/api/dashboard` p95 155.6 ms,
  `/api/scans?limit=50` p95 136.3 ms, `/api/targets` p95 119.5 ms — all under the 300 ms
  budget, 0 failures; 5/5 concurrent safe scans completed (launched in 123 ms).
- 237 backend tests pass, `ruff check .` clean, `tsc --noEmit` and `npm run build` green.
- Plugin run with `PLUGIN_DIRS=examples/plugins`: catalogue lists the plugin and a scan loads
  it with zero problems and zero findings.
- Production stack built and run on 2026-11-15 (Docker 29.8, Compose v5.5.1):
  `venomscan-api` 4.04 GB (Chromium included), `venomscan-web` 414 MB. Caddy on
  `https://localhost` (internal CA) served `/healthz`, `/login` (200) and the API with HSTS and
  `X-Frame-Options`. Seed created demo data through the worker (`http://api:8000/demo`,
  scan completed, 9 findings). All four report formats generated in the container; JSON
  download hash matched the stored digest, PDF was a valid 108 KB `%PDF-1.4` file (bytes
  differ from the model digest by design). SSE streamed 50 live events through Caddy with
  `retry: 3000`; gzip shrank `/api/targets` from 821 to 500 bytes. The isolated plugin ran
  inside the container (`venom.plugin.version_banner`, 0 findings).
- OWASP Juice Shop integration scan (`8697ad7f…`) completed through the same prod worker:
  4 real findings, 22 requests.
- Backup and restore exercised end to end: `scripts/backup.sh` wrote a 170 KB checksummed
  dump, a mutated target name was restored, all 4 reports survived, and the JSON report hash
  still matched after restart.
- Fixes found by the first real build (now in the Dockerfile/compose): `uv sync` needs
  `--all-packages` at this workspace root, Playwright's driver needs `libatomic1` before
  `--with-deps`, and the worker must consume the default Celery queue.

**Remaining**
- Nuclei was tested with mocks only; run it with a reviewed binary and template set before
  relying on it.
- PDF print layout has a header test and live generation, but no manual visual review yet.

---

## Post-audit gap closure — DONE (2026-11-15)

Closed the four previously listed module gaps:

- **Deterministic correlation** — `correlate/rules.py` + `correlate/engine.py`; four
  gate/trigger rules, single strongest multiplier per finding, severity re-derived, narrative
  stored in `recon.correlation` and streamed as a `correlating/attack_paths` event.
- **`venom.sqli.time`** — active, consent-gated; baseline = fastest of two clean requests,
  bounded MySQL/Postgres/MSSQL sleep payloads, confirmation needs ≥3 s over baseline in 2 of 3
  attempts; learning note added.
- **`crawl.spa`** — Playwright capture of post-render routes and XHR calls behind
  `SCAN_SPA_ENABLED`; scope guard on every browser request, ≤3 extra same-origin navigations,
  60 s cap, `recon.spa` summary, warning-only degradation.
- **Dashboard** — API adds per-target overview plus `by_check`/`by_owasp` splits; the
  dashboard renders a target card and a toggleable vulnerability-split card.

**Verification**
- 250 backend tests pass (new correlation, sqli.time, SPA and dashboard tests); `ruff check .`
  clean; `tsc --noEmit` clean.
- Live engine run against a local fixture: `venom.sqli.time` confirmed at 3110/3062/3062 ms
  over a 46 ms baseline, correlation fired `credentialed-injection` and re-scored it to 9.6,
  SPA report captured routes + XHR, client-only route and `spa-xhr` endpoint appeared in the
  surface.
- Live API dashboard returned the target overview and OWASP/check splits; the browser DOM
  confirmed both new cards and the check-tab toggle.

---

## Recon depth, directory probing & login hardening — DONE (2026-11-15)

- **DNS depth** — SOA added to the record set, SRV probing for SIP/XMPP/autodiscover, PTR for
  the first three addresses, and SPF/DMARC parsed out of TXT (including `_dmarc.<apex>` for
  `www.` hosts and a shared deadline so slow lookups degrade instead of hanging).
- **ASN / netblock / country** — Team Cymru DNS origin + ASN TXT lookups for up to four public
  IPv4/IPv6 addresses; hosting labels come from the AS name, prefixes land in the summary, and
  non-public addresses are skipped.
- **WHOIS fallback** — when RDAP has no registration data, a two-hop port-43 WHOIS walk
  (IANA bootstrap → registry → registrar server) parses the first value per key, caps reads
  at 64 KB, and never raises into the scan.
- **`crawl.dirs`** — 141 curated read-only GET paths ordered by value density; soft-404
  baseline (`/_venomscan-<token>`) filtered by body fingerprint and redirect target;
  robots.txt disallow honoured; caps 0/24/40 probes for passive/safe/active behind
  `SCAN_DIRS_ENABLED`; budget-aware.
- **Surface hints** — query parameters, form fields, cookie names and header candidates
  aggregated from every discovery source into `recon.surface` and shown on the scan page.
- **Login throttling** — per-account window (5 failures / 5 min → 15 min lockout) and a
  separate, higher per-IP threshold (20) so one locked account cannot lock out a shared NAT;
  429 + `Retry-After`, audited as `auth.login.blocked` / `auth.login.failed`, surfaced on the
  Activity page. `LOGIN_STATE_BACKEND=redis` (prod default) shares the counters across API
  workers via hashed keys and falls back to per-process state when Redis is unreachable.
- **PDF QA fixes** — section headings carry `break-after: avoid` (no more heading stranded at
  a page bottom) and Nuclei findings report `GET` rather than the raw `http` protocol type.
- **Nuclei in the prod stack** — the Linux binary lives in `NUCLEI_BIN_DIR` (default
  `./.nuclei-bin`, gitignored), is bind-mounted read-only at `/opt/nuclei` in api + worker,
  and `NUCLEI_ENABLED=true` with `NUCLEI_BINARY=/opt/nuclei/nuclei` is the prod default;
  it still runs only for `active` scans with explicit consent.
- **Deployment runbook + registration switch** — `docs/DEPLOYMENT.md` walks DNS → firewall →
  secret rotation → first start → TLS verification → demo removal → 18-point post-deploy
  checklist, and `ALLOW_REGISTRATION` (default `true`) closes public sign-up after onboarding
  (`403 Registration is closed on this installation`).
- **Self-contained deployment bundle** — `release/venomscan-deploy/` ships source, compose,
  Caddyfile, Dockerfiles, templates, scripts and docs with `install.sh` (Docker/ports/DNS
  checks, secret generation, Nuclei download, build, health wait) and `smoke.sh`
  (containers, health, TLS SAN/issuer, headers, UI, login, integrations, registration state);
  the extracted tarball validates with `docker compose config` and the smoke script passed
  8/8 against the local prod stack.

**Verification**
- 266 backend tests, `ruff check .` and `tsc --noEmit` clean (test settings now pin
  `_env_file=None` so a developer `.env` cannot leak into assertions).
- Redis-shared lockout: two API processes on :8001/:8002 against the same Redis — five
  failures on one returned 429 + `Retry-After: 900` on the other, while a different account
  on the same IP still signed in; Redis held only hashed keys (270 tests now).
- Live example.com scan: SOA, SPF, DMARC `p=reject`, AS13335 with prefixes/countries and RDAP
  WHOIS; live local fixture: 24 probes found `/docs` (source `dirs`) and surface hints
  returned query `q,url`, form `q,xml`, cookie `session_id`.
- Live lockout on :8001: 4×401 then 429 with `Retry-After: 900` for the failed email while
  `demo@venomscan.local` still signed in from the same IP (IP threshold 20).
- Real Nuclei (v3 via `go install`) + bundled `nuclei-templates/venomscan-headers.yaml` in an
  active scan: 1 finding, `nuclei.venomscan-security-headers`, method `GET`, redacted
  Set-Cookie in evidence.
- Nuclei inside the prod compose stack: a cross-compiled Linux binary executed as the
  unprivileged `venom` user (`v3.11.1`), `/api/integrations` reported
  `enabled/configured/binary_present/templates_present: true`, and an `active` scan with
  consent against the verified self-check target completed with 15 findings including
  `nuclei.venomscan-security-headers`.
- LLM path exercised over real HTTP against a local OpenAI-compatible mock: the API request
  carried `Authorization: Bearer`, `response_format: json_object`, system/user roles and the
  `<untrusted_target_data>` fence; a scan summary persisted with `fallback: false` and the
  provider payload. A wrong key returned `provider returned HTTP 401` and an unreachable host
  `provider unreachable: ConnectError`, both degrading to the deterministic payload.
- Deploy-path dry run with a public domain: `docker compose config` under
  `DOMAIN=scan.example.com` rendered the Caddy `DOMAIN`/`ACME_EMAIL` and matching
  `API_BASE`/`WEB_BASE`/`CORS_ORIGINS`/`OOB_PUBLIC_BASE_URL` for api, worker and web; the
  operator guide now lists the DNS/ports/secret checklist for a real host.
- Final acceptance sweep: `pytest` 270 passed (exit 0), `ruff` and `tsc --noEmit` clean; live
  prod smoke through Caddy TLS — login, dashboard (2 targets), scans (7), scan findings (15),
  check catalogue (30), audit trail, PDF report (144 KB) + signed link 200 with tampered token
  403, integrations enabled with the mounted Nuclei binary, and the web app serving
  `/dashboard` 200.
- Registration switch: 271 tests pass; a spare API with `ALLOW_REGISTRATION=false` returned
  `403 Registration is closed on this installation` for a new account while existing users
  still logged in (200).
- 23-page PDF report visibly reviewed page by page: cover + executive summary clean, one
  finding per page with evidence blocks, endpoint appendix and SHA-256 footer intact.
- Prod images (`venomscan-api`, `venomscan-worker`, `venomscan-web`) rebuilt and smoke-checked
  by importing the app/worker and asserting the new code inside each image; the localhost
  compose stack was then recreated on the new images and verified through Caddy TLS:
  `/healthz` 200, login 200, a safe scan completed with 24 directory probes recorded, and the
  SSE stream delivered live events (`text/event-stream`, 42 events stored).

---

## Assignment alignment: shadcn/ui + AI learning notes — DONE (2026-11-16)

Closed the two remaining deltas against the client brief:

- **shadcn/ui stack** — UI primitives now live in `apps/web/components/ui/`
  (`button`, `card`, `badge`, `dialog`, `progress`, `feedback`) with a barrel export,
  `components.json`, `class-variance-authority`, Radix `Slot`/`Dialog`/`Progress`, and
  `tailwindcss-animate`. The legacy `components/ui.tsx` file is gone; all 19 import sites
  resolve through `@/components/ui` unchanged.
- **AI-generated educational explanations** — new `education` AI kind
  (`EducationPayload`), prompt task and grounded fallback built from the curated
  `checks/learning.py` notes. `POST /api/checks/{check_id}/ai/education` persists an
  `AiAnalysis(kind=education)` row and writes an `ai.analysis` audit event. Grounding only
  allows the `check:<id>` ref — URLs/CVEs are rejected. Learning mode adds an **AI explain**
  action per check that renders plain language, why-it-matters, manual verification and a
  practice tip, badged as `AI · <provider>` or `grounded fallback`.

**Verification**
- 273 backend tests pass (two new education tests), `ruff check .` clean, `tsc --noEmit`
  clean, `next build` compiles every route.
- Live check: temp API instance, demo login, `POST /api/checks/venom.cookies.flags/ai/education`
  → 200, `grounded=true`, `fallback=true` (no provider key), refs `["check:venom.cookies.flags"]`.

---

## Timeline summary

| Phase | Days | Cumulative | Milestone |
|---|---|---|---|
| 0 Foundation | 2–3 | 3 | stack runs |
| 1 Vertical slice | 4–5 | 8 | **demo-ready product** |
| 2 Recon + surface | 5–6 | 14 | real reconnaissance |
| 3 Safe checks | 6–7 | 21 | useful assessments |
| 4 Active + API | 5–6 | 27 | deeper testing |
| 5 AI | 4–5 | 32 | intelligence layer |
| 6 Reports + integrations | 4–5 | 37 | deliverable reports |
| 7 Hardening | 4–5 | 42 | production-ready |

~40–45 focused days. Presented as milestones, not calendar promises; Phase 1 is the
review gate where the direction is validated before the long build.

---

## Risk register

| Risk | Impact | Mitigation |
|---|---|---|
| Active checks cause disruption on a real target | High | Safe default profile, explicit opt-in, per-scan request budget, cancel, non-destructive payloads only |
| False positives erode trust | High | Evidence-based verification, verification status, fixture precision tests |
| AI hallucination | High | Structured context, schema + evidence-ref validation, deterministic fallback, AI never sets severity |
| SSRF / DNS rebinding against our own infrastructure | Critical | Single chokepoint, IP pinning, redirect re-validation, egress-blocked workers |
| Unauthorized scanning via the platform | Critical | Mandatory authorization verification, audit trail, attestation record |
| Third-party plugin escapes sandbox | High | Contract validation, subprocess isolation, no creds in plugin env |
| Report generation blocking workers | Medium | Dedicated `w-report` queue, timeouts, streaming for large scans |
| AI cost blowup | Medium | Per-scan token budget, caching by finding hash, local-provider option |
| Scope creep across 15 unique features | High | Phase gates, explicit acceptance criteria, no phase starts before prior gate passes |

---

## Decisions required before Phase 1

1. **LLM provider** — OpenAI-compatible / Anthropic / Ollama (default: OpenAI-compatible, fallback on).
2. **Tenancy** — single-org install (recommended) or multi-tenant from day one.
3. **Default scan profile** — `safe` (recommended) or `passive`.
4. **Integrations** — Burp/Nuclei feature-flagged (recommended) or enabled by default.

Everything else proceeds with the defaults documented in ARCHITECTURE.md.
