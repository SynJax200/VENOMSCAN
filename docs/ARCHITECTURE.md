# VENOMSCAN — System Architecture

**Brand:** S&S Researcher
**Product:** VENOMSCAN — AI-assisted web application security assessment platform
**Document status:** Draft for review (no implementation yet)

---

## 1. Scope

VENOMSCAN performs **authorized** security assessments of web applications: reconnaissance,
attack-surface discovery, vulnerability testing, API analysis, AI-assisted triage, and
professional reporting.

### Non-goals (hard limits, enforced in code)

| Excluded | Reason |
|---|---|
| Destructive payloads (DROP TABLE, file writes, shell execution) | Non-destructive by design |
| Password brute-force / credential stuffing | Out of scope; lockout only assessed heuristically |
| DoS, load testing, resource exhaustion | Not a stress tool |
| Detections evasion / WAF bypass tuning | Out of scope |
| Scanning of unverified targets | Authorization gate is mandatory |
| Exploit generation or weaponization | Assessment, not exploitation |

---

## 2. Reference repository analysis

| Repo | License | What we take (concepts only unless noted) |
|---|---|---|
| `scf13/ghostscan` | **MIT** | Phase-pipeline orchestrator, plugin auto-discovery, scan profiles (stealth/standard/aggressive), `score = impact*0.6 + confidence*0.4` risk model, context multipliers, correlation engine, hard scope gate + SSRF protection, per-tool timeout/retry, resumable sessions, proxy support |
| `thecmdguy/Ducky` | **MIT** | Feature decomposition for recon primitives (DNS record set, WHOIS, IP intel, TLS inspector, header inspector, CVE lookup via NVD), UI grouping of tools |
| `loucifer-x/PROSECUTOR` | **No license file** → all rights reserved | Ideas only: dynamically loaded `scanners/` package, Playwright SPA parsing, OOB callback verification for SSRF. **No code reuse.** |
| `layyyfn/RedTiger-Tools` | Re-upload; contains stealer/DoS/phishing builders | **Excluded entirely.** Contains malware functionality and is incompatible with this product's purpose. |

Where we adapt MIT code, the source and commit are recorded in `NOTICE.md`.

---

## 3. Design principles

1. **Engine ≠ platform.** The scanning engine is a standalone Python package with no
   dependency on FastAPI, the database, or Redis. It receives a `ScanContext` and emits
   events/results through abstract interfaces. This satisfies the brief's requirement that
   "the scanning engine is independent from the frontend" and keeps it CLI-testable.
2. **Safe by default.** A scan does nothing beyond passive GETs unless the user explicitly
   selects an active profile on a verified target.
3. **Evidence or it didn't happen.** Every finding carries request/response evidence and a
   verification status. AI may describe findings, never create them.
4. **One network chokepoint.** All outbound target traffic flows through `SafeHttpClient`,
   which enforces scope, SSRF rules, rate limits, and timeouts. No module may use `requests`
   or `httpx` directly (enforced by an import-lint test).
5. **Modular by contract, not by convention.** Checks are discovered via Python entry points
   with a typed contract and validated at load time.

---

## 4. Runtime topology

```
                        ┌─────────────────────────┐
   Browser ──HTTPS──►   │  web (Next.js 15, TS)   │   Vercel-style SSR, no scan logic
                        └────────────┬────────────┘
                                     │ REST + SSE
                        ┌────────────▼────────────┐
                        │  api (FastAPI)          │  auth, targets, scans, findings,
                        │  control plane only     │  reports, AI proxy, audit, SSE hub
                        └───┬─────────────┬───────┘
                            │             │
                 ┌──────────▼──┐   ┌──────▼─────────┐
                 │ PostgreSQL  │   │ Redis          │  queue + pub/sub + rate-limit counters
                 └──────▲──────┘   └──────▲─────────┘
                        │                 │
        ┌───────────────┴─────────────────┴───────────────┐
        │  Celery workers (isolated containers)           │
        │  w-recon  │  w-safe  │  w-active  │  w-ai  │ w-report │
        └───────────────┬─────────────────────────────────┘
                        │
                 ┌──────▼──────────────────────────────────┐
                 │  venomscan-engine (pip package)         │
                 │  scope/safety → recon → crawl → checks  │
                 │  → verify → correlate → intel → ai → report │
                 └─────────────────────────────────────────┘
                        │  (all traffic)
                 ┌──────▼───────┐
                 │ SafeHttpClient│ ──► target   (proxy-capable → Burp)
                 └──────────────┘
```

**Why separate queues:** `w-active` can be scaled to zero or run on a segregated network
segment without affecting passive recon. `w-ai` has egress only to the LLM provider.

**Compose services (dev):** `web`, `api`, `w-recon`, `w-safe`, `w-active`, `w-ai`,
`w-report`, `beat`, `postgres`, `redis`, optional `juice-shop` (test target).
The SSRF/XXE callback listener runs inside the process that executes scans (API thread or
worker) and binds loopback by default; set `OOB_BIND_HOST` / `OOB_PUBLIC_BASE_URL` when the
target must reach it over a network. A standalone listener service is a deployment option,
not implemented yet.

---

## 5. Scan lifecycle (state machine)

```
queued → authorizing → recon → crawling → analyzing → verifying
       → correlating → ai_enriching → reporting → completed
                                        ↘ failed / cancelled
```

| Stage | Produces | Runs on |
|---|---|---|
| authorizing | verified scope, allowed hosts/paths | api |
| recon | DNS, WHOIS, IP intel, tech stack, WAF, TLS | w-recon |
| crawling | URLs, parameters, forms, JS endpoints, API specs | w-recon |
| analyzing | raw check observations | w-safe / w-active |
| verifying | `verification_status` + dedup collapse | w-safe |
| correlating | finding groups + context multipliers | w-safe |
| ai_enriching | explanations, priority, FP review, summary | w-ai (optional) |
| reporting | JSON/HTML/MD/PDF artifacts | w-report |

Each transition writes a `scan_event` row (append-only) and publishes to Redis for the SSE
stream, so the dashboard can replay history after reconnect.

**Budgets:** per-scan max requests, max wall-clock, per-host RPS, max concurrency.
Hitting a budget ends the scan gracefully with `partial` status — never hangs.

---

## 6. Safety & authorization model

This section is the product's backbone; every item is testable.

### 6.1 Authorization gate
A target cannot be scanned until verified by one of:

- **DNS TXT** record `_venomscan.<host>` = `venomscan-verify=<token>`
- **HTTP file** `https://<host>/.well-known/venomscan-verify.txt`
- **Manual attestation** — user uploads authorization letter / states scope; recorded with
  timestamp, IP, user id, and exact scope text in the audit log.

Verification expires after 90 days. Every scan row stores the `authorization_id` used.

### 6.2 ScopeGuard / SSRFGuard (single chokepoint)
`SafeHttpClient` on **every** request:

1. Resolve hostname; resolve **again** after connect and pin the IP (anti DNS-rebinding).
2. Reject: loopback, RFC1918, link-local, CGNAT, multicast, `169.254.169.254`,
   IPv6 `::1`/`fc00::/7`/`fe80::/10`, and any IP in `SANDBOX_BLOCKLIST`.
3. Enforce allowlisted hosts/paths from the scope record (wildcards allowed for subdomains).
4. Re-validate the same rules on **every redirect hop** (max 5).
5. Strip/deny `Proxy-Authorization` to arbitrary hosts; egress proxy is operator-configured only.

### 6.3 Rate limiting
Token bucket per `(scan, host)`: default 5 req/s, burst 10, jitter 50–200 ms; honors
`Retry-After`; global cap per scan. Active profile: 2 req/s.

### 6.4 Isolation
- Worker containers: non-root, read-only root FS, no docker socket, capped CPU/memory.
- Plugins: contract-validated; Phase 3 runs them in a subprocess with `resource` limits and
  no DB/Redis credentials. Phase 7 hardens with seccomp (Linux).
- Secrets: encrypted at rest (`Fernet` with key from env / KMS); never logged; redacted in evidence.

### 6.5 Audit log
Append-only `audit_event` table + structured logs: scan start/stop/cancel, scope decisions,
authorization proofs, credential use, report export, AI calls (model, tokens, prompt hash).
Outbound requests are logged as `method`, `url`, `status`, `bytes`, `duration` — never bodies.

### 6.6 Kill switch
Per-scan cancel via Redis flag polled by workers; global `SCANS_ENABLED=false` disables
dispatch; Celery `soft_time_limit` per task.

---

## 7. Engine module contracts

### 7.1 Check plugin

```python
class CheckMeta(BaseModel):
    id: str  # "venom.xss.reflected"
    name: str
    category: Literal["injection", "client", "server", "config", "api", "disclosure"]
    default_severity: Severity
    profile: Literal["passive", "safe", "active"]  # minimum profile required
    requires_auth: bool
    cwe: list[str]
    owasp: list[str]
    payload_risk: Literal["none", "low", "medium", "high"]


class Check(Protocol):
    meta: CheckMeta

    async def run(self, ctx: ScanContext) -> list[Observation]: ...
```

`Observation` is the pre-verification record: URL, method, param, payload, evidence capture,
confidence hint. The verification stage converts `Observation` → `Finding` or discards it.

Discovery: `importlib.metadata.entry_points(group="venomscan.checks")` + built-ins.
Loading validates required attrs and rejects unknown `profile="active"` unless the scan
opted in. Third-party plugins live in a separate distribution, not in-tree.

### 7.2 Event sink

```python
class EventSink(Protocol):
    async def emit(self, event: ScanEvent) -> None: ...
```

`RedisEventSink` in workers; `ListEventSink` in tests; `NullSink` for CLI.

### 7.3 Crawler output (the attack surface)

```python
class Endpoint(BaseModel):
    url, method, params: list[Param], source: Literal["html","form","js","openapi","dir","sitemap","spa"]
    auth_required: bool | None
    content_type, response_hash, depth
class Param(BaseModel):
    name, location: Literal["query","body","header","cookie","path"], sample, type_hint
```

This structure feeds the React Flow graph and the check scheduler.

---

## 8. Risk model

Deterministic, documented, unit-tested:

```
impact   = cvss_score or check.default_impact      (0-10)
conf     = evidence_confidence                     (0-10)
base     = impact * 0.6 + conf * 0.4

multipliers (applied only with correlation evidence):
  auth_context + injection family  × 1.50   (login page + SQLi ⇒ critical)
  unauthenticated API access       × 1.40
  internet-exposed admin surface   × 1.30
  secrets in public JS             × 1.35

risk = min(base * Π multipliers, 10)
severity = critical ≥9.0, high ≥7.0, medium ≥4.0, low ≥0.1
```

AI **never** overwrites these numbers. AI produces `priority_score` (advisory) and
`fp_likelihood` (0–1) shown alongside, with reasoning.

---

## 9. Verification & deduplication

| Step | Rule |
|---|---|
| Reflection confirmation | Payload marker must reappear with the same encoding context; verify twice to exclude caching |
| Boolean SQLi | Paired true/false payloads must produce stable differential (3× repeat) |
| Time-based | Delay must exceed baseline by ≥ 3 s in 2/3 attempts; flagged `low confidence` otherwise |
| XSS (DOM) | Marker must be observable in the browser; console hook confirms execution context |
| OOB checks | Callback must arrive on our listener with matching nonce within 30 s |
| Dedupe key | `sha1(check_id + normalized_url + param + payload_family + tech_sig)` |
| Duplicate window | Same key across scans updates `last_seen` instead of creating a row |

Findings carry `verification_status ∈ {suspected, verified, rejected}`; rejected items are
kept for learning mode but hidden from reports.

`verified` is evidence-bound. The verifier classifies every check family and only promotes
when the stored proof matches its contract:

| Category | Examples | Promotion rule |
|---|---|---|
| exploit | XSS, SQLi, SSRF, XXE, SSTI, LFI, IDOR | Required proof keys must have real values |
| observed | headers, cookies, TLS, CORS, methods, redirect, exposed files, API spec/JWT/GraphQL | At least one observed response field per contract (e.g. `url` + `status_code`, `allow`, `location` + `canary`) |
| heuristic | auth-page hygiene, JS secrets, CSRF tokens, unauth API guesses | Never promoted; stays `suspected` |
| external | Nuclei, Burp, plugins | Never promoted; stays `suspected` |

`effective_verification()` is a pure validator reused by the API read paths, reports and AI
context, so legacy rows that claim `verified` without supporting evidence render as
`suspected` with a `verification_reason`. The persisted rows can be corrected in place with
`python -m venomscan_api.audit_verification` (dry-run first; the tool writes a JSON backup of
every changed row before committing).

---

## 10. AI intelligence engine

### 10.1 Provider abstraction

```python
class LLMProvider(Protocol):
    async def complete(
        self, *, system: str, user: str, schema: type[BaseModel], max_tokens: int
    ) -> BaseModel: ...
```

Adapters: OpenAI-compatible (default), Anthropic, Ollama (local, no key).
Selected via `LLM_PROVIDER` env; the workspace override (provider, model, base URL,
encrypted key) is stored in `ai_settings` and edited from the settings page.

### 10.2 Grounding guarantees
- Input is a **structured** `FindingContext` (evidence IDs, status codes, header diffs,
  tech stack). Never raw HTML dumps.
- Output must match a Pydantic schema; every claim carries `evidence_refs: list[str]`.
- `GroundingValidator` rejects outputs with invented URLs, CVEs not in the scan intel, or
  refs to nonexistent evidence; the attempt is not retried (a slow or wrong model never
  delays a scan) and the response degrades to the deterministic template.
- Target content is treated as untrusted: wrapped in `<untrusted_target_data>` delimiters,
  with an explicit instruction to ignore embedded directives. Model has **no tools**.
- Every call stores `prompt_version`, `model`, `token_usage`, `grounded: bool`.
- With no API key configured, all AI surfaces degrade to rule-based templates (product
  remains fully functional).

### 10.3 AI features

| Feature | Output | Grounding |
|---|---|---|
| Vulnerability explanation | plain-language "what/why" | finding + evidence |
| Risk prioritization | advisory rank + reason | finding set + context multipliers |
| False-positive analysis | `fp_likelihood` + reasoning | paired request/response |
| Vulnerability correlation | narrative over rule-built groups | correlation graph |
| Attack-surface analysis | cluster summaries | endpoint graph |
| Remediation | concrete, framework-aware steps | tech stack |
| Executive summary | 1 page, non-technical | aggregate stats |
| Analyst assistant | chat over scan data (no tools) | retrieval over findings/endpoints |
| Learning mode | explains each step + glossary terms | scan events |

---

## 11. Data model (core tables)

```
users(id, email, password_hash, role, totp_secret, created_at)
orgs(id, name) | org_members(org_id, user_id, role)         -- phase 1 is single-org
targets(id, org_id, base_url, label, created_by, created_at)
authorizations(id, target_id, method, token_hash, proof_path, scope_json, verified_at, expires_at)
scans(id, target_id, authorization_id, profile, status, config_json, budget_json,
      started_at, finished_at, created_by, parent_scan_id)
scan_events(id, scan_id, seq, phase, type, payload_json, created_at)
endpoints(id, scan_id, url, method, params_json, source, response_hash)
technologies(id, scan_id, name, version, category, confidence)
findings(id, scan_id, check_id, title, severity, cvss_vector, cvss_score,
         confidence, verification_status, url, method, parameter, payload,
         request_evidence_json, response_evidence_json, description, impact,
         remediation, refs_json, cwe_json, owasp_json, dedup_key,
         first_seen, last_seen, group_id)
finding_groups(id, scan_id, kind, summary, multiplier)
ai_analyses(id, finding_id, kind, model, prompt_version, grounded, payload_json, created_at)
reports(id, scan_id, format, path, sha256, generated_at)
audit_events(id, actor_id, action, target_ref, meta_json, ip, created_at)
settings(id, org_id, key, value_encrypted)
```

Indexes on `findings(scan_id, severity, dedup_key)`, `scan_events(scan_id, seq)`,
`endpoints(scan_id, url_hash)`. Scan comparison uses `findings.dedup_key` across scans.

---

## 12. HTTP API (control plane)

```
POST   /auth/register | /auth/login | /auth/refresh | /auth/logout
GET    /auth/me
POST   /targets                      create target
GET    /targets | /targets/{id}
POST   /targets/{id}/verify          start DNS/HTTP verification
POST   /targets/{id}/attest          manual authorization attestation
POST   /scans                        {target_id, profile, modules[], auth_profile_id}
GET    /scans | /scans/{id}
POST   /scans/{id}/cancel
GET    /scans/{id}/events            SSE stream
GET    /scans/{id}/findings | /findings/{id}
PATCH  /findings/{id}                triage: status, notes
GET    /scans/{id}/surface          graph nodes/edges
GET    /scans/{id}/compare/{other}
POST   /scans/{id}/ai/{kind}         explanation | summary | prioritize | fp-review
POST   /assistant                    scoped chat
POST   /reports                      {scan_id, formats[]}
GET    /reports | /reports/{id}/download
GET    /integrations/nuclei/status   binary + version probe
POST   /scans/{id}/integrations/nuclei
POST   /integrations/burp/import     XML/JSON import
CRUD   /settings/credentials         encrypted test accounts for IDOR/authz
GET    /audit                        filterable
```

Conventions: JWT access (15 min) + refresh (7 d) in httpOnly cookies; CSRF double-submit
for state-changing routes; pydantic response models; RFC7807 problem+json errors;
cursor pagination; `Idempotency-Key` on scan creation.

---

## 13. Frontend map (Next.js App Router)

```
/(auth)/login  /register
/(app)/dashboard            KPIs, severity donut, recent scans, tech distribution, AI insights
/(app)/targets              table + verification status
/(app)/targets/[id]         overview, auth status, scan history
/(app)/scans/new            wizard: target → authorization → profile → modules → review
/(app)/scans/[id]           live dashboard (SSE), phase timeline, tabs:
                              Findings · Endpoints · Technologies · Headers/TLS · Surface · AI Analyst
/(app)/findings/[id]        evidence viewer, CVSS, AI analysis, triage
/(app)/reports              list, preview, download
/(app)/learning             student mode: guided walkthrough, glossary, "why this matters"
/(app)/settings             LLM provider, credentials, integrations, scan defaults, audit
```

**Design tokens:** background `#FFFFFF`, surface `#F8FAFC`, navy `#0B1F3A`,
primary `#1D4ED8`, primary-hover `#1E40AF`, ring `#93C5FD`; severity
critical `#B91C1C`, high `#EA580C`, medium `#CA8A04`, low `#2563EB`, info `#64748B`.
Typography: Geist Sans / Inter, mono Geist Mono. Radius 10 px, 1 px `#E2E8F0` borders,
soft shadows, generous whitespace. Charts: Recharts (donut, bar, area, sparkline);
graph: React Flow with dagre auto-layout. Dark mode is a later toggle, light is primary.

---

## 14. Reporting

Canonical `report.json` (schema-versioned) → renderers:
HTML (Jinja2, self-contained, inline CSS) → PDF (WeasyPrint) · Markdown · JSON.
Contents: cover, confidentiality + authorization statement, scope, methodology, executive
summary, risk overview, findings table, detailed findings (evidence, CVSS, remediation,
references, verification status), attack-surface appendix, tool/version appendix, disclaimer.
Artifacts are hashed (SHA-256) and stored; downloads use signed, expiring URLs.

---

## 15. Observability & testing

- Structured JSON logs with `scan_id` correlation; Prometheus `/metrics` on api and workers.
- Sentry-compatible error reporting (optional DSN).
- Tests: `pytest` unit per check against fixture servers (`respx` + a local Starlette app);
  contract tests for the scanner package; integration against OWASP Juice Shop in compose;
  Playwright e2e for the critical UI flows; AI tests with a mocked provider + golden fixtures;
  import-lint test asserting no module bypasses `SafeHttpClient`.

---

## 16. Open decisions (need sign-off)

1. **LLM provider** — OpenAI-compatible API, Anthropic, or local Ollama? Default is
   OpenAI-compatible with graceful no-key fallback.
2. **Multi-tenancy** — single-org local install (default, faster) vs. multi-tenant SaaS schema.
3. **Scan profile default** — `safe` (recommended) vs. `passive`.
4. **Nuclei/Burp** — ship integrations on by default or feature-flagged?
