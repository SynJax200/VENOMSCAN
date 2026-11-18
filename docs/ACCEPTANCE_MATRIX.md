# VENOMSCAN — Client Acceptance Matrix

Source of requirements: `# PROJECT ASSIGNMENT  VENOMSCAN.pdf` (Cyber Mind Space, 10 pages).
Matrix built: 2026-11-18. Repo state: `main`, 546 unit/integration tests passing, ruff clean.

Statuses used below:

- **MET** — implemented in code, covered by an automated test, and (where marked) proven on a live run.
- **WAIVED** — client-approved deviation; not counted as met.
- **OPEN** — no successful proof yet (listed separately, not counted as met).

Evidence paths are repo-relative, with engine modules written from `engine/venomscan_engine/`, API modules from `apps/api/venomscan_api/` and UI modules from `apps/web/`.

Every row is one discrete requirement from the PDF. Row-level evidence points at the
implementation path and the test file that locks the behaviour; live proofs are
listed in the "Live evidence ledger" at the end.

---

## 1. Project objective — capability areas

| ID | Requirement | Implementation | Test / evidence | Status |
|---|---|---|---|---|
| OBJ-1 | Automated reconnaissance | `engine/venomscan_engine/recon/` | `tests/unit/engine/test_dns.py`, `test_osint.py`, `test_ip_intel.py`, `test_waf.py` | MET |
| OBJ-2 | Attack surface discovery | `crawl/`, `pipeline/orchestrator.py`, surface graph API | `test_crawl.py`, `test_endpoint_intel.py`, live 82-endpoint scan | MET |
| OBJ-3 | Web application security testing | `checks/` (34 registered checks) | `test_checks.py`, `test_active_checks.py`, `test_fp_corpus.py` | MET |
| OBJ-4 | API security analysis | `checks/api_security.py`, `intel/`, `crawl/jsintel.py` | `test_api_checks.py`, `test_api_intel.py`, `test_jwt_intel.py` | MET |
| OBJ-5 | Vulnerability detection & verification | `checks/`, `verify/verifier.py`, evidence fields | `test_verifier.py`, `test_finding_integrity.py` | MET |
| OBJ-6 | AI-powered security intelligence | `engine/venomscan_engine/ai/`, `services/ai_service.py` | `tests/unit/ai/`, `tests/unit/api/test_ai_api.py` | MET |
| OBJ-7 | Automated reporting | `engine/venomscan_engine/reports/`, `routers/reports.py` | `test_reports.py`, `test_reports_api.py`, live PDF 19–21 pages | MET |
| OBJ-8 | Educational explanations | `checks/learning.py`, `ai` kind `education`, learning UI | `test_learning.py`, `test_learning_api.py`, live `kind=education` 200 | MET |

## 2. Reference repositories

| ID | Requirement | Implementation | Test / evidence | Status |
|---|---|---|---|---|
| REF-1 | Study reference repos, reuse only with licence review; no blind copying | `NOTICE.md` documents concepts used, licences reviewed; RedTiger-Tools excluded entirely | `NOTICE.md` | MET |

## 3. Module A — Reconnaissance

| ID | Requirement | Implementation | Test / evidence | Status |
|---|---|---|---|---|
| A-1 | DNS enumeration | `recon/dns.py` | `test_dns.py` | MET |
| A-2 | Subdomain discovery | `recon/osint.py` (crt.sh, certspotter, OTX passive DNS, hostsearch) | `test_osint.py`, recon proof on `<authorized-target>` (6 names) | MET |
| A-3 | WHOIS information | `recon/exposure.py` (IANA RDAP) | `test_exposure.py` | MET |
| A-4 | IP intelligence | `recon/ip_intel.py` (Shodan InternetDB, optional Shodan/Censys keys, PTR sweep) | `test_ip_intel.py`, recon proof (ports 80/443, tags) | MET |
| A-5 | Technology fingerprinting | `recon/tech.py` | `test_checks.py`, live Next.js/Vercel detection | MET |
| A-6 | Web server identification | `checks/server.py` + tech fingerprints | `test_checks.py` | MET |
| A-7 | WAF identification | `recon/waf.py` | `test_waf.py` | MET |
| A-8 | SSL/TLS analysis | `recon/tls.py` + `checks/tls_check.py` | `test_checks.py` (single snapshot per scan — by design) | MET |

## 4. Module B — Web Crawling & Attack Surface Discovery

| ID | Requirement | Implementation | Test / evidence | Status |
|---|---|---|---|---|
| B-1 | Automatic website crawling | `crawl/crawler.py` | `test_crawl.py` | MET |
| B-2 | Endpoint discovery | `crawl/crawler.py`, `crawl/hints.py`, endpoint records | `test_crawl.py`, live 82 endpoints | MET |
| B-3 | Parameter extraction | `crawl/html_extract.py`, `endpoints.parameters` | `test_crawl.py` | MET |
| B-4 | Form detection | `crawl/html_extract.py` | `test_crawl.py` | MET |
| B-5 | JavaScript file analysis | `crawl/js.py`, `crawl/jsintel.py`, `checks/secrets.py` | `test_jsintel.py` | MET |
| B-6 | API endpoint discovery | `crawl/jsintel.py`, `intel/`, evidence-tagged live vs unverified | `test_endpoint_intel.py`, `test_api_intel.py` | MET |
| B-7 | Directory and file discovery | `crawl/dirs.py`, `checks/files.py` | `test_dirs.py` | MET |
| B-8 | SPA support | `crawl/spa.py` (opt-in via `SCAN_SPA_ENABLED`; off by default = safe profile) | `test_spa.py` | MET |
| B-9 | Sitemap and robots.txt analysis | `crawl/sitemap.py`, `crawl/robots.py` | `test_crawl.py` | MET |

## 5. Module C — Vulnerability Assessment (15 independent modules)

All active validation is consent-gated and GET-only; safe checks run by default.

| ID | Requirement | Implementation | Test / evidence | Status |
|---|---|---|---|---|
| C-1 | SQL Injection | `checks/sqli.py` (error + time-based), GET-only probes | `test_active_checks.py`, `test_sqli_time.py` | MET |
| C-2 | Cross-Site Scripting | `checks/xss.py` (reflected + DOM) | `test_dom_xss.py`, `test_active_checks.py` | MET |
| C-3 | CSRF | `checks/csrf.py` | `test_checks.py` | MET |
| C-4 | SSRF | `checks/ssrf.py` (+ OOB listener, opt-in) | `test_ssrf.py`, `test_oob.py` | MET |
| C-5 | IDOR | `checks/authz.py` (account replay with stored test credentials) | `test_authz.py`, `test_authflows.py` | MET |
| C-6 | LFI | `checks/lfi.py` | `test_active_checks.py` | MET |
| C-7 | Open Redirect | `checks/redirect.py` | `test_checks.py` | MET |
| C-8 | XXE | `checks/xxe.py` | `test_xxe.py` | MET |
| C-9 | SSTI | `checks/ssti.py` | `test_active_checks.py` | MET |
| C-10 | Security misconfiguration | `checks/headers.py`, `clickjacking.py`, `cache.py`, `methods.py`, `cors.py` | `test_checks.py` | MET |
| C-11 | Authentication weaknesses | `checks/auth.py`, `checks/api_security.py`, `checks/api_security.py` | `test_checks.py`, `test_jwt_intel.py` | MET |
| C-12 | Session management issues | `checks/session.py`, `checks/cookies.py` | `test_checks.py` | MET |
| C-13 | Insecure security headers | `checks/headers.py` (CSP/HSTS/COOP/COEP/Referrer/Permissions, per-header impact) | `test_hardening_impact_is_specific_to_the_missing_header` | MET |
| C-14 | Information disclosure | `checks/disclosure.py`, `checks/server.py` | `test_checks.py` | MET |
| C-15 | Exposed secrets and sensitive files | `checks/secrets.py`, `checks/files.py` | `test_jsintel.py`, `test_dirs.py` | MET |

## 6. Module D — API Security Scanner

| ID | Requirement | Implementation | Test / evidence | Status |
|---|---|---|---|---|
| D-1 | REST API discovery | `crawl/jsintel.py`, `intel/`, endpoint tagging | `test_endpoint_intel.py` | MET |
| D-2 | OpenAPI/Swagger analysis | `checks/api_security.py` | `test_api_checks.py` | MET |
| D-3 | API endpoint mapping | endpoint table + surface graph + reports | `test_api_intel.py`, live surface graph page | MET |
| D-4 | Authentication configuration checks | `checks/api_security.py` | `test_api_checks.py`, `test_jwt_intel.py` | MET |
| D-5 | Authorization testing | `checks/api_security.py`, `checks/authz.py`, BOLA matrix | `test_authz.py` | MET |
| D-6 | Rate-limit assessment | `checks/api_security.py` (bounded GET burst ≤20) | `test_api_checks.py` | MET |
| D-7 | Sensitive data exposure | `checks/api_security.py` | `test_api_checks.py` | MET |
| D-8 | CORS configuration analysis | `checks/cors.py` (reflect+credentials detection) | `test_checks.py` | MET |

## 7. Module E — AI Intelligence Engine

All AI output is grounded: URLs/CVEs/refs are validated against scan evidence, and any
provider failure degrades to a deterministic, evidence-based fallback.

| ID | Requirement | Implementation | Test / evidence | Status |
|---|---|---|---|---|
| E-1 | AI vulnerability explanation | `ai` kind `explanation` (finding-level) | `test_ai_engine.py`, `test_ai_api.py` | MET |
| E-2 | AI risk prioritization | `ai` kind `prioritize` | `test_ai_api.py` | MET |
| E-3 | AI false-positive analysis | `ai` kinds `fp_review`, `fp_triage` | `test_ai_api.py`, `test_fp_corpus.py` | MET |
| E-4 | AI vulnerability correlation | `correlate/engine.py` + `ai` kind `correlate` | `test_correlation.py` | MET |
| E-5 | AI attack surface analysis | `ai` kinds `surface_summary`, `endpoint_prioritize` | `test_ai_api.py` | MET |
| E-6 | AI remediation recommendations | `remediation` kind, `next_steps` | `test_ai_engine.py` | MET |
| E-7 | AI executive summary generation | `summary` kind + report autofill (`ensure_report_analyses`) | `test_ai_api.py`, report AI section live | MET |
| E-8 | AI security assessment assistant | `POST /api/ai/assistant` (`answer()` with retrieval) | `test_ai_engine.py`, `test_ai_api.py` | MET |
| E-9 | AI-generated educational explanations | `education` kind + `POST /api/checks/{id}/ai/education` | `test_ai_api.py`, live 200 `kind=education` | MET |
| E-10 | AI must use actual scan evidence, never invent vulnerabilities | `ai/context.py` digests, `GroundingValidator`, output contracts | `test_ai_context.py`; invented-URL test degrades to fallback | MET |
| E-11 | Modular LLM integration (provider-agnostic) | `ai/provider.py`, `ai/providers/` (openai_compat.py, anthropic.py, ollama.py) | provider-contract tests; live Gemini 200 observed | MET |

## 8. Module F — Reporting Engine

Formats:

| ID | Requirement | Implementation | Test / evidence | Status |
|---|---|---|---|---|
| F-1 | PDF | Playwright renderer `reports/renderers.py` | `test_reports.py`, live 19–21-page PDFs | MET |
| F-2 | HTML | `reports/renderers.py` | `test_reports.py` | MET |
| F-3 | JSON | `reports/renderers.py` | `test_reports.py` | MET |
| F-4 | Markdown | `reports/renderers.py` | `test_reports.py` | MET |

Every vulnerability report contains:

| ID | Requirement | Implementation (`reports/model.py::ReportFinding`) | Status |
|---|---|---|---|
| F-5 | Vulnerability name | `title` | MET |
| F-6 | Severity | `severity` | MET |
| F-7 | CVSS score where applicable | `cvss_score`/`cvss_vector` (`reports/cvss.py`, 43 mapped ids + fallbacks) | MET |
| F-8 | Affected URL | `url` | MET |
| F-9 | Vulnerable parameter | `parameter` | MET |
| F-10 | Technical description | `description` | MET |
| F-11 | Evidence | `request_evidence`, `response_evidence` (+ reproduction steps) | MET |
| F-12 | Confidence level | `confidence` | MET |
| F-13 | Potential impact | `impact` | MET |
| F-14 | Remediation | `remediation` | MET |
| F-15 | References | `references` (+ CWE/OWASP) | MET |
| F-16 | Verification status | `verification_status` | MET |

## 9. Unique features (15)

| ID | Requirement | Implementation | Test / evidence | Status |
|---|---|---|---|---|
| U-1 | Interactive attack surface visualization | `components/surface-graph.tsx` (React Flow) | live scan page | MET |
| U-2 | Real-time scanning dashboard | SSE `GET /api/scans/{id}/events/stream` + live page | `test_runner.py`, live scan page | MET |
| U-3 | Live vulnerability discovery | streamed events + per-check outcome table | `test_runner.py`, live 23-row check coverage | MET |
| U-4 | AI-powered security analyst | `routers/ai.py` assistant + citation chips | `test_ai_api.py` | MET |
| U-5 | Vulnerability correlation engine | `correlate/engine.py` + `correlate` kind | `test_correlation.py` | MET |
| U-6 | Scan history and comparison | `GET /api/scans/{id}/compare`, `scan-extras.tsx` | `test_integrations_api.py::test_scan_compare_reports_new_fixed_persisting` | MET |
| U-7 | Burp Suite integration | `integrations.py` (XML import + export) | `test_integrations.py`, `test_integrations_api.py` | MET |
| U-8 | Nuclei integration | `integrations/nuclei.py`, prod compose mount | `test_integrations.py`, live Nuclei run | MET |
| U-9 | Playwright browser automation | `browser.py` (SPA render + PDF) | `test_browser.py`, browser E2E | MET |
| U-10 | Custom security plugin architecture | `plugins/` (subprocess runner, resource limits) | `test_plugins.py`, `docs/PLUGIN_AUTHORING.md` | MET |
| U-11 | Intelligent duplicate finding removal | `verify/dedupe.py` | `test_models.py` | MET |
| U-12 | Technology-based vulnerability intelligence | `intel/` + check mapping | `test_intel.py` | MET |
| U-13 | Evidence-based vulnerability verification | `verify/verifier.py`, verification statuses | `test_verifier.py` | MET |
| U-14 | Student learning mode | `learning/`, `app/(app)/learning`, progress API | `test_learning.py`, `test_learning_api.py` | MET |
| U-15 | Professional automated report generation | report pipeline + signed links | `test_reports_api.py`, live PDF via signed URL | MET |

## 10. UI design direction

| ID | Requirement | Implementation | Status |
|---|---|---|---|
| UI-1 | Modern and minimal UI | shadcn/ui primitives + custom shell | MET |
| UI-2 | Light theme as the primary theme | Dark theme in production | WAIVED (client: treat theme as done, 2026-11-18) |
| UI-3 | White background | Dark background (`#0a0a0a`) | WAIVED (same client decision) |
| UI-4 | Deep navy blue and electric blue accents | Dark palette with cyan/magenta accents | WAIVED (same client decision) |
| UI-5 | Professional typography | `globals.css` type scale + wordmark | MET |
| UI-6 | Responsive layout | 248 px rail + responsive grids | MET |
| UI-7 | Smooth interactions | transitions, skeletons, toasts | MET |
| UI-8 | Clean charts and visualizations | Recharts + React Flow | MET |

## 11. Dashboard widgets

| ID | Requirement | Implementation | Status |
|---|---|---|---|
| DB-1 | Total scans | dashboard stat card | MET |
| DB-2 | Completed scans | dashboard stat card | MET |
| DB-3 | Discovered vulnerabilities | open findings card | MET |
| DB-4 | Critical findings | severity distribution | MET |
| DB-5 | High findings | severity distribution | MET |
| DB-6 | Medium findings | severity distribution | MET |
| DB-7 | Low findings | severity distribution | MET |
| DB-8 | Recent scan activity | recent activity table | MET |
| DB-9 | Target overview | target overview widget | MET |
| DB-10 | Technology distribution | technology widget | MET |
| DB-11 | Vulnerability distribution | OWASP/check grouping widget | MET |
| DB-12 | AI security insights | "Security insights" panel | MET |

## 12. Scan workflow (11 steps)

| ID | Step | Implementation | Status |
|---|---|---|---|
| WF-1 | User logs into VENOMSCAN | `routers/auth.py`, login page | MET |
| WF-2 | User adds an authorized website | `routers/targets.py` | MET |
| WF-3 | Ownership/permission confirmation + scope | attestation / DNS TXT / well-known + `scope_notes` | MET |
| WF-4 | Selects a scan profile | `Profile` passive/safe/active | MET |
| WF-5 | Scanner starts reconnaissance | `pipeline/orchestrator.py` recon phase | MET |
| WF-6 | Crawler discovers endpoints and parameters | `crawl/` | MET |
| WF-7 | Security modules analyse the attack surface | `checks/` per profile | MET |
| WF-8 | Findings normalized and verified | `models.py` dedupe keys, `verify/` | MET |
| WF-9 | AI analyses the findings | `services/ai_service.py` | MET |
| WF-10 | Dashboard displays results | dashboard + scan detail | MET |
| WF-11 | User generates a professional report | `routers/reports.py` | MET |

## 13. Preferred stack

| ID | Requirement | Implementation | Status |
|---|---|---|---|
| ST-1 | Frontend: Next.js + TypeScript | `apps/web` (Next 15.5.29, strict TS) | MET |
| ST-2 | Backend: Python + FastAPI | `apps/api` | MET |
| ST-3 | UI: Tailwind CSS + shadcn/ui | `components.json`, Radix primitives | MET |
| ST-4 | Database: PostgreSQL | SQLAlchemy 2 + PG 16 (SQLite fallback for dev) | MET |
| ST-5 | Task queue: Redis + Celery | `workers/`, compose worker | MET |
| ST-6 | Browser automation: Playwright | `browser.py`, PDF render, E2E | MET |
| ST-7 | Visualization: React Flow | `@xyflow/react` surface graph | MET |
| ST-8 | AI: modular LLM integration | provider abstraction | MET |
| ST-9 | Deployment: Docker | `infra/docker`, compose, deploy bundle | MET |

## 14. Architecture constraints

| ID | Requirement | Implementation | Status |
|---|---|---|---|
| AR-1 | Scanning engine independent from the frontend | `engine/venomscan_engine` has no web imports; CLI + tests only | MET |
| AR-2 | Modular scanners, add without rewriting the app | registry + `@register` + plugins | MET |

## 15. Security & reliability

| ID | Requirement | Implementation | Test / evidence | Status |
|---|---|---|---|---|
| SEC-1 | Strict scope enforcement | `safety/scope.py` in every request chokepoint | `test_safety.py`, `test_http_client.py` | MET |
| SEC-2 | SSRF protection | `safety/ssrf.py` (DNS pinning, cloud metadata block) | `test_ssrf.py`, live lab scan | MET |
| SEC-3 | No unauthorized scanning | verification gate before any scan dispatch | `test_api.py` | MET |
| SEC-4 | Safe scanning defaults | safe profile, GET-only probes, consent for active | `test_safe_checks.py` | MET |
| SEC-5 | Rate limiting | `safety/ratelimit.py`, scan RPS, login lockout (Redis) | `test_login_guard.py`, live 429+Retry-After | MET |
| SEC-6 | Scan timeouts | `scan_max_seconds`, per-request timeouts, check budget | `test_runner.py` | MET |
| SEC-7 | Isolated workers | Celery worker + separate containers + plugin subprocess | `test_plugins.py`, live Celery scan | MET |

## 16. Reliability practices & final expectations

| ID | Requirement | Implementation | Status |
|---|---|---|---|
| Q-1 | Secure credential management | Fernet-encrypted AI key, hashed passwords, env secrets, redaction | MET |
| Q-2 | Plugin isolation | subprocess + rlimits + scoped findings re-validation | MET |
| Q-3 | Audit logging | `services/audit.py` + verification tests | MET |
| Q-4 | Proper error handling | typed errors, deterministic fallbacks, structured API errors | MET |
| Q-5 | No destructive testing by default | GET-only active probes, no state-changing payloads | MET |
| Q-6 | Every module has actual backend functionality | 34 checks, recon/crawl/api/AI/report modules | MET |
| Q-7 | Structured outputs | Pydantic schemas end-to-end | MET |
| Q-8 | Testing | 546 tests (unit + API + engine) + gated browser E2E | MET |
| Q-9 | Working application, not a UI prototype | live scans, reports, exports verified | MET |

## 17. Pre-build deliverables

| ID | Requirement | Implementation | Status |
|---|---|---|---|
| PB-1 | Architecture, repo structure, module breakdown, roadmap prepared for review | `docs/ARCHITECTURE.md`, `docs/MODULES.md`, `docs/REPO-STRUCTURE.md`, `docs/ROADMAP.md` | MET |

---

## Score

Computed directly from the rows above (`grep -c` on status columns):

- Total tracked requirements: **150**
- MET: **147**
- WAIVED (client decision): **3** (UI-2, UI-3, UI-4)
- OPEN: **0**

Strict coverage = 147 / 150 = **98.0%**.
Excluding the three client-waived theme rows: 147 / 147 = **100%** of active requirements.

This is a fresh matrix built from the client PDF on 2026-11-18. It is **not** the
opaque 140-row sheet from the 2026-11-17 audit whose original list is not in the repo,
so the two percentages are not comparable.

## Open verifications (not counted as requirements)

1. **Real LLM provider structured completion.** Live calls reached Gemini (HTTP 200 with
   real JSON) and the provider path is fixed for reasoning models (`LLM_MAX_TOKENS`,
   default 4096), but the final `fallback=false` run was blocked by free-tier HTTP 429
   quota on the supplied key. Re-run in Codespaces where the key already lives in
   `.env.prod` (Settings → AI → Test provider, or any "AI explain").
2. Operational: permanent hosting/VPS, public ACME certificate, key rotation after the
   demo. None of these appear in the client PDF.

## Live evidence ledger

| Date | Evidence |
|---|---|
| 2026-11-16 | Recon proof on `<authorized-target>` (`recon-proof-2026-11-16.json`): 6 subdomains, Wayback/urlscan history, Shodan InternetDB ports/tags, SPF/DMARC |
| 2026-11-16 | Client site scan report (`<authorized-target>-scan-report.pdf`), signed PDF link |
| 2026-11-18 | Fresh PG 16 init (15 tables), Redis lockout 429 + Retry-After, Celery end-to-end scan |
| 2026-11-18 | Per-check outcomes: 23 rows (22 completed + 1 skipped) + UI table, Playwright verified |
| 2026-11-18 | Reproduction steps in 21-page PDF on a real scan (`d67e83c5`) |
| 2026-11-18 | Browser E2E on production build against a local lab target |
| 2026-11-18 | CVSS v3.1 on 6/6 findings in JSON + Markdown (lab scan) |
| 2026-11-18 | DNS-pinned SafeHttpClient live lab scan: 23/23 checks, 6 findings |
| 2026-11-18 | AI: provider reachable (Gemini 200 JSON, 42.6 s), truncation root cause found and fixed; quota 429 blocked final structured run |
