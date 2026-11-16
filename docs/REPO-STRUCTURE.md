# VENOMSCAN — Repository Structure

Monorepo, three deployable units: `apps/web` (Next.js), `apps/api` (FastAPI),
`engine/` + `workers/` (Python engine and Celery tasks). Everything else is docs,
infra, fixtures, and tests.

```
venomscan/
├─ README.md
├─ NOTICE.md                        # adapted MIT sources + attribution
├─ LICENSE                          # proprietary — Cyber Mind Space
├─ .editorconfig
├─ .gitignore
├─ .env.example                     # documented, no real secrets
├─ Makefile                         # make dev / test / lint / migrate / seed
├─ pyproject.toml                   # uv workspace root: api, engine, workers, tests
│
├─ docs/
│  ├─ ARCHITECTURE.md               # system design (this review)
│  ├─ REPO-STRUCTURE.md             # this file
│  ├─ MODULES.md                    # module and check inventory
│  ├─ ROADMAP.md                    # phases, acceptance criteria
│  ├─ THREAT_MODEL.md               # STRIDE for the platform itself (phase 7)
│  ├─ SAFETY.md                     # scope rules, profiles, authorization flow
│  ├─ DEPLOYMENT.md                 # VPS/DNS/ACME runbook and post-deploy checklist
│  ├─ OPERATOR_GUIDE.md             # install, TLS, backup/restore, troubleshooting
│  ├─ USER_GUIDE.md                 # targets, scans, reports, learning mode
│  ├─ PLUGIN_AUTHORING.md           # plugin contract and isolation model
│  └─ adr/                          # architecture decision records
│     ├─ 0001-engine-isolation.md
│     ├─ 0002-safe-http-client.md
│     ├─ 0003-plugin-entrypoints.md
│     └─ 0004-ai-grounding.md
│
├─ apps/
│  ├─ web/                          # Next.js 15, App Router, TypeScript
│  │  ├─ package.json
│  │  ├─ next.config.ts
│  │  ├─ tailwind.config.ts         # design tokens from ARCHITECTURE §13
│  │  ├─ components.json            # shadcn/ui config
│  │  ├─ src/
│  │  │  ├─ app/
│  │  │  │  ├─ (auth)/login/page.tsx
│  │  │  │  ├─ (auth)/register/page.tsx
│  │  │  │  ├─ (app)/layout.tsx
│  │  │  │  ├─ (app)/dashboard/page.tsx
│  │  │  │  ├─ (app)/targets/page.tsx
│  │  │  │  ├─ (app)/targets/[id]/page.tsx
│  │  │  │  ├─ (app)/scans/new/page.tsx
│  │  │  │  ├─ (app)/scans/[id]/page.tsx
│  │  │  │  ├─ (app)/scans/[id]/surface/page.tsx
│  │  │  │  ├─ (app)/findings/[id]/page.tsx
│  │  │  │  ├─ (app)/reports/page.tsx
│  │  │  │  ├─ (app)/learning/page.tsx
│  │  │  │  ├─ (app)/settings/page.tsx
│  │  │  │  └─ api/[...]/route.ts   # thin BFF proxy → FastAPI (cookie forwarding)
│  │  │  ├─ components/
│  │  │  │  ├─ ui/                  # shadcn primitives (button, card, table, dialog…)
│  │  │  │  ├─ charts/              # SeverityDonut, TechDistribution, TrendArea
│  │  │  │  ├─ surface/             # React Flow graph, node renderers, legend
│  │  │  │  ├─ scans/               # PhaseTimeline, LiveFeed, ScanWizard, ScanCard
│  │  │  │  ├─ findings/            # FindingTable, EvidenceViewer, SeverityBadge
│  │  │  │  └─ layout/              # Sidebar, Topbar, PageHeader, EmptyState
│  │  │  ├─ lib/                    # api client, sse hook, formatters, cn()
│  │  │  ├─ stores/                 # zustand: scan filters, live feed buffer
│  │  │  └─ types/                  # generated from OpenAPI (openapi-typescript)
│  │  └─ public/
│  │
│  └─ api/                          # FastAPI control plane
│     ├─ pyproject.toml
│     ├─ alembic.ini
│     ├─ alembic/versions/
│     └─ venomscan_api/
│        ├─ main.py                 # app factory, middleware, routers
│        ├─ core/
│        │  ├─ config.py            # pydantic-settings, .env driven
│        │  ├─ security.py          # JWT, password hashing (scrypt), CSRF
│        │  ├─ crypto.py            # Fernet field encryption
│        │  ├─ deps.py              # DB session, current_user, org scoping
│        │  └─ errors.py            # RFC7807 problem responses
│        ├─ db/
│        │  ├─ base.py              # declarative base, naming conventions
│        │  ├─ session.py
│        │  └─ models/              # user, target, authorization, scan, finding,
│        │                           # endpoint, technology, group, ai_analysis,
│        │                           # report, audit_event, setting
│        ├─ schemas/                # pydantic request/response models
│        ├─ routers/                # auth, targets, scans, findings, reports,
│        │                           # surface, assistant, integrations, settings, audit
│        ├─ services/
│        │  ├─ scan_service.py      # enqueue, state transitions, cancel
│        │  ├─ authz_service.py     # DNS/HTTP verification, attestation
│        │  ├─ report_service.py
│        │  ├─ ai_service.py        # proxy to engine AI + persistence
│        │  └─ events.py            # Redis pub/sub → SSE generator
│        └─ tests/
│
├─ engine/                          # standalone scanning package — NO FastAPI/DB imports
│  ├─ pyproject.toml                # name: venomscan-engine, entry point group
│  └─ venomscan_engine/
│     ├─ __init__.py
│     ├─ models.py                  # Finding, Observation, Endpoint, Param, ScanEvent…
│     ├─ context.py                 # ScanContext: target, scope, config, clients, sink
│     ├─ safety/
│     │  ├─ scope.py                # ScopeGuard: allowlist, wildcard, path rules
│     │  ├─ ssrf.py                 # IP classification, DNS pinning, redirect re-check
│     │  ├─ http.py                 # SafeHttpClient (httpx + guards + rate limit)
│     │  ├─ ratelimit.py            # token bucket (Redis / in-memory backend)
│     │  ├─ budget.py               # request + time budgets, cancel flag
│     │  └─ redact.py               # evidence secret redaction
│     ├─ pipeline/
│     │  ├─ orchestrator.py         # phase sequencing, failure isolation
│     │  ├─ phases.py               # recon → crawl → analyze → verify → correlate → ai → report
│     │  └─ events.py               # EventSink protocol + implementations
│     ├─ recon/
│     │  ├─ dns.py                  # A/AAAA/MX/NS/TXT/CNAME/SOA/PTR/SRV
│     │  ├─ subdomains.py           # passive sources + DNS brute (bounded)
│     │  ├─ whois.py
│     │  ├─ ip_intel.py             # ASN, geo, rDNS (offline-capable fallback)
│     │  ├─ tech.py                 # header/body/favicon/JS fingerprint DB
│     │  ├─ waf.py                  # WAF/CDN detection signatures
│     │  ├─ tls.py                  # cert chain, SANs, expiry, protocols, ciphers
│     │  └─ server.py               # banners, HTTP methods, error pages
│     ├─ crawl/
│     │  ├─ crawler.py              # BFS, depth/page caps, robots.txt
│     │  ├─ forms.py                # form + field extraction
│     │  ├─ params.py               # query/body/header param harvesting
│     │  ├─ js_analyzer.py          # endpoint + secret regex over JS bundles
│     │  ├─ api_discovery.py        # swagger/openapi/graphql probes
│     │  ├─ directories.py          # wordlist probe (bounded, 200/signature filtered)
│     │  ├─ sitemap.py              # sitemap.xml, robots.txt
│     │  └─ spa.py                  # Playwright-driven SPA route capture
│     ├─ checks/
│     │  ├─ registry.py             # entry-point discovery + contract validation
│     │  ├─ base.py                 # Check protocol, helpers (reflect, diff, timing)
│     │  ├─ headers.py
│     │  ├─ cookies.py
│     │  ├─ tls_config.py
│     │  ├─ info_disclosure.py
│     │  ├─ directory_listing.py
│     │  ├─ exposed_files.py
│     │  ├─ secrets_js.py
│     │  ├─ cors.py
│     │  ├─ csrf.py
│     │  ├─ open_redirect.py
│     │  ├─ xss_reflected.py
│     │  ├─ xss_dom.py              # Playwright
│     │  ├─ sqli_error.py
│     │  ├─ sqli_time.py            # active
│     │  ├─ ssti.py                 # active
│     │  ├─ lfi.py                  # active
│     │  ├─ ssrf.py                 # active, OOB
│     │  ├─ xxe.py                  # active
│     │  ├─ idor.py                 # active, needs test accounts
│     │  ├─ auth_weaknesses.py
│     │  └─ session_management.py
│     ├─ api_security/
│     │  ├─ openapi.py              # spec parsing + endpoint import
│     │  ├─ authz.py                # role-pair response comparison
│     │  ├─ ratelimit_scan.py       # bounded probe of retry-after behaviour
│     │  └─ sensitive_data.py
│     ├─ verify/
│     │  ├─ verifier.py             # confidence scoring, repeat checks
│     │  └─ dedupe.py               # dedup_key computation, merge rules
│     ├─ correlate/
│     │  ├─ rules.py                # context-multiplier rules
│     │  └─ engine.py               # group builder
│     ├─ intel/
│     │  ├─ nvd.py                  # CVE lookup (cached, offline DB snapshot)
│     │  ├─ mappings.py             # tech+version → candidate CVEs
│     │  └─ cvss.py                 # vector parsing/score helpers
│     ├─ ai/
│     │  ├─ provider.py             # LLMProvider protocol + factory
│     │  ├─ providers/openai_compat.py, anthropic.py, ollama.py
│     │  ├─ prompts/                # versioned prompt templates
│     │  ├─ grounding.py            # schema + evidence-ref validation
│     │  ├─ features.py             # explain, prioritize, fp_review, correlate,
│     │  │                           # surface_summary, remediation, exec_summary
│     │  └─ fallback.py             # deterministic templates when no key
│     ├─ report/
│     │  ├─ schema.py               # canonical report.json model
│     │  ├─ builders/json.py, html.py, markdown.py, pdf.py
│     │  └─ templates/              # Jinja2 HTML report + CSS
│     ├─ integrations/
│     │  ├─ nuclei.py               # subprocess, JSONL parse, scope guard
│     │  └─ burp.py                 # proxy config + XML/JSON import/export
│     ├─ plugins/
│     │  ├─ loader.py               # entry-point loader + isolation hooks
│     │  └─ sandbox.py              # subprocess runner w/ resource limits
│     └─ cli.py                     # `venomscan scan <url> --profile safe`
│
├─ workers/                         # Celery app
│  ├─ pyproject.toml
│  └─ venomscan_workers/
│     ├─ celery_app.py              # queues: recon, safe, active, ai, report
│     ├─ tasks/scan.py              # execute_scan(scan_id)
│     ├─ tasks/phase.py             # per-phase tasks
│     ├─ tasks/ai.py
│     ├─ tasks/report.py
│     └─ signals.py                 # soft timeouts, cancel flag checks
│
├─ infra/
│  ├─ docker/
│  │  ├─ web.Dockerfile
│  │  ├─ api.Dockerfile
│  │  ├─ worker.Dockerfile          # shared, queue set per service
│  │  └─ engine.Dockerfile          # for CLI/plugin sandbox
│  ├─ compose/
│  │  ├─ docker-compose.yml         # full stack
│  │  ├─ docker-compose.dev.yml     # hot reload, exposed ports
│  │  └─ docker-compose.test.yml    # adds juice-shop + ephemeral postgres
│  └─ nginx/
│     └─ dev.conf                   # single-origin reverse proxy for dev
│
├─ fixtures/
│  ├─ wordlists/                    # small curated lists (dirs, subdomains)
│  ├─ fingerprints/                 # tech + WAF signature YAML
│  ├─ payloads/                     # safe canaries, one file per check family
│  ├─ cve-snapshot.json             # offline NVD subset (tech→CVE)
│  └─ sample-targets/               # tiny local vulnerable apps for unit tests
│
└─ tests/
   ├─ conftest.py                   # app factory, DB, auth fixtures, local target
   ├─ unit/engine/                  # per-check tests against fixture servers
   ├─ unit/api/
   ├─ integration/                  # full scan against juice-shop
   ├─ e2e/                          # Playwright UI flows
   ├─ security/                     # scope-guard, SSRF, redirect, DNS-rebind tests
   └─ ai/                           # mocked provider, golden outputs, grounding rejects
```

## Conventions

- **Python:** 3.12, `uv`, ruff, mypy strict on `engine/`; async I/O throughout the engine.
- **TypeScript:** strict mode, ESLint + Prettier, server components by default.
- **Naming:** checks `venom.<area>.<check>`; queues `recon|safe|active|ai|report`.
- **Imports:** `engine/` may not import `apps.api` or `workers`. Enforced in CI.
- **Network:** only `engine/safety/http.py` may construct an HTTP client for target traffic.
- **Secrets:** `.env` only; every new secret gets a `.env.example` entry and a redaction rule.
- **Migrations:** Alembic autogenerate, reviewed by hand; never edit applied migrations.
