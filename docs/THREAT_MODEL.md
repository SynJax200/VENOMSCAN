# VENOMSCAN threat model and security review (Phase 7)

Scope: the VENOMSCAN deployment itself — control plane, workers, web UI, datastores and
the operator-supplied integrations. The target being scanned is out of scope by
definition; attacks against it are governed by [SAFETY.md](SAFETY.md).

## Assets

| Asset | Why it matters |
| --- | --- |
| Test-account credentials | Give access to the client's application |
| LLM API key | Billed externally; may be shared across projects |
| `SECRET_KEY` | Signs JWTs, CSRF tokens, signed report links |
| Findings and evidence | Sensitive description of client weaknesses |
| Reports and their SHA-256 | Delivered to clients; must be tamper-evident |
| Audit log | Who authorized and ran what, and when |
| Worker execution surface | Runs Nuclei, Chromium and plugins |

## Trust boundaries

1. Browser ↔ Caddy (TLS, internet)
2. Caddy ↔ web / API (internal compose network)
3. API ↔ PostgreSQL / Redis (internal network, credentialed)
4. API ↔ target (governed by `SafeHttpClient` scope + SSRF rules)
5. Worker ↔ target (same chokepoint, separate process)
6. Parent ↔ plugin subprocess (untrusted code, scrubbed env, no network client)
7. Operator browser ↔ external tools (Nuclei templates, Burp imports)

## STRIDE review

| Threat | STRIDE | Scenario | Mitigation | Residual risk |
| --- | --- | --- | --- | --- |
| Spoofing | S | Stolen session cookie replayed | HttpOnly, SameSite=Lax cookies, `COOKIE_SECURE=true` in prod, short access-token TTL, refresh rotation | XSS on another origin could still steal cookies if the operator reuses passwords; no MFA yet |
| Spoofing | S | Forged CSRF-driven state change | CSRF token required on every mutating route, double-submit cookie, token rotated after login | Same-site subdomain attacker is out of model (single host deployment) |
| Tampering | T | Report modified before delivery | SHA-256 over canonical JSON exposed on download and preview; signed URL bound to report id + expiry | Recipient must actually verify the hash; operator guide documents the command |
| Tampering | T | Audit log edited to hide a scan | Audit rows are append-only at the application layer; database access is operator-controlled | A DBA with write access can still alter rows; ship database logs to external storage for high-assurance use |
| Repudiation | R | Analyst denies running an intrusive scan | Every scan stores `authorization_id`, profile, consent flag, actor and IP; verification attempts are audited | Attestation truthfulness depends on the person signing it |
| Information disclosure | I | SSRF pulls internal metadata | SSRF guard blocks private/loopback/link-local unless explicitly allowed; redirects re-validated; URL-shaped probes use the OOB token, never internal addresses | `ALLOW_PRIVATE_TARGETS=true` intentionally weakens this for labs |
| Information disclosure | I | Credentials leak into reports or audit | Headers/keys redacted in evidence; audit redactor masks sensitive keys; report model excludes credential rows; plugin payload excludes them | A target that echoes a secret in a response body can still surface it as finding evidence; review before delivering |
| Information disclosure | I | Signed report link forwarded publicly | Links expire (`REPORT_LINK_HOURS`), are HMAC-bound, and rotating `SECRET_KEY` revokes them | Anyone with a live link can read the report — treat it as a bearer token |
| Information disclosure | I | Plugin exfiltrates data or reads secrets | Child process gets a scoped payload, scrubbed env, temp cwd, no HTTP client, memory/CPU limits, hard timeout | Plugins are operator-installed code; review before enabling any third-party plugin |
| Denial of service | D | Scan floods target or worker | Token bucket, request/time budgets, scan timeouts (soft 540 s / hard 600 s), autoscaled worker pool with task recycling, kill switch | Very large crawls still consume worker slots until budget ends |
| Denial of service | D | Dashboard slows down under load | Covering indexes, aggregate counts (no N+1 lazy loads), gzip on JSON, SSE batches of 200 events with keep-alives | Single-node Postgres is a scaling ceiling; load test documents current headroom |
| Elevation of privilege | E | One tenant reads another tenant's data | Every query joins through `Target.owner_id`; foreign ids return `404`; reports/scans/intel/compare/export all re-check ownership | Single-org deployment assumes one trusted analyst team |
| Elevation of privilege | E | Active checks run without consent | API rejects `active` without `active_consent=true`; orchestrator re-checks before running any active module | A compromised API process could bypass its own checks — host hardening matters |
| Elevation of privilege | E | Plugin escapes its sandbox | Subprocess isolation, scrubbed env, no network, resource limits, output revalidation; plugin output is data, never executed | POSIX limits are best-effort on Windows; run production on Linux |

## Security review checklist (Phase 7)

- [x] All target traffic passes `SafeHttpClient`; no direct `httpx`/`requests` calls to
  target hosts elsewhere (the `/demo` fixtures are deliberate lab targets, mounted only
  when `DEMO_ENABLED=true` outside production).
- [x] Redirects re-validated hop by hop; proxy support validated as http/https only.
- [x] Burp import is all-or-nothing on scope; 5 MB cap; XML parsed with the standard
  library, no external entity resolution.
- [x] Nuclei runs with an absolute binary, allowlisted severities, capped output and
  re-validated URLs; environment allowlist only.
- [x] Reports served with CSP, `X-Frame-Options: SAMEORIGIN`, `nosniff`, and no-store on
  preview; HTML escaping covers every target-controlled field.
- [x] Signed links use `hmac.compare_digest` and an expiry check; expired/invalid → 403.
- [x] Audit details redacted recursively (key-based) and header credentials scrubbed from
  free text.
- [x] Secrets encrypted at rest with Fernet; decrypted only for the call that needs them.
- [x] CSRF enforced on every mutating route, including imports and report generation.
- [x] Worker auth to Redis/Postgres uses credentials from the environment; compose keeps
  datastores off the public network.
- [x] Caddy sets HSTS, nosniff, frame options, referrer policy and removes `Server`.
- [x] Dependency and license review is a release checklist item
  ([PLUGIN_AUTHORING.md](PLUGIN_AUTHORING.md) and every third-party tool used).

### Known gaps

1. No MFA; rely on strong passwords and network isolation.
2. Audit is append-only in application code, not tamper-proof at the database level.
3. Windows deployments do not have POSIX plugin resource limits (timeout still applies).
4. Third-party Nuclei templates and Burp data are trusted operator inputs; licenses and
   template quality are the operator's responsibility.
