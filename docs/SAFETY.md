# VENOMSCAN safety model

VENOMSCAN exists to make authorized security testing repeatable for a single
organization. Every guarantee below is enforced in code, not by convention. This page is
the contract operators and testers can rely on; the STRIDE review in
[THREAT_MODEL.md](THREAT_MODEL.md) covers how the guarantees hold against attacks on the
platform itself.

## 1. Authorized targets only

- A target cannot be scanned until one verification method succeeds: a DNS TXT record, a
  token file under `/.well-known/`, or a signed manual attestation by an analyst. The
  authorization has an expiry and a fresh one is required after it lapses.
- The API refuses to queue a scan (`409`) when the latest authorization is missing,
  unverified or expired, and the scan row stores the authorization it ran under.
- Every verification attempt, scan queue/cancel, credential change, import/export and
  report action is written to `audit_events`. Audit details pass through a redactor that
  masks `authorization`, `cookie`, `token`, `secret`, `password`, `api_key` and
  `credential` keys and scrubs header-shaped secrets from free text.
- Scope is always derived from the verified target URL (`Scope.from_target`). Imported
  Burp data is parsed only if **every** URL falls inside that scope; a single
  out-of-scope URL rejects the whole import with `422` and writes nothing.

Operators remain responsible for having permission for the systems they add. VENOMSCAN
cannot verify that a DNS record or attestation is truthful — it records who claimed what
and when.

## 2. Safe by default

- Default profile is `safe`. The `active` profile additionally requires
  `active_consent=true` on the scan request (HTTP 400 otherwise) and the orchestrator
  re-checks that consent before executing any active module.
- Passive/safe modules never mutate state. Active modules are bounded read-only canaries:
  at most 4 XSS canaries, 4 SQL error quotes, 3 template expressions, 2 traversal attempts
  and 2 XML probes per scan, with sensitive parameter names and destructive paths skipped.
- No destructive testing is implemented. There is no upload-and-execute, no data deletion,
  no denial-of-service request shape, and no request-rate stress test beyond the small
  sequential rate-limit probe.
- Nuclei runs only when an operator installs the binary and enables it, and only in the
  `active` profile with the severity/rate/timeout caps validated by
  `NucleiConfig.validate()`.

## 3. One outbound chokepoint

Every request to a target goes through `SafeHttpClient`:

- **Scope allowlist** — scheme/host/port must match the target (plus any explicitly
  allowed extra hosts); redirects are re-validated per hop.
- **SSRF guard** — private, loopback, link-local, multicast and reserved addresses are
  blocked unless `ALLOW_PRIVATE_TARGETS=true` (local labs only). The check runs on DNS
  results, on redirect targets, and on URLs supplied to the out-of-band callback.
- **Rate limiting and budgets** — a token bucket (`SCAN_RPS`) plus per-scan request and
  wall-clock budgets (`SCAN_MAX_REQUESTS`, `SCAN_MAX_SECONDS`) stop runaway scans. The
  UI kill switch and the scan budget both terminate work cooperatively.
- **No ambient proxy** — `trust_env=False`; only an operator-configured
  `UPSTREAM_PROXY_URL` (http/https, validated) is used, and redirects still pass the
  scope and SSRF checks.
- **No secret capture** — evidence bodies are capped and redacted; file contents and
  credential values are never persisted.

## 4. Isolated workers and plugins

- Scans run in Celery workers (production) or a local background executor (development).
  A worker recycles after `WORKER_MAX_TASKS_PER_CHILD` tasks and has soft/hard time limits.
- Plugins are **analysis only**. Discovery is AST-only; the child runs as
  `python -I -m venomscan_engine.plugins.worker` with a scrubbed environment, a temporary
  working directory, POSIX memory/CPU limits where available, a hard timeout, and no
  network capability (it never receives `SafeHttpClient`). The payload contains target
  metadata, endpoints and existing findings — never credentials. The parent rejects
  unknown severities, drops out-of-scope URLs, caps findings (25/plugin, 50/scan) and
  re-scores everything it keeps.
- Test-account credentials and AI keys are encrypted at rest (Fernet) and are only
  decrypted in-process for the specific check or provider call that needs them; plugin
  payloads never include them.

## 5. Reporting integrity

- One canonical `ReportModel` feeds JSON, Markdown, HTML and PDF. Integrity is the
  SHA-256 of canonical JSON (sorted keys, compact separators), returned as
  `X-Content-SHA256` on download and printed in the HTML/PDF footer. The JSON download is
  exactly the hashed bytes, so `sha256sum` verifies it directly; PDF file bytes vary with
  the renderer, so compare the model digest instead.
- Download links require an authenticated session. Signed links are
  HMAC-SHA256 over `report_id.expires` verified with `hmac.compare_digest`, and expire
  after `REPORT_LINK_HOURS`. Rotating `SECRET_KEY` invalidates all outstanding links.
- Preview HTML is server-rendered with `html.escape` and served with a restrictive
  `Content-Security-Policy`; target-controlled strings cannot execute in the report page.

## 6. Limits operators must respect

- Only scan systems you own or are explicitly authorized to test. "Authorized" includes
  the scope boundary (hosts, subdomains, ports) agreed with the owner.
- Do not enable `ALLOW_PRIVATE_TARGETS` on a shared deployment; it weakens the SSRF guard.
- Keep `OOB_ENABLED` reachable only from the targets you test; the listener binds loopback
  by default.
- Treat the curated CVE snapshot as triage input, not proof of exploitability. Validate
  every match manually.
- Review third-party tools (Nuclei templates, Burp exports) under their own licenses before
  use; VENOMSCAN does not vendor them.
