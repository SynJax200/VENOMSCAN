# VENOMSCAN user guide

Audience: students, bug-bounty hunters, pentesters and researchers running assessments
inside their organization. You must have written permission for every target you add.

## 1. Sign in and orient

After login you land on **Overview** (`/dashboard`): open scans, total findings by
severity, a per-target overview (scans, findings, latest status, last activity), a
vulnerability split you can switch between OWASP 2021 categories and individual checks,
most frequently seen technologies and the latest scans. The left navigation is
Overview · Targets · Scans · Findings · Reports · Learning · Activity · Settings.

## 2. Add and verify a target

1. **Targets → Add target**. Give it a name, the exact base URL and scope notes (hosts,
   paths and out-of-scope areas agreed with the owner).
2. Open the target and complete **verification**: publish the shown `TXT` record, upload
   the token to `/.well-known/…`, or sign the manual attestation. Verification expires;
   scans are blocked (`409`) until it is valid again.
3. A target is the scope boundary. Anything outside its host is refused by the engine and
   by imports, even if a page links there.

## 3. Run a scan

Click **Start scan** on the target page. Choose a profile:

| Profile | What it does | When to use |
| --- | --- | --- |
| `passive` | Configuration reads only (no extra probing) | First look, very sensitive systems |
| `safe` (default) | Passive + bounded non-destructive probes (CORS, exposed files, secrets, redirects) | Normal assessments |
| `active` | Read-only canaries: reflected/DOM XSS, SQL errors and time-based SQL delays, SSTI, LFI, SSRF/XXE, rate limit, IDOR/authz | After consent and a safe baseline |

Active scans need the explicit consent checkbox every time. Everything travels through the
scope allowlist, SSRF guard, rate limit and request/time budgets; the scan page has a
**Cancel** button (kill switch) that stops work cooperatively.

`safe` and `active` scans also probe a curated read-only path list (24 and 40 probes) for
admin panels, API docs, config and backup files; soft-404s are filtered, robots.txt is
honoured and hits appear in the endpoint table with source `dirs`.

While a scan runs, the timeline streams live: phase, progress, tool starts, warnings and
plugin results. Events are batched and the page falls back to polling if streaming is
blocked.

## 4. Read findings

**Findings** shows every finding across your scans with severity, verification status and
risk score, filterable by severity. A finding page explains description, impact,
remediation, CWE/OWASP/CVSS, references and redacted request/response evidence.
`suspected` means the engine observed a signal; `verified` means the verifier reproduced
it with a second request. Treat `suspected` as a lead, not a conclusion.

On a scan page you also get:

- **Detected technologies** and, below, **Known CVEs for detected technologies** — an
  offline curated snapshot matched by version range. `version unknown` means the banner
  had no version; verify manually. This is triage input, never proof.
- **Surface graph** and endpoint inventory from the crawl.
- **Compare scans** — pick another completed scan of the same target to see **new**,
  **fixed** and **persisting** findings (matched by dedup key).
- **AI intelligence** (if configured) — explanation, false-positive review, remediation,
  summary, prioritisation, attack-surface clustering and a scoped assistant that answers
  only from this scan's data. Model output is grounding-checked; failures fall back to
  deterministic text.

## 5. Reports

**Scan page → Reports** or the **Reports** page:

1. Pick a completed scan and a format: JSON (canonical model), Markdown, HTML or PDF.
2. Use **Preview** for the print-ready HTML, **Download** for the file, or **Signed link**
   to copy an HMAC-signed URL that works without a session until it expires
   (`REPORT_LINK_HOURS`, default 7 days).
3. Integrity: the download response carries `X-Content-SHA256`, the UI shows the first 12
   characters, and the HTML footer prints the full hash. The digest covers the canonical
   report model, so `sha256sum` reproduces it for JSON, Markdown and HTML files. A PDF is
   rendered by Chromium and embeds render metadata, so its file bytes differ — compare the
   PDF footer hash / `X-Content-SHA256` instead.

Signed links are bearer tokens — share them only with the intended recipient. Rotating
`SECRET_KEY` on the server revokes all of them.

## 6. Integrations

- **Burp import** (target page) — paste or upload a Burp XML/JSON export. All URLs must be
  inside the target scope; otherwise nothing is imported and you get a `422` listing the
  offenders. A successful import creates a completed `import` scan with no traffic sent.
- **Burp export** (scan page) — download the scan as Burp XML for your existing workflow.
- **Nuclei** (operator-enabled, active scans only) — the operator installs the binary and a
  reviewed template directory (`NUCLEI_BINARY`, `NUCLEI_TEMPLATES`; the repo ships
  `nuclei-templates/` with one read-only header template). Results arrive as `nuclei.*`
  findings alongside the built-in checks; the scan timeline reports how many templates
  matched, and a tool failure degrades to a warning instead of failing the scan.

## 7. Learning mode

**Learning** starts with six guided tracks that cover all 34 checks: attack surface,
transport and sessions, browser defences, access control, API/secrets and injection. Each
lesson has a one-line objective plus **What**, **Why** and **Verify** notes, and you can
mark it **Studying** or **Done**; progress is stored per account and the overall and
per-track bars survive reloads.

**Practice from your scans** lists verified findings on targets you own. Selecting one
opens a five-step walkthrough — confirm scope, reproduce once, read the signal, judge the
evidence, remediate — built from the stored request/response evidence with credentials,
cookies, tokens and sensitive query parameters redacted. **Practice questions** adds
deterministic exercises (identify the captured evidence key, pick the matching manual
verification, restore the walkthrough order, rank sibling findings by risk) with
explanations and in-page grading. This is the intended loop: read the track, study a real
finding, answer the questions, then mark the lesson done.

**AI explain** asks the configured LLM for a student-facing note (plain language, why it
matters, manual verification, practice tip) grounded only in that check's curated notes;
without an LLM key it returns the same deterministic note and is badged `grounded
fallback`. The same page shows installed analysis plugins, their limits and any discovery
problems — use it to turn findings into a lesson or to review what a plugin will see.

## 8. Settings

- Default scan profile and per-check disable list (disabling suppresses findings only;
  requests still pass the safety chokepoint).
- Test-account credentials for authenticated checks (encrypted at rest; values are never
  shown again).
- AI provider/model/base URL/key.
- Integrations status: Nuclei, Burp, upstream proxy, plugin directories.

## 9. Activity and accountability

**Activity** is the audit log: logins, failed and throttled sign-ins, verification attempts,
scans, cancellations, credential changes, imports/exports, report creation/downloads and AI
calls. Secrets in details are redacted. When in doubt about what ran and under which
authorization, start here.

Five failed sign-ins lock the account for 15 minutes (configurable); a separate higher
per-IP limit keeps one locked account from blocking everyone on the same network. Blocked
attempts show as **Sign-in throttled** with the retry delay in the response.

## 10. Rules of engagement

- Scan only targets you are explicitly authorized to test, within the agreed scope.
- Do not enable `ALLOW_PRIVATE_TARGETS` or point scans at infrastructure you do not own.
- Do not treat a suspected finding as confirmed until you verify it manually.
- Report vulnerabilities through the owner's channel; do not retain client data longer
  than the engagement requires.
