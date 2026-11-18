# Free-tier deployment on Render + Neon

The cheapest way to put VENOMSCAN online without a VPS. Two Render Docker
services (API and web) talk to a free Neon Postgres database. Everything is
created from [`render.yaml`](../render.yaml); the only value you type is the
database connection string.

**What you get:** a public HTTPS URL on `*.onrender.com`, no card required, no
expiry on the database. **What you give up:** the free instance sleeps after
15 minutes idle (first request afterwards takes about a minute), has 512 MB of
RAM, and runs one instance — so keep the safe profile, small request budgets
and no Celery worker. For a permanent installation with Nuclei, OOB and workers
use the VPS runbook in [DEPLOYMENT.md](DEPLOYMENT.md) instead.

> Render hands out `https://<service>.onrender.com` names. `nip.io` /
> `sslip.io` subdomains are for self-hosted VMs with an IP but no DNS; they are
> not needed here. A custom domain can be attached later in the dashboard.

---

## 1. Create the database (Neon)

1. Sign in at <https://neon.com> and create a project. Pick **AWS us-east-2
   (Ohio)** so it sits next to the Render region in the blueprint.
2. Open **Connect**, switch **Connection pooling** off (the API runs one
   instance, so the direct host avoids PgBouncer prepared-statement limits),
   and copy the connection string. It looks like:

   ```
   postgresql://neondb_owner:<password>@ep-cool-name-123456.c-9.us-east-2.aws.neon.tech/neondb?sslmode=require
   ```

3. Change the driver prefix from `postgresql://` to `postgresql+psycopg://` and
   drop any `&channel_binding=require` parameter:

   ```
   postgresql+psycopg://neondb_owner:<password>@ep-cool-name-123456.c-9.us-east-2.aws.neon.tech/neondb?sslmode=require
   ```

   The `?sslmode=require` part is mandatory — Neon rejects plaintext
   connections and the API will fail its first deploy without it.

Keep the string somewhere private; it is the only secret you enter by hand.

Neon's free tier suspends an idle database after a few minutes. The first query
after a suspension reconnects automatically but adds a second or two.

---

## 2. Deploy the blueprint (Render)

1. Sign in at <https://dashboard.render.com> with GitHub and grant access to
   the repository.
2. **New → Blueprint**, pick this repository, keep the branch `main`. Render
   reads `render.yaml` and shows two services: `venomscan-api` and
   `venomscan-web`.
3. It asks for one value — `DATABASE_URL`. Paste the Neon string from step 1.
4. **Apply**. Render creates both services and wires `API_BASE`, `WEB_BASE` and
   `CORS_ORIGINS` on the API to the services' `RENDER_EXTERNAL_URL` values.

`API_INTERNAL_URL` on the web service is pinned in `render.yaml` to
`https://venomscan-api.onrender.com` — the public URL, because Render's
`fromService` host is the private short name (`venomscan-api`) that Next cannot
reach over HTTPS. If you rename the API service, update that value and push.

The API image installs Playwright Chromium, so the first build takes roughly
10–20 minutes. The web build follows it.

**Check:** the API's `/healthz` shows as live in the dashboard log, and
`https://<api-host>.onrender.com/healthz` returns `{"status":"ok", ...}`.

> If a referenced value is empty or stale, open the Blueprint page and click
> **Manual sync** — `fromService` references are resolved on each sync.

---

## 3. First account and closing sign-up

1. Open the web service URL (`https://<web-host>.onrender.com`). It redirects
   to `/login`; use **Register**.
2. The first registered account becomes the administrator — the blueprint
   starts with `ALLOW_REGISTRATION=true` for exactly this reason.
3. In Render, open `venomscan-api` → **Environment** → set
   `ALLOW_REGISTRATION` to `false` → **Save** (this redeploys the service).
   Later registrations now get `403 Registration is closed on this
   installation`; existing accounts keep working.

Add the targets you own and complete the ownership check before the first scan.
The authorization gate is enforced server-side; scanning anything you do not
control is out of scope — see [SAFETY.md](SAFETY.md).

---

## 4. Optional: enable the AI layer

The blueprint ships with `AI_AUTO_TRIAGE=false` and `AI_REPORT_AUTOFILL=false`,
so scans use the deterministic analysis path. To turn the model on:

1. `venomscan-api` → **Environment** → add `LLM_API_KEY` (secret) and
   `LLM_MAX_TOKENS=4096`.
2. If you use Gemini's OpenAI-compatible endpoint, also set
   `AI_ALLOWED_HOSTS=generativelanguage.googleapis.com` — the provider URL is
   rejected unless its host is on this allowlist.
3. Redeploy, then open **Settings → AI**, keep provider
   `openai_compat`, set the model (e.g. `gemini-3-flash-preview`) and the base
   URL (`https://generativelanguage.googleapis.com/v1beta/openai/`), save the
   key and press **Test provider**.

Settings saved in the UI live in the database and override the environment
variables for provider/model/base URL, so a stale row is the usual cause of a
`404` from the provider. On a free instance leave `AI_AUTO_TRIAGE` off unless
you want every scan to spend a model call.

---

## 5. Post-deploy checks

| # | Check | Expected |
| --- | --- | --- |
| 1 | `https://<api-host>.onrender.com/healthz` | `status: ok` |
| 2 | Web URL loads over HTTPS | login page, no mixed-content errors |
| 3 | Register → reload | session survives (cookie is `Secure`) |
| 4 | `POST /api/auth/register` after step 3 | `403 Registration is closed` |
| 5 | Add an owned target and verify it | target shows verified with an expiry date |
| 6 | Run a `safe` scan | completes; findings show evidence |
| 7 | Create a JSON and a PDF report | both download; PDF works within the 512 MB instance |
| 8 | Activity page | register, login, target and scan events listed |

Report links expire after 24 hours (`REPORT_LINK_HOURS`), which keeps a shared
demo URL from leaking old reports.

---

## 6. Updating and operating

- **Deploy a change:** push to `main`; both services rebuild
  (`autoDeployTrigger: commit`). Edits to `render.yaml` need the Blueprint's
  **Manual sync** afterwards.
- **Rotate secrets:** `SECRET_KEY` is generated by Render. Changing it
  invalidates sessions, CSRF tokens and signed report links; rotate
  `LLM_API_KEY` from the dashboard only.
- **Restart:** the free instance sleeps after 15 minutes without traffic and
  wakes on the next request. A scan is kept alive by the polling scan page;
  do not close the tab if you close the laptop screen.
- **Limits on free:** 512 MB RAM, one instance, no zero-downtime deploys. If
  PDF rendering or an `active` scan runs out of memory, use the smaller safe
  profile or move to a paid instance / the VPS stack.
- **Backups:** Neon keeps a short point-in-time history on free; run
  `scripts/backup.sh` locally against the same `DATABASE_URL` (or `pg_dump`
  manually) before risky operations.
- **Tear-down:** delete the Blueprint in Render and the Neon project. There is
  nothing on a persistent disk to preserve.

---

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| API deploy fails with a driver error | `DATABASE_URL` still starts with `postgresql://` — change it to `postgresql+psycopg://` |
| API dies on start with an SSL error | `?sslmode=require` is missing from the connection string |
| Web loads but every `/api` call is a 502 | The rewrite target is wrong or the API is asleep — check `API_INTERNAL_URL` on the web service and open `/healthz` once |
| Login bounces back to `/login` | Cookies need HTTPS; make sure `COOKIE_SECURE=true` and you are not testing on an `http://` URL |
| Provider test returns `404` | The database AI settings row points at an old model/base URL — update it in Settings → AI or clear it |
| Provider test returns `429` | Provider quota for that key, not a VENOMSCAN bug; wait or use another key |
| First request after a quiet period hangs ~1 min | Normal free-tier cold start on Render and Neon |
