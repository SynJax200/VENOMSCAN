from __future__ import annotations

import re
from urllib.parse import urlsplit

from venomscan_engine.checks.registry import register
from venomscan_engine.context import ScanContext
from venomscan_engine.models import Finding, Severity

_TOKEN = re.compile(
    r"(?i)(csrf|xsrf|authenticity|requestverification|antiforgery|nonce|(^|_)token($|_))"
)
_SKIP_TYPES = {"submit", "button", "reset", "image"}
_SEARCH_FIELDS = {"q", "query", "s", "search", "term", "terms", "keywords"}


def _same_host(left: str, right: str) -> bool:
    return urlsplit(left).hostname == urlsplit(right).hostname


@register
class CSRFTokenCheck:
    id = "venom.csrf.token"
    name = "Anti-CSRF token presence"
    category = "csrf"
    default_severity = Severity.MEDIUM
    profile = "safe"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        root = ctx.root
        forms = ctx.artifacts.get("forms") or []
        if root is None or not isinstance(forms, list):
            return []

        findings: list[Finding] = []
        for form in forms:
            if not isinstance(form, dict) or str(form.get("method", "")).upper() != "POST":
                continue
            action = form.get("action") or ""
            if not action or not _same_host(action, root.url):
                continue
            fields = [field for field in form.get("fields") or [] if field.get("name")]
            names = {field["name"] for field in fields}
            if any(_TOKEN.search(name) for name in names):
                continue
            if any(field.get("type") == "password" for field in fields):
                continue
            actionable = [field for field in fields if field.get("type") not in _SKIP_TYPES]
            if not actionable:
                continue
            if names and names <= {name.lower() for name in _SEARCH_FIELDS}:
                continue
            path = urlsplit(action).path or "/"
            findings.append(
                Finding(
                    check_id=self.id,
                    title=f"POST form {path} has no anti-CSRF token",
                    category=self.category,
                    severity=Severity.MEDIUM,
                    confidence=6,
                    url=form.get("page") or root.url,
                    parameter=action,
                    description=(
                        f"The form on {form.get('page')} submits a POST request to {path} with "
                        f"fields ({', '.join(sorted(names)) or 'none'}) but carries no recognizable "
                        "anti-CSRF token. This is a metadata-only observation: the handler may "
                        "verify SameSite cookies, Origin or a header-based token."
                    ),
                    impact="If no other control exists, another site can submit this form with the "
                    "victim's session and change server-side state.",
                    remediation="Use a per-session, unpredictable token in a hidden field (or a "
                    "double-submit cookie), validate it server-side, and set SameSite=Lax/Strict "
                    "on the session cookie.",
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
                    ],
                    cwe=["CWE-352"],
                    owasp=["A01:2021 Broken Access Control"],
                    request_evidence={"method": "POST", "url": action},
                    response_evidence={"page": form.get("page"), "fields": sorted(names)},
                )
            )
        return findings
