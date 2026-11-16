from __future__ import annotations

import re
from urllib.parse import urlsplit

from venomscan_engine.checks.cookies import parse_set_cookie
from venomscan_engine.checks.registry import register
from venomscan_engine.context import ScanContext
from venomscan_engine.models import Finding, Severity

_SESSION_LIKE = re.compile(r"(sess|sid|token|auth|jwt|remember)", re.IGNORECASE)


@register
class SessionScopeCheck:
    id = "venom.session"
    name = "Session cookie scope"
    category = "session"
    default_severity = Severity.MEDIUM
    profile = "safe"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        root = ctx.root
        if root is None or not root.set_cookies:
            return []
        host = (urlsplit(root.url).hostname or "").lower()
        findings: list[Finding] = []
        seen: set[str] = set()

        for raw in root.set_cookies:
            parsed = parse_set_cookie(raw)
            if parsed is None:
                continue
            name, attrs = parsed
            if name in seen or not _SESSION_LIKE.search(name):
                continue
            seen.add(name)
            domain = (attrs.get("domain") or "").lstrip(".").lower()
            if not domain or not host or domain == host:
                continue
            if not host.endswith("." + domain):
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    title=f"Session cookie '{name}' is scoped to the parent domain",
                    category=self.category,
                    severity=Severity.MEDIUM,
                    confidence=9,
                    url=root.url,
                    parameter=name,
                    description=f"The session cookie '{name}' declares Domain={attrs.get('domain')}, "
                    f"so browsers also send it to every sibling host under {domain}. The cookie is "
                    f"only needed by {host}.",
                    impact="Any compromised or attacker-controlled sibling subdomain receives the "
                    "victim's session cookie.",
                    remediation=f"Remove the Domain attribute (or set Domain={host}) so the cookie "
                    "stays host-only, keep HttpOnly/Secure/SameSite, and isolate untrusted "
                    "subdomains on a separate registrable domain.",
                    references=[
                        "https://developer.mozilla.org/docs/Web/HTTP/Cookies",
                        "https://cwe.mitre.org/data/definitions/565.html",
                    ],
                    cwe=["CWE-565", "CWE-1275"],
                    owasp=["A07:2021 Identification and Authentication Failures"],
                    request_evidence={"method": "GET", "url": root.url},
                    response_evidence={"cookie": name, "domain": attrs.get("domain")},
                )
            )
        return findings
