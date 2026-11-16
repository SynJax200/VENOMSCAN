from __future__ import annotations

import re
from urllib.parse import urlsplit

from venomscan_engine.checks.registry import register
from venomscan_engine.context import ScanContext
from venomscan_engine.models import Finding, Severity

# Only pages that establish or expose a session are worth a cache finding.
_SENSITIVE_PATH = re.compile(
    r"/(login|signin|sign-in|account|admin|dashboard|settings|profile|checkout|orders?|billing)"
    r"(/|$)",
    re.IGNORECASE,
)


@register
class CacheablePageCheck:
    id = "venom.cache"
    name = "Cache policy on authenticated pages"
    category = "cache"
    default_severity = Severity.MEDIUM
    profile = "safe"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        pages = ctx.artifacts.get("pages") or []
        if ctx.root is None or not isinstance(pages, list):
            return []
        findings: list[Finding] = []
        for page in pages:
            if not isinstance(page, dict) or page.get("status_code") != 200:
                continue
            url = page.get("url") or ""
            if not _SENSITIVE_PATH.search(urlsplit(url).path):
                continue
            if not page.get("set_cookie"):
                continue
            cache_control = (page.get("cache_control") or "").lower()
            pragma = (page.get("pragma") or "").lower()
            if "no-store" in cache_control or "private" in cache_control or "no-cache" in pragma:
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    title="Authenticated page can be cached",
                    category=self.category,
                    severity=Severity.MEDIUM,
                    confidence=8,
                    url=url,
                    description=f"The response from {urlsplit(url).path} sets a cookie but does not "
                    "restrict caching (Cache-Control lacks no-store/private and Pragma lacks "
                    "no-cache). Browsers and shared proxies may store the body.",
                    impact="Session-specific content can be replayed from a shared machine or "
                    "intermediary cache after logout.",
                    remediation="Send Cache-Control: no-store (or at minimum private, no-cache) "
                    "and avoid caching Set-Cookie responses at the CDN.",
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/",
                        "https://cwe.mitre.org/data/definitions/524.html",
                    ],
                    cwe=["CWE-524"],
                    owasp=["A05:2021 Security Misconfiguration"],
                    request_evidence={"method": "GET", "url": url},
                    response_evidence={
                        "url": url,
                        "cache_control": page.get("cache_control") or "",
                        "pragma": page.get("pragma") or "",
                        "set_cookie": True,
                    },
                )
            )
        return findings
