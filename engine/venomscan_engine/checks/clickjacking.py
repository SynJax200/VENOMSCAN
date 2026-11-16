from __future__ import annotations

from venomscan_engine.checks.base import is_interstitial, response_evidence
from venomscan_engine.checks.registry import register
from venomscan_engine.context import ScanContext
from venomscan_engine.models import Finding, Severity


@register
class ClickjackingCheck:
    id = "venom.clickjacking"
    name = "Frame protection"
    category = "config"
    default_severity = Severity.MEDIUM
    profile = "passive"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        root = ctx.root
        if root is None or is_interstitial(root):
            return []
        csp = root.header("content-security-policy") or ""
        if root.header("x-frame-options") or "frame-ancestors" in csp.lower():
            return []
        return [
            Finding(
                check_id=self.id,
                title="Page can be framed by any origin",
                category=self.category,
                severity=Severity.MEDIUM,
                confidence=9,
                url=root.url,
                description="Neither X-Frame-Options nor a CSP frame-ancestors directive was "
                "returned. Any site can embed this page in an iframe and overlay UI on top of it.",
                impact="Logged-in users can be tricked into clicking controls they cannot see "
                "(clickjacking), including state-changing actions.",
                remediation="Send X-Frame-Options: DENY (or SAMEORIGIN where framing is needed) and "
                "add frame-ancestors 'none' to the Content-Security-Policy.",
                references=[
                    "https://owasp.org/www-community/attacks/Clickjacking",
                    "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options",
                ],
                cwe=["CWE-1021"],
                owasp=["A05:2021 Security Misconfiguration"],
                request_evidence={"method": "GET", "url": root.url},
                response_evidence=response_evidence(ctx),
            )
        ]
