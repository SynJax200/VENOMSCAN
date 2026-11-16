from __future__ import annotations

from venomscan_engine.checks.registry import register
from venomscan_engine.context import ScanContext
from venomscan_engine.models import Finding, Severity
from venomscan_engine.safety.http import TargetUnreachable, TooManyRedirects

CANARY_ORIGIN = "https://venomscan-canary.invalid"


@register
class CORSMisconfigCheck:
    id = "venom.cors.misconfig"
    name = "CORS policy"
    category = "cors"
    default_severity = Severity.MEDIUM
    profile = "safe"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        root = ctx.root
        if root is None or ctx.client is None or ctx.remaining_seconds < 3:
            return []
        try:
            response = await ctx.client.request("GET", root.url, headers={"Origin": CANARY_ORIGIN})
        except (TargetUnreachable, TooManyRedirects):
            return []

        allowed = (response.header("access-control-allow-origin") or "").strip()
        if allowed != CANARY_ORIGIN:
            return []
        credentials = (response.header("access-control-allow-credentials") or "").lower() == "true"
        severity = Severity.HIGH if credentials else Severity.MEDIUM
        return [
            Finding(
                check_id=self.id,
                title="CORS policy reflects arbitrary origins"
                + (" with credentials" if credentials else ""),
                category=self.category,
                severity=severity,
                confidence=10,
                url=root.url,
                description=(
                    f"A request carrying Origin: {CANARY_ORIGIN} was answered with "
                    f"Access-Control-Allow-Origin: {CANARY_ORIGIN}"
                    + (
                        " and Access-Control-Allow-Credentials: true. Any website can read "
                        "authenticated responses with the victim's session."
                        if credentials
                        else "."
                    )
                ),
                impact=(
                    "Cross-origin data theft: an attacker-controlled page can read responses "
                    "intended for this application."
                    if not credentials
                    else "Full account takeover surface: an attacker page can read authenticated "
                    "API responses with the victim's cookies."
                ),
                remediation="Use a strict allowlist of trusted origins. Never reflect the request "
                "Origin, and only enable credentials for origins that require it.",
                references=[
                    "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
                    "https://developer.mozilla.org/docs/Web/HTTP/CORS",
                ],
                cwe=["CWE-942"],
                owasp=["A05:2021 Security Misconfiguration"],
                request_evidence={
                    "method": "GET",
                    "url": root.url,
                    "origin": CANARY_ORIGIN,
                },
                response_evidence={
                    "url": response.url,
                    "status_code": response.status_code,
                    "access_control_allow_origin": allowed,
                    "access_control_allow_credentials": credentials,
                },
            )
        ]
