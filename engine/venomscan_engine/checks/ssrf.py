from __future__ import annotations

import time
from urllib.parse import urlsplit

from venomscan_engine.checks.probes import canary, get_probe, probe_points, with_value
from venomscan_engine.checks.registry import register
from venomscan_engine.context import ScanContext
from venomscan_engine.models import Finding, Severity, VerificationStatus

MAX_ENDPOINTS = 2
CALLBACK_WAIT_SECONDS = 3.0
PARAM_HINTS = (
    "url",
    "uri",
    "link",
    "src",
    "source",
    "target",
    "dest",
    "redirect",
    "next",
    "continue",
    "return",
    "goto",
    "callback",
    "webhook",
    "feed",
    "image",
    "img",
    "avatar",
    "proxy",
    "host",
    "domain",
    "site",
    "endpoint",
    "fetch",
    "load",
)


def _url_shaped(name: str, value: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in PARAM_HINTS) or value.startswith(
        ("http://", "https://")
    )


@register
class SsrfCheck:
    id = "venom.ssrf"
    name = "SSRF (out-of-band callback)"
    category = "injection"
    default_severity = Severity.MEDIUM
    profile = "active"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        oob = ctx.artifacts.get("oob")
        if oob is None or not getattr(oob, "base_url", None):
            await ctx.emit(
                "analyzing",
                "warning",
                "SSRF skipped: no out-of-band listener is configured for this deployment",
                payload={"check_id": self.id},
            )
            return []
        if ctx.root is None or ctx.remaining_seconds < 8:
            return []

        findings: list[Finding] = []
        points = probe_points(ctx, MAX_ENDPOINTS, accept=_url_shaped)
        for point in points:
            if ctx.remaining_seconds < 6:
                break
            token = canary(ctx, self.id, point.parameter)
            callback_url = oob.url_for(token)
            probe_url = with_value(point, callback_url)
            started = time.time()
            response = await get_probe(ctx, point, callback_url)
            if response is None:
                continue
            wait_seconds = min(CALLBACK_WAIT_SECONDS, max(0.5, ctx.remaining_seconds - 2))
            hit = await oob.wait_for(token, wait_seconds, since=started)
            if hit is None:
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    title="Application fetched a URL chosen by the requester",
                    category=self.category,
                    severity=Severity.MEDIUM,
                    confidence=9,
                    verification_status=VerificationStatus.VERIFIED,
                    url=point.url,
                    parameter=point.parameter,
                    payload=callback_url,
                    description=(
                        f"The {point.parameter!r} parameter of {point.url} was replaced with an "
                        "out-of-band callback URL. The application made that request itself: the "
                        "listener recorded the callback for this scan's token."
                    ),
                    impact=(
                        "A server-side fetch lets an attacker reach internal services, cloud "
                        "metadata endpoints and local files through the server's network position."
                    ),
                    remediation=(
                        "Allowlist outbound destinations, resolve and pin IPs before connecting, "
                        "block loopback/private/link-local and cloud metadata ranges, disable "
                        "unneeded URL-fetch features and require user confirmation for external "
                        "fetches."
                    ),
                    references=[
                        "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
                    ],
                    cwe=["CWE-918"],
                    owasp=["A10:2021 Server-Side Request Forgery"],
                    request_evidence={
                        "method": "GET",
                        "url": probe_url,
                        "callback_host": urlsplit(callback_url).netloc,
                    },
                    response_evidence={
                        "callback_received": True,
                        "callback_method": hit.method,
                        "callback_path": hit.path,
                        "source_ip": hit.source_ip,
                        "body_stored": False,
                    },
                )
            )
        return findings
