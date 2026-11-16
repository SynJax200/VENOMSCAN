from __future__ import annotations

from venomscan_engine.checks.probes import (
    canary,
    get_probe,
    is_html,
    looks_blocked,
    probe_points,
    with_value,
)
from venomscan_engine.checks.registry import register
from venomscan_engine.context import ScanContext
from venomscan_engine.models import Finding, Severity, VerificationStatus

MAX_PROBES = 4
MAX_REQUESTS = 12


@register
class ReflectedXssCheck:
    id = "venom.xss.reflected"
    name = "Reflected XSS (canary)"
    category = "injection"
    default_severity = Severity.HIGH
    profile = "active"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if ctx.root is None:
            return []

        findings: list[Finding] = []
        requests = 0
        for point in probe_points(ctx, MAX_PROBES, preferred=("q", "search", "query", "name", "msg")):
            if requests >= MAX_REQUESTS or ctx.remaining_seconds < 5:
                break
            token = canary(ctx, self.id, point.parameter)
            control = f"vs{token}plain"
            control_response = await get_probe(ctx, point, control)
            requests += 1
            if (
                control_response is None
                or control_response.status_code >= 500
                or looks_blocked(control_response)
                or control not in control_response.body
            ):
                continue

            # Unknown element: proves unescaped reflection without executing script.
            payload = f"vs<{token}>"
            response = await get_probe(ctx, point, payload)
            requests += 1
            if response is None or response.status_code >= 500 or not is_html(response):
                continue
            if looks_blocked(response) or payload not in response.body:
                continue

            variants = 1
            second_payload = f'"><vs{token}x>'
            if requests < MAX_REQUESTS and ctx.remaining_seconds >= 5:
                second = await get_probe(ctx, point, second_payload)
                requests += 1
                if (
                    second is not None
                    and second.status_code < 500
                    and is_html(second)
                    and not looks_blocked(second)
                    and second_payload in second.body
                ):
                    variants = 2

            confirmed = variants == 2
            findings.append(
                Finding(
                    check_id=self.id,
                    title="Reflected input is not HTML-escaped",
                    category=self.category,
                    severity=Severity.HIGH,
                    confidence=9 if confirmed else 6,
                    verification_status=(
                        VerificationStatus.VERIFIED if confirmed else VerificationStatus.SUSPECTED
                    ),
                    url=point.url,
                    parameter=point.parameter,
                    payload=payload,
                    description=(
                        f"The {point.parameter!r} parameter was reflected into the HTML response "
                        "verbatim, including raw angle brackets. A script payload in the same "
                        "position would execute in the victim's browser."
                        + (
                            " A second payload with quotes and brackets was also reflected raw, "
                            "so the escaping gap is reproducible."
                            if confirmed
                            else " Only the first payload was reflected raw; the second variant "
                            "did not reproduce, so this needs manual confirmation."
                        )
                    ),
                    impact=(
                        "An attacker can craft a link that runs script in a victim's session on the "
                        "victim site, read page data and act as that user."
                    ),
                    remediation=(
                        "Context-aware output encoding for HTML, attributes, JavaScript and URLs; "
                        "add a restrictive Content-Security-Policy as defence in depth."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/xss/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                    ],
                    cwe=["CWE-79"],
                    owasp=["A03:2021 Injection"],
                    request_evidence={"method": "GET", "url": with_value(point, payload)},
                    response_evidence={
                        "url": response.url,
                        "status_code": response.status_code,
                        "content_type": response.header("content-type"),
                        "reflection": "raw-payload",
                        "control_reflected": True,
                        "variants_reflected": variants,
                        "block_page": False,
                    },
                )
            )
            if len(findings) >= MAX_PROBES:
                break
        return findings
