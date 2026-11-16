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

MAX_PROBES = 3


def ssti_operands(token: str) -> tuple[int, int]:
    return int(token[:4], 16) % 800 + 100, int(token[4:8], 16) % 80 + 10


def ssti_payload(token: str) -> tuple[str, str]:
    left, right = ssti_operands(token)
    return f"{{{{{left}*{right}}}}}", str(left * right)


def ssti_confirm_payload(token: str) -> tuple[str, str]:
    left, right = ssti_operands(token)
    confirm_left, confirm_right = left + 7, right + 3
    return f"{{{{{confirm_left}*{confirm_right}}}}}", str(confirm_left * confirm_right)


@register
class SstiCheck:
    id = "venom.ssti"
    name = "Server-side template injection (canary)"
    category = "injection"
    default_severity = Severity.HIGH
    profile = "active"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if ctx.root is None:
            return []

        findings: list[Finding] = []
        for point in probe_points(
            ctx, MAX_PROBES, preferred=("name", "q", "search", "message", "template", "title")
        ):
            if ctx.remaining_seconds < 6:
                break
            token = canary(ctx, self.id, point.parameter)
            payload, expected = ssti_payload(token)
            response = await get_probe(ctx, point, payload)
            if response is None or response.status_code >= 500 or not is_html(response):
                continue
            if looks_blocked(response) or payload in response.body or expected not in response.body:
                continue

            confirm_payload, confirm_expected = ssti_confirm_payload(token)
            confirm = await get_probe(ctx, point, confirm_payload)
            confirmed = (
                confirm is not None
                and confirm.status_code < 500
                and is_html(confirm)
                and not looks_blocked(confirm)
                and confirm_payload not in confirm.body
                and confirm_expected in confirm.body
            )
            findings.append(
                Finding(
                    check_id=self.id,
                    title="Server-side template expression was evaluated",
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
                        f"The {point.parameter!r} parameter was rendered through a template engine: "
                        f"the canary expression {payload} returned {expected} in the response "
                        "instead of the literal text."
                        + (
                            " A second expression with different operands returned its own "
                            "product, confirming evaluation rather than a coincidental number."
                            if confirmed
                            else " A second expression did not reproduce, so this needs manual "
                            "confirmation."
                        )
                    ),
                    impact=(
                        "Template injection can escalate to server-side code execution and full "
                        "compromise of the application host."
                    ),
                    remediation=(
                        "Never compile user input as a template. Pass user values as context "
                        "variables and keep templates static; sandbox or remove risky template "
                        "features."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/Server_Side_Template_Injection"
                    ],
                    cwe=["CWE-94"],
                    owasp=["A03:2021 Injection"],
                    request_evidence={"method": "GET", "url": with_value(point, payload)},
                    response_evidence={
                        "url": response.url,
                        "status_code": response.status_code,
                        "evaluated": expected,
                        "variants_evaluated": 2 if confirmed else 1,
                    },
                )
            )
        return findings
