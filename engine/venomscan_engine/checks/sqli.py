from __future__ import annotations

import re

from venomscan_engine.checks.probes import (
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
CONTROL_VALUE = "1"

# Error signatures that only appear when a database rejects malformed syntax.
_ERROR_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("mysql", re.compile(r"(?i)(SQL syntax.*MySQL|Warning.*mysql_|check the manual that corresponds to your MySQL)")),
    ("postgres", re.compile(r"(?i)(PostgreSQL.*ERROR|unterminated quoted string|syntax error at or near)")),
    ("oracle", re.compile(r"(?i)ORA-\d{4,5}")),
    ("mssql", re.compile(r"(?i)(Microsoft OLE DB Provider for SQL Server|Unclosed quotation mark after the character string)")),
    ("sqlite", re.compile(r"(?i)(sqlite3\.OperationalError|SQLite/JDBCDriver|SQLite.Exception)")),
)


def _family(body: str) -> str | None:
    return next((name for name, pattern in _ERROR_SIGNATURES if pattern.search(body)), None)


@register
class SqlErrorCheck:
    id = "venom.sqli.error"
    name = "SQL injection (error-based canary)"
    category = "injection"
    default_severity = Severity.MEDIUM
    profile = "active"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if ctx.root is None:
            return []

        findings: list[Finding] = []
        for point in probe_points(
            ctx, MAX_PROBES, preferred=("id", "cat", "page", "sort", "filter", "user", "item")
        ):
            if ctx.remaining_seconds < 6:
                break
            # A benign value must stay clean: error pages that always render a driver
            # message are a generic failure page, not injection evidence.
            control = await get_probe(ctx, point, CONTROL_VALUE)
            if control is None:
                continue
            if _family(control.body) is not None or looks_blocked(control):
                continue

            payload = "'"
            response = await get_probe(ctx, point, payload)
            if response is None or not is_html(response) or looks_blocked(response):
                continue
            family = _family(response.body)
            if family is None:
                continue

            repeat = await get_probe(ctx, point, payload)
            confirmed = (
                repeat is not None
                and is_html(repeat)
                and not looks_blocked(repeat)
                and _family(repeat.body) == family
            )
            findings.append(
                Finding(
                    check_id=self.id,
                    title="SQL error disclosed after quote probe",
                    category=self.category,
                    severity=Severity.MEDIUM,
                    confidence=9 if confirmed else 6,
                    verification_status=(
                        VerificationStatus.VERIFIED if confirmed else VerificationStatus.SUSPECTED
                    ),
                    url=point.url,
                    parameter=point.parameter,
                    payload=payload,
                    description=(
                        f"A single quote in the {point.parameter!r} parameter produced a {family} "
                        "database error while the benign control value stayed clean. The "
                        "application passes the value into a SQL statement without proper "
                        "parameterisation."
                        + (
                            " The same payload reproduced the error on a second request."
                            if confirmed
                            else " The error did not reproduce on a second request, so this "
                            "needs manual confirmation."
                        )
                    ),
                    impact=(
                        "Confirmed injectable input can expose or modify data depending on the "
                        "database permissions of the application account."
                    ),
                    remediation=(
                        "Use parameterised queries/ORM bindings for every value; suppress driver "
                        "errors from responses and log them server-side instead."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/SQL_Injection",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html",
                    ],
                    cwe=["CWE-89"],
                    owasp=["A03:2021 Injection"],
                    request_evidence={"method": "GET", "url": with_value(point, payload)},
                    response_evidence={
                        "url": response.url,
                        "status_code": response.status_code,
                        "error_family": family,
                        "control_value": CONTROL_VALUE,
                        "control_clean": True,
                        "repeat_confirmed": confirmed,
                    },
                )
            )
        return findings
