from __future__ import annotations

from venomscan_engine.checks.probes import ProbePoint, get_probe, probe_points, with_value
from venomscan_engine.checks.registry import register
from venomscan_engine.context import ScanContext
from venomscan_engine.models import Finding, Severity, VerificationStatus
from venomscan_engine.safety.http import ResponseBundle

MAX_POINTS = 2
DELAY_SECONDS = 3.0
DELAY_MS = int(DELAY_SECONDS * 1000)
# A delayed payload must still be delayed on a second run; the baseline is the
# fastest of two clean requests so ordinary jitter never masquerades as a delay.
BASELINE_SAMPLES = 2
CONFIRM_ATTEMPTS = 2

# One read-only payload per major engine family. Each asks the database to sleep
# for a fixed, bounded interval; nothing is written or extracted.
PAYLOADS: tuple[tuple[str, str], ...] = (
    ("mysql", f"' AND SLEEP({DELAY_SECONDS:g})-- -"),
    ("postgres", f"'; SELECT pg_sleep({DELAY_SECONDS:g})-- "),
    ("mssql", f"'; WAITFOR DELAY '0:0:{DELAY_SECONDS:g}'-- "),
)


def _fastest(samples: list[int]) -> int:
    return min(samples) if samples else 0


def _is_delayed(elapsed_ms: int, baseline_ms: int) -> bool:
    return elapsed_ms - baseline_ms >= DELAY_MS


async def _timed_probe(
    ctx: ScanContext, point: ProbePoint, value: str
) -> ResponseBundle | None:
    return await get_probe(ctx, point, value)


@register
class TimeBasedSqliCheck:
    id = "venom.sqli.time"
    name = "SQL injection (time-based canary)"
    category = "injection"
    default_severity = Severity.HIGH
    profile = "active"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if ctx.root is None or ctx.client is None:
            return []

        findings: list[Finding] = []
        for point in probe_points(
            ctx, MAX_POINTS, preferred=("id", "cat", "page", "item", "user", "sort")
        ):
            if ctx.remaining_seconds < DELAY_SECONDS * 3 + 5:
                break
            finding = await self._probe_point(ctx, point)
            if finding is not None:
                findings.append(finding)
        return findings

    async def _probe_point(self, ctx: ScanContext, point: ProbePoint) -> Finding | None:
        baseline_samples: list[int] = []
        for _ in range(BASELINE_SAMPLES):
            response = await _timed_probe(ctx, point, "1")
            if response is None:
                return None
            baseline_samples.append(response.elapsed_ms)
        baseline = _fastest(baseline_samples)

        for family, payload in PAYLOADS:
            if ctx.remaining_seconds < DELAY_SECONDS * 2 + 4:
                return None
            first = await _timed_probe(ctx, point, payload)
            if first is None:
                return None
            if not _is_delayed(first.elapsed_ms, baseline):
                continue
            elapsed = [first.elapsed_ms]
            for _ in range(CONFIRM_ATTEMPTS):
                if ctx.remaining_seconds < DELAY_SECONDS + 3:
                    break
                again = await _timed_probe(ctx, point, payload)
                if again is None:
                    break
                elapsed.append(again.elapsed_ms)
            delayed = sum(1 for ms in elapsed if _is_delayed(ms, baseline))
            if delayed < 2:
                continue
            return Finding(
                check_id=self.id,
                title="Time-based SQL injection confirmed by repeated delay",
                category=self.category,
                severity=Severity.HIGH,
                confidence=9,
                verification_status=VerificationStatus.SUSPECTED,
                url=point.url,
                parameter=point.parameter,
                payload=payload,
                description=(
                    f"The {point.parameter!r} parameter took about {DELAY_SECONDS:g}s longer than "
                    f"the baseline in {delayed} of {len(elapsed)} attempts when a {family} "
                    "sleep payload was supplied. The application evaluates injected SQL, not "
                    "just its syntax."
                ),
                impact=(
                    "Blind SQL injection lets an attacker enumerate and extract database "
                    "contents one bit at a time using the same timing channel."
                ),
                remediation=(
                    "Bind every value through parameterised queries or an ORM; reject "
                    "unexpected types and keep database error/timing behaviour uniform."
                ),
                references=[
                    "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html",
                ],
                cwe=["CWE-89"],
                owasp=["A03:2021 Injection"],
                request_evidence={"method": "GET", "url": with_value(point, payload)},
                response_evidence={
                    "baseline_ms": baseline,
                    "attempt_ms": elapsed,
                    "delayed_attempts": delayed,
                    "family": family,
                    "threshold_ms": DELAY_MS,
                },
            )
        return None
