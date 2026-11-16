from __future__ import annotations

import re

from venomscan_engine.checks.probes import get_probe, looks_blocked, probe_points, with_value
from venomscan_engine.checks.registry import register
from venomscan_engine.context import ScanContext
from venomscan_engine.models import Finding, Severity, VerificationStatus

MAX_POINTS = 2
CONTROL_VALUE = "vs-control.html"

# Read-only traversal probes; matched file contents are never stored in findings.
_PAYLOADS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "unix_passwd",
        "../../../../../../etc/passwd",
        re.compile(r"(?m)^root:[x*]?:0:0:"),
    ),
    (
        "windows_ini",
        "..\\..\\..\\..\\..\\windows\\win.ini",
        re.compile(r"(?im)^\[fonts\]"),
    ),
)
_PATH_PARAMS = ("file", "path", "page", "include", "view", "download", "doc", "folder", "template")


@register
class PathTraversalCheck:
    id = "venom.lfi.path"
    name = "Path traversal / LFI (canary)"
    category = "files"
    default_severity = Severity.HIGH
    profile = "active"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if ctx.root is None:
            return []

        points = [
            point
            for point in probe_points(ctx, MAX_POINTS * 4, preferred=_PATH_PARAMS)
            if any(word in point.parameter.lower() for word in _PATH_PARAMS)
        ][:MAX_POINTS]

        findings: list[Finding] = []
        for point in points:
            control = await get_probe(ctx, point, CONTROL_VALUE)
            if control is None or looks_blocked(control):
                continue
            for label, payload, pattern in _PAYLOADS:
                response = await get_probe(ctx, point, payload)
                if response is None or response.status_code != 200 or looks_blocked(response):
                    continue
                if not pattern.search(response.body):
                    continue
                if pattern.search(control.body):
                    continue
                findings.append(
                    Finding(
                        check_id=self.id,
                        title="Path traversal reached a system file",
                        category=self.category,
                        severity=Severity.HIGH,
                        confidence=9,
                        verification_status=VerificationStatus.VERIFIED,
                        url=point.url,
                        parameter=point.parameter,
                        payload=payload,
                        description=(
                            f"The {point.parameter!r} parameter accepted a traversal sequence and "
                            f"returned the contents of a known system file ({label}). Matching file "
                            "contents are intentionally omitted from the evidence."
                        ),
                        impact=(
                            "An attacker can read files outside the web root, including secrets, "
                            "configuration and credentials."
                        ),
                        remediation=(
                            "Resolve requested paths against a fixed allowlist inside the web root; "
                            "reject traversal sequences and never pass raw paths to file APIs."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/Path_Traversal",
                            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
                        ],
                        cwe=["CWE-22"],
                        owasp=["A01:2021 Broken Access Control"],
                        request_evidence={"method": "GET", "url": with_value(point, payload)},
                        response_evidence={
                            "url": response.url,
                            "status_code": response.status_code,
                            "matched_file": label,
                            "control_value": CONTROL_VALUE,
                            "control_clean": True,
                            "body_stored": False,
                        },
                    )
                )
                break
        return findings
