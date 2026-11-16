from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

from venomscan_engine.checks.registry import register
from venomscan_engine.context import ScanContext
from venomscan_engine.models import Finding, Severity

MAX_FINDINGS = 16


@dataclass(frozen=True)
class _Rule:
    label: str
    severity: Severity
    confidence: int
    pattern: re.Pattern[str]


_RULES: tuple[_Rule, ...] = (
    _Rule("AWS access key", Severity.HIGH, 9, re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    _Rule("GitHub token", Severity.HIGH, 9, re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b")),
    _Rule("Stripe secret key", Severity.HIGH, 9, re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b")),
    _Rule(
        "Private key block",
        Severity.HIGH,
        9,
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    _Rule("Slack token", Severity.MEDIUM, 8, re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    _Rule("Google API key", Severity.LOW, 6, re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
)

_GENERIC = re.compile(
    r"""(?i)\b(?:api[_-]?key|secret|token|passwd|password)\b["'\s:=]{1,4}"""
    r"""(["']?)([A-Za-z0-9_\-/+.]{24,})\1"""
)
_PLACEHOLDER = re.compile(
    r"(?i)(example|sample|placeholder|your[_-]?|xxxx|changeme|dummy|redacted|localhost|"
    r"abcdef|123456|000000)"
)


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _mask(value: str) -> str:
    if len(value) <= 10:
        return "«redacted»"
    return f"{value[:4]}…{value[-4:]} (len {len(value)})"


def _finding(source: dict, label: str, masked: str, severity: Severity, confidence: int) -> Finding:
    origin = source["url"]
    return Finding(
        check_id="venom.secrets.js",
        title=f"Potential secret in JavaScript: {label}",
        category="secrets",
        severity=severity,
        confidence=confidence,
        url=origin,
        parameter=label,
        description=(
            f"The JavaScript delivered to the browser contains a value matching the {label} "
            "pattern. Values shipped to clients are public regardless of how the bundle is "
            "minified or obfuscated."
        ),
        impact="A live credential can grant access to a third-party service or backend data "
        "outside the application's authorization model.",
        remediation="Revoke and rotate the credential, move the call to the server side, and add "
        "a build-time secret scanner so it cannot be reintroduced.",
        references=[
            "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
            "https://cwe.mitre.org/data/definitions/798.html",
        ],
        cwe=["CWE-798", "CWE-200"],
        owasp=["A02:2021 Cryptographic Failures"],
        request_evidence={"method": "GET", "url": origin},
        response_evidence={
            "url": origin,
            "inline": bool(source.get("inline")),
            "pattern": label,
            "masked_value": masked,
        },
    )


@register
class JSSecretsCheck:
    id = "venom.secrets.js"
    name = "Hardcoded secrets in JavaScript"
    category = "secrets"
    default_severity = Severity.HIGH
    profile = "safe"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        scripts = ctx.artifacts.get("scripts") or []
        if not isinstance(scripts, list):
            return []

        findings: list[Finding] = []
        for source in scripts:
            if len(findings) >= MAX_FINDINGS or not isinstance(source, dict):
                break
            body = source.get("body") or ""
            if not body:
                continue
            matched: set[str] = set()
            for rule in _RULES:
                if len(findings) >= MAX_FINDINGS:
                    break
                match = rule.pattern.search(body)
                if match is None or rule.label in matched:
                    continue
                matched.add(rule.label)
                findings.append(
                    _finding(source, rule.label, _mask(match.group(0)), rule.severity, rule.confidence)
                )

            if len(findings) >= MAX_FINDINGS:
                continue
            for match in _GENERIC.finditer(body):
                value = match.group(2)
                if _PLACEHOLDER.search(value) or _entropy(value) < 3.5 or len(set(value)) < 10:
                    continue
                findings.append(
                    _finding(
                        source, "Generic secret assignment", _mask(value), Severity.MEDIUM, 6
                    )
                )
                break
        return findings
