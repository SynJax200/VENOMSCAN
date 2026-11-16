from __future__ import annotations

import re

from venomscan_engine.checks.base import response_evidence
from venomscan_engine.checks.registry import register
from venomscan_engine.context import ScanContext
from venomscan_engine.models import Finding, Severity

_SESSION_LIKE = re.compile(r"(sess|sid|token|auth|jwt|remember)", re.IGNORECASE)


def parse_set_cookie(value: str) -> tuple[str, dict[str, str]] | None:
    segments = [segment.strip() for segment in value.split(";") if segment.strip()]
    if not segments or "=" not in segments[0]:
        return None
    name = segments[0].split("=", 1)[0].strip()
    if not name:
        return None
    attrs: dict[str, str] = {}
    for segment in segments[1:]:
        if "=" in segment:
            key, val = segment.split("=", 1)
            attrs[key.strip().lower()] = val.strip()
        else:
            attrs[segment.lower()] = ""
    return name, attrs


@register
class CookieFlagsCheck:
    id = "venom.cookies.flags"
    name = "Cookie security attributes"
    category = "session"
    default_severity = Severity.LOW
    profile = "passive"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        root = ctx.root
        if root is None or not root.set_cookies:
            return []

        findings: list[Finding] = []
        seen: set[str] = set()
        is_https = root.url.startswith("https://")

        for raw in root.set_cookies:
            parsed = parse_set_cookie(raw)
            if parsed is None:
                continue
            name, attrs = parsed
            if name in seen:
                continue
            seen.add(name)

            missing: list[str] = []
            if is_https and "secure" not in attrs:
                missing.append("Secure")
            if "httponly" not in attrs:
                missing.append("HttpOnly")
            if "samesite" not in attrs:
                missing.append("SameSite")
            if not missing:
                continue

            session_like = bool(_SESSION_LIKE.search(name))
            severity = Severity.MEDIUM if session_like or "HttpOnly" in missing else Severity.LOW
            findings.append(
                Finding(
                    check_id=self.id,
                    title=f"Cookie '{name}' is missing {', '.join(missing)}",
                    category=self.category,
                    severity=severity,
                    confidence=9,
                    url=root.url,
                    parameter=name,
                    description=(
                        f"The Set-Cookie header for '{name}' does not set: {', '.join(missing)}. "
                        "Cookies without HttpOnly are readable by injected JavaScript; cookies "
                        "without Secure can leak over plaintext HTTP; cookies without SameSite are "
                        "sent on some cross-site requests."
                    ),
                    impact="Session theft via XSS or network interception, and increased exposure to "
                    "cross-site request forgery.",
                    remediation=(
                        f"Set the cookie as '{name}=…; Secure; HttpOnly; SameSite=Lax' (use "
                        "SameSite=Strict for sensitive session cookies) and scope Path/Domain as "
                        "narrowly as possible."
                    ),
                    references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
                    cwe=["CWE-1004", "CWE-614"],
                    owasp=["A05:2021 Security Misconfiguration"],
                    request_evidence={"method": "GET", "url": root.url},
                    response_evidence={**response_evidence(ctx), "set_cookie": "«redacted»"},
                )
            )
        return findings
