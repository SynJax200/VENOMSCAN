from __future__ import annotations

from venomscan_engine.checks.base import is_interstitial, response_evidence
from venomscan_engine.checks.registry import register
from venomscan_engine.context import ScanContext
from venomscan_engine.models import Finding, Severity

_HARDENING_HEADERS = (
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
)

_HARDENING_DETAILS: dict[str, tuple[str, str]] = {
    "x-content-type-options": (
        "browsers may MIME-sniff a response and execute it as a different content type",
        "Send X-Content-Type-Options: nosniff.",
    ),
    "referrer-policy": (
        "full referrer URLs can leak sensitive paths and query strings to third parties",
        "Send Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
    ),
    "permissions-policy": (
        "powerful browser features remain available to embedded or compromised content",
        "Send Permissions-Policy restricting camera, microphone, geolocation and other unused features.",
    ),
    "cross-origin-opener-policy": (
        "cross-origin documents can keep a window opener reference, enabling XS-Leak and "
        "Spectre-style cross-origin attacks",
        "Send Cross-Origin-Opener-Policy: same-origin to isolate the browsing context group.",
    ),
}


@register
class SecurityHeadersCheck:
    id = "venom.headers.missing"
    name = "Security header configuration"
    category = "config"
    default_severity = Severity.MEDIUM
    profile = "passive"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        root = ctx.root
        if root is None or is_interstitial(root):
            return []
        findings: list[Finding] = []
        csp = root.header("content-security-policy")
        hsts = root.header("strict-transport-security")
        is_https = root.url.startswith("https://")

        if not csp:
            findings.append(
                Finding(
                    check_id="venom.headers.csp",
                    title="Content Security Policy is not set",
                    category=self.category,
                    severity=Severity.MEDIUM,
                    confidence=9,
                    url=root.url,
                    description="No Content-Security-Policy header was returned. Without a CSP the "
                    "browser will execute any injected script it can parse, which widens the impact "
                    "of cross-site scripting by removing the last client-side mitigation.",
                    impact="An injected script can execute in a victim's session and read or modify "
                    "data the application exposes to the browser.",
                    remediation="Define a Content-Security-Policy starting from a restrictive default-src "
                    "'self' policy, then allow only the specific script, style and connect sources the "
                    "application needs. Add frame-ancestors 'none' to block framing.",
                    references=[
                        "https://owasp.org/www-project-secure-headers/",
                        "https://developer.mozilla.org/docs/Web/HTTP/CSP",
                    ],
                    cwe=["CWE-693"],
                    owasp=["A05:2021 Security Misconfiguration"],
                    request_evidence={"method": "GET", "url": root.url},
                    response_evidence=response_evidence(ctx),
                )
            )

        if is_https and not hsts:
            findings.append(
                Finding(
                    check_id="venom.headers.hsts",
                    title="HSTS is not enforced",
                    category=self.category,
                    severity=Severity.MEDIUM,
                    confidence=9,
                    url=root.url,
                    description="The response is served over HTTPS but does not set "
                    "Strict-Transport-Security. Browsers may still attempt plaintext HTTP on the "
                    "first visit, leaving room for downgrade attacks.",
                    impact="A network attacker can force the first request over HTTP and intercept "
                    "or modify it.",
                    remediation="Send Strict-Transport-Security: max-age=31536000; includeSubDomains "
                    "on every HTTPS response (add preload once you are certain every subdomain "
                    "supports HTTPS).",
                    references=["https://owasp.org/www-project-secure-headers/"],
                    cwe=["CWE-319"],
                    owasp=["A02:2021 Cryptographic Failures"],
                    request_evidence={"method": "GET", "url": root.url},
                    response_evidence=response_evidence(ctx),
                )
            )

        missing = [name for name in _HARDENING_HEADERS if not root.header(name)]
        if missing:
            impact = " ".join(
                f"Without {name}: {_HARDENING_DETAILS[name][0]};"
                for name in missing
            )
            remediation = " ".join(_HARDENING_DETAILS[name][1] for name in missing)
            findings.append(
                Finding(
                    check_id="venom.headers.hardening",
                    title="Missing HTTP hardening headers",
                    category=self.category,
                    severity=Severity.LOW,
                    confidence=9,
                    url=root.url,
                    description="The following defensive headers are absent: "
                    + ", ".join(missing)
                    + ".",
                    impact=impact,
                    remediation=remediation,
                    references=["https://owasp.org/www-project-secure-headers/"],
                    cwe=["CWE-693"],
                    owasp=["A05:2021 Security Misconfiguration"],
                    request_evidence={"method": "GET", "url": root.url},
                    response_evidence=response_evidence(ctx),
                )
            )
        return findings
