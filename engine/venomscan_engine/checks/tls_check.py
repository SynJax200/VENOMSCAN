from __future__ import annotations

from venomscan_engine.checks.registry import register
from venomscan_engine.context import ScanContext
from venomscan_engine.models import Finding, Severity
from venomscan_engine.recon.tls import TLSInfo

_WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}
_WEAK_CIPHERS = ("RC4", "3DES", "DES-CBC", "NULL", "EXPORT")


@register
class TLSCheck:
    id = "venom.tls.weak"
    name = "TLS configuration"
    category = "transport"
    default_severity = Severity.HIGH
    profile = "passive"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        info: TLSInfo | None = ctx.artifacts.get("tls")
        if info is None:
            return []

        url = ctx.target_url
        evidence = {
            "protocol": info.protocol,
            "cipher": info.cipher,
            "issuer": info.issuer,
            "subject": info.subject,
            "not_after": info.not_after,
            "days_to_expiry": info.days_to_expiry,
            "verified": info.verified,
            "error": info.error,
            "sans": info.sans,
        }
        findings: list[Finding] = []
        common = {
            "category": self.category,
            "url": url,
            "confidence": 10,
            "request_evidence": {"method": "GET", "url": url},
            "response_evidence": {"tls": evidence},
        }

        if info.days_to_expiry is not None and info.days_to_expiry < 0:
            findings.append(
                Finding(
                    check_id="venom.tls.expired",
                    title="TLS certificate has expired",
                    severity=Severity.HIGH,
                    description="The certificate presented by the server is past its validity period. "
                    "Browsers will show an interstitial warning and users are trained to click "
                    "through it, which trains exactly the wrong behaviour.",
                    impact="Loss of confidentiality and integrity guarantees; user trust erosion.",
                    remediation="Renew the certificate and automate renewal (ACME) with monitoring on "
                    "expiry windows.",
                    references=["https://owasp.org/www-project-transport-layer-protection/"],
                    cwe=["CWE-298"],
                    owasp=["A02:2021 Cryptographic Failures"],
                    **common,
                )
            )
        elif info.days_to_expiry is not None and info.days_to_expiry < 30:
            findings.append(
                Finding(
                    check_id="venom.tls.expiring",
                    title=f"TLS certificate expires in {info.days_to_expiry} days",
                    severity=Severity.LOW,
                    description="The certificate is valid but close to expiry. Automated renewal may "
                    "be missing or failing.",
                    impact="An outage or browser warning if renewal does not complete in time.",
                    remediation="Verify automated renewal and add expiry alerting at 30/14/7 days.",
                    references=["https://owasp.org/www-project-transport-layer-protection/"],
                    cwe=["CWE-298"],
                    owasp=["A02:2021 Cryptographic Failures"],
                    **common,
                )
            )

        if info.protocol in _WEAK_PROTOCOLS:
            findings.append(
                Finding(
                    check_id="venom.tls.protocol",
                    title=f"Deprecated TLS version negotiated ({info.protocol})",
                    severity=Severity.MEDIUM,
                    description="The server accepted a TLS version older than TLS 1.2, which is "
                    "deprecated and has known weaknesses.",
                    impact="Traffic may be exposed to downgrade and cryptanalytic attacks.",
                    remediation="Disable TLS 1.0/1.1 and require TLS 1.2+ with modern cipher suites.",
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"
                    ],
                    cwe=["CWE-326"],
                    owasp=["A02:2021 Cryptographic Failures"],
                    **common,
                )
            )

        if info.cipher and any(marker in info.cipher.upper() for marker in _WEAK_CIPHERS):
            findings.append(
                Finding(
                    check_id="venom.tls.cipher",
                    title=f"Weak cipher suite negotiated ({info.cipher})",
                    severity=Severity.MEDIUM,
                    description="The negotiated cipher suite is considered weak or export-grade.",
                    impact="Reduced confidentiality of in-transit data.",
                    remediation="Restrict cipher suites to AEAD constructions (AES-GCM, ChaCha20-Poly1305).",
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"
                    ],
                    cwe=["CWE-327"],
                    owasp=["A02:2021 Cryptographic Failures"],
                    **common,
                )
            )

        if (
            not info.verified
            and info.error
            and (info.days_to_expiry is None or info.days_to_expiry >= 0)
        ):
            findings.append(
                Finding(
                    check_id="venom.tls.untrusted",
                    title="TLS certificate is not trusted",
                    severity=Severity.MEDIUM,
                    description="Certificate validation failed: " + info.error[:200],
                    impact="Users cannot distinguish the site from an impersonation attempt.",
                    remediation="Install a certificate issued by a publicly trusted CA matching the "
                    "hostname, and serve the full intermediate chain.",
                    references=["https://owasp.org/www-project-transport-layer-protection/"],
                    cwe=["CWE-295"],
                    owasp=["A02:2021 Cryptographic Failures"],
                    **common,
                )
            )
        return findings
