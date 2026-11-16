from __future__ import annotations

import re

from venomscan_engine.checks.base import response_evidence
from venomscan_engine.checks.registry import register
from venomscan_engine.context import ScanContext
from venomscan_engine.models import Finding, Severity


@register
class ServerExposureCheck:
    id = "venom.info.server"
    name = "Server information exposure"
    category = "disclosure"
    default_severity = Severity.LOW
    profile = "passive"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        root = ctx.root
        if root is None:
            return []
        findings: list[Finding] = []

        if root.url.startswith("http://"):
            findings.append(
                Finding(
                    check_id="venom.transport.plaintext",
                    title="Site is served over plaintext HTTP",
                    category="transport",
                    severity=Severity.HIGH,
                    confidence=10,
                    url=root.url,
                    description="The target responded over HTTP without TLS. All request and response "
                    "content, including cookies and credentials, travels in cleartext.",
                    impact="Credentials and session tokens can be read or modified by anyone on the "
                    "network path.",
                    remediation="Serve all traffic over HTTPS and redirect HTTP to HTTPS with HSTS.",
                    references=["https://owasp.org/www-project-transport-layer-protection/"],
                    cwe=["CWE-319"],
                    owasp=["A02:2021 Cryptographic Failures"],
                    request_evidence={"method": "GET", "url": root.url},
                    response_evidence=response_evidence(ctx),
                )
            )

        disclosed: list[str] = []
        server = root.header("server")
        if server and re.search(r"/\d", server):
            disclosed.append(f"Server: {server}")
        powered = root.header("x-powered-by")
        if powered:
            disclosed.append(f"X-Powered-By: {powered}")
        aspnet = root.header("x-aspnet-version")
        if aspnet:
            disclosed.append(f"X-AspNet-Version: {aspnet}")

        if disclosed:
            findings.append(
                Finding(
                    check_id="venom.info.version",
                    title="Server and framework versions are disclosed",
                    category=self.category,
                    severity=Severity.LOW,
                    confidence=10,
                    url=root.url,
                    description="Response headers reveal exact product versions: "
                    + "; ".join(disclosed)
                    + ". Attackers use version fingerprints to shortlist known CVEs.",
                    impact="Faster, more targeted exploitation of known vulnerabilities in the "
                    "disclosed components.",
                    remediation="Suppress version tokens (nginx server_tokens off, remove X-Powered-By "
                    "and X-AspNet-Version) and keep components patched.",
                    references=[
                        "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration"
                    ],
                    cwe=["CWE-200"],
                    owasp=["A05:2021 Security Misconfiguration"],
                    request_evidence={"method": "GET", "url": root.url},
                    response_evidence=response_evidence(ctx),
                )
            )
        return findings
