from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit

from venomscan_engine.checks.registry import register
from venomscan_engine.context import ScanContext
from venomscan_engine.models import Finding, Severity
from venomscan_engine.safety.http import TargetUnreachable, TooManyRedirects

CANARY_HOST = "venomscan-canary.invalid"
CANARY_URL = f"https://{CANARY_HOST}/venomscan-open-redirect"
MAX_ENDPOINTS = 3

_REDIRECT_PARAM = re.compile(
    r"(?i)(url|uri|next|redirect|return|continue|dest|destination|target|callback|goto|to|link)"
)


@register
class OpenRedirectCheck:
    id = "venom.redirect.open"
    name = "Open redirect canary"
    category = "redirect"
    default_severity = Severity.MEDIUM
    profile = "safe"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        root = ctx.root
        if root is None or ctx.client is None:
            return []

        findings: list[Finding] = []
        for endpoint in ctx.endpoints:
            if len(findings) >= MAX_ENDPOINTS or ctx.remaining_seconds < 3:
                break
            if endpoint.method != "GET" or endpoint.state != "live":
                continue
            parts = urlsplit(endpoint.url)
            if parts.hostname not in ctx.scope.hosts:
                continue
            query = parse_qsl(parts.query, keep_blank_values=True)
            if not query:
                continue
            preferred = [name for name, _ in query if _REDIRECT_PARAM.search(name)]
            parameter = preferred[0] if preferred else query[0][0]
            pairs = [(name, CANARY_URL if name == parameter else value) for name, value in query]
            probe_url = parts._replace(query=urlencode(pairs, doseq=True)).geturl()
            try:
                response = await ctx.client.request(
                    "GET", probe_url, follow_redirects=False
                )
            except (TargetUnreachable, TooManyRedirects):
                continue
            if response.status_code not in {301, 302, 303, 307, 308}:
                continue
            location = response.header("location") or ""
            if not location:
                continue
            if location.startswith("/") and not location.startswith("//"):
                continue
            target = urljoin(endpoint.url, location)
            target_host = urlsplit(target).hostname
            if target_host and target_host in ctx.scope.hosts:
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    title=f"Open redirect via parameter '{parameter}'",
                    category=self.category,
                    severity=Severity.MEDIUM,
                    confidence=10,
                    url=endpoint.url,
                    parameter=parameter,
                    payload=CANARY_URL,
                    description=f"Requesting {parts.path or '/'} with {parameter} set to an external "
                    f"canary returned HTTP {response.status_code} and Location: {location}. The "
                    "server accepted an off-scope redirect target. The canary was never followed.",
                    impact="Attackers can build links on the trusted domain that bounce victims to "
                    "a phishing or malware page.",
                    remediation="Allow only relative paths or an explicit allowlist of hosts. "
                    "Resolve and validate the target after decoding before issuing the redirect.",
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                        "https://cwe.mitre.org/data/definitions/601.html",
                    ],
                    cwe=["CWE-601"],
                    owasp=["A01:2021 Broken Access Control"],
                    request_evidence={"method": "GET", "url": probe_url},
                    response_evidence={
                        "status_code": response.status_code,
                        "location": location,
                        "canary": CANARY_HOST,
                    },
                )
            )
        return findings
