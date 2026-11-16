from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from venomscan_engine.checks.registry import register
from venomscan_engine.context import ScanContext
from venomscan_engine.models import Finding, Severity
from venomscan_engine.safety.http import TargetUnreachable, TooManyRedirects

# Only signatures strong enough that a hit is unambiguous. Responses that look
# like the application shell (for example SPA catch-all routes) are ignored.
_ENV_KEY = re.compile(
    r"(?m)^(?:export\s+)?[A-Z][A-Z0-9_]*"
    r"(?:SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE|DSN|DATABASE_URL|AWS_|API_KEY)[A-Z0-9_]*\s*="
)


@dataclass(frozen=True)
class _Probe:
    path: str
    label: str
    severity: Severity
    pattern: re.Pattern[str]
    html_ok: bool = False


_PROBES: tuple[_Probe, ...] = (
    _Probe("/.git/HEAD", "Git HEAD ref", Severity.HIGH, re.compile(r"\Aref:\s+refs/")),
    _Probe("/.git/config", "Git repository config", Severity.HIGH, re.compile(r"\[core\]")),
    _Probe("/.env", "Environment file with secrets", Severity.HIGH, _ENV_KEY),
    _Probe(
        "/phpinfo.php",
        "PHP configuration page",
        Severity.MEDIUM,
        re.compile(r"<title>\s*phpinfo\(\)|PHP Version\s*\d"),
        html_ok=True,
    ),
    _Probe(
        "/server-status",
        "Apache server-status page",
        Severity.MEDIUM,
        re.compile(r"Apache Server Status"),
        html_ok=True,
    ),
    _Probe("/.svn/entries", "Subversion metadata", Severity.MEDIUM, re.compile(r"(?m)^\d+\s*$")),
)


@register
class ExposedFilesCheck:
    id = "venom.files.exposed"
    name = "Exposed configuration and metadata files"
    category = "disclosure"
    default_severity = Severity.HIGH
    profile = "safe"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        root = ctx.root
        if root is None or ctx.client is None:
            return []
        parts = urlsplit(root.url)
        origin = f"{parts.scheme}://{parts.netloc}"
        findings: list[Finding] = []

        for probe in _PROBES:
            if ctx.remaining_seconds < 3:
                break
            url = urljoin(origin, probe.path)
            try:
                response = await ctx.client.get(url)
            except (TargetUnreachable, TooManyRedirects):
                continue
            if response.status_code != 200:
                continue
            content_type = (response.header("content-type") or "").lower()
            if "html" in content_type and not probe.html_ok:
                continue
            if response.body.strip() and response.body == root.body:
                continue
            if not probe.pattern.search(response.body):
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    title=f"Exposed file: {probe.path} ({probe.label})",
                    category=self.category,
                    severity=probe.severity,
                    confidence=10,
                    url=response.url,
                    parameter=probe.path,
                    description=f"The server returns {probe.path} with content matching a "
                    f"{probe.label} signature. This file is not application content and should "
                    "never be web-reachable.",
                    impact="Source history, credentials or server configuration can be recovered "
                    "from this path, which often leads directly to deeper compromise.",
                    remediation="Block dotfiles and metadata paths at the web server, remove the "
                    "file from the document root and rotate any credentials it contained.",
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/",
                        "https://cwe.mitre.org/data/definitions/538.html",
                    ],
                    cwe=["CWE-538", "CWE-200"],
                    owasp=["A05:2021 Security Misconfiguration"],
                    request_evidence={"method": "GET", "url": url},
                    response_evidence={
                        "url": response.url,
                        "status_code": response.status_code,
                        "content_type": content_type,
                        "signature": probe.label,
                        "body": "«redacted: potential secrets»",
                    },
                )
            )
        return findings
