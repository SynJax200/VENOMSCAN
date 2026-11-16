from __future__ import annotations

import re

from venomscan_engine.checks.registry import register
from venomscan_engine.context import ScanContext
from venomscan_engine.models import Finding, Severity

_ERROR_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Python traceback", re.compile(r"Traceback \(most recent call last\):")),
    ("PHP fatal error", re.compile(r"(?is)Fatal error:.{0,180}?on line \d+")),
    (
        "SQL error",
        re.compile(
            r"(?i)(You have an error in your SQL syntax|SQL syntax.{0,40}MySQL|"
            r"Microsoft OLE DB Provider for SQL Server|ORA-\d{5})"
        ),
    ),
    ("Java stack trace", re.compile(r"\bjava\.lang\.[A-Za-z0-9_.]+Exception")),
    ("ASP.NET error page", re.compile(r"(?i)Server Error in '/' Application")),
    ("Framework stack trace", re.compile(r"(?s)Stack trace:.{0,400}?at System\.[A-Za-z]")),
)

_DIRECTORY_TITLES = re.compile(
    r"(?i)<title>\s*(Index of /|Directory listing for )", re.MULTILINE
)


def _pages(ctx: ScanContext) -> list[dict]:
    pages = ctx.artifacts.get("pages") or []
    return [page for page in pages if isinstance(page, dict)] if isinstance(pages, list) else []


@register
class VerboseErrorsCheck:
    id = "venom.info.errors"
    name = "Verbose error pages"
    category = "disclosure"
    default_severity = Severity.MEDIUM
    profile = "safe"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for page in _pages(ctx):
            body = page.get("body") or ""
            if not body:
                continue
            for label, pattern in _ERROR_SIGNATURES:
                if not pattern.search(body):
                    continue
                findings.append(
                    Finding(
                        check_id=self.id,
                        title=f"Verbose {label} exposed",
                        category=self.category,
                        severity=Severity.MEDIUM,
                        confidence=8,
                        url=page.get("url") or ctx.target_url,
                        parameter=label,
                        description=f"The response body contains a {label} signature. Framework and "
                        "database internals are visible instead of a generic error message.",
                        impact="Attackers learn file paths, library versions and sometimes query "
                        "fragments, which speeds up targeted exploitation.",
                        remediation="Serve generic error pages in production, log the details "
                        "server-side only, and disable framework debug modes.",
                        references=[
                            "https://owasp.org/www-community/Improper_Error_Handling",
                            "https://cwe.mitre.org/data/definitions/209.html",
                        ],
                        cwe=["CWE-209"],
                        owasp=["A05:2021 Security Misconfiguration"],
                        request_evidence={"method": "GET", "url": page.get("url") or ctx.target_url},
                        response_evidence={
                            "url": page.get("url"),
                            "status_code": page.get("status_code"),
                            "signature": label,
                            "body": "«redacted: server internals»",
                        },
                    )
                )
                break
        return findings


@register
class DirectoryListingCheck:
    id = "venom.info.dirlist"
    name = "Directory listing"
    category = "disclosure"
    default_severity = Severity.MEDIUM
    profile = "safe"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for page in _pages(ctx):
            if page.get("status_code") != 200:
                continue
            body = page.get("body") or ""
            match = _DIRECTORY_TITLES.search(body)
            if match is None:
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    title="Directory listing is enabled",
                    category=self.category,
                    severity=Severity.MEDIUM,
                    confidence=9,
                    url=page.get("url") or ctx.target_url,
                    description="The server returned a generated directory index ("
                    + match.group(0).strip()
                    + "). Every file in the folder is enumerable and browsable.",
                    impact="Backups, uploads and source files that were never linked become "
                    "discoverable.",
                    remediation="Disable autoindex/Options -Indexes and return 403 or 404 for "
                    "directories without an application route.",
                    references=[
                        "https://owasp.org/www-community/attacks/Directory_traversal",
                        "https://cwe.mitre.org/data/definitions/548.html",
                    ],
                    cwe=["CWE-548"],
                    owasp=["A05:2021 Security Misconfiguration"],
                    request_evidence={"method": "GET", "url": page.get("url") or ctx.target_url},
                    response_evidence={
                        "url": page.get("url"),
                        "status_code": page.get("status_code"),
                        "signature": match.group(1),
                    },
                )
            )
        return findings
