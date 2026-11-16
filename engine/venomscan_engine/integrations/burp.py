from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlsplit
from xml.etree import ElementTree

from venomscan_engine.models import Finding, Severity, VerificationStatus
from venomscan_engine.safety.scope import Scope, ScopeViolation

_MAX_IMPORT_BYTES = 5_000_000
_SEVERITIES = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "information": Severity.INFO,
    "info": Severity.INFO,
}
_CONFIDENCE = {"certain": 9, "firm": 7, "tentative": 5}


class BurpImportError(ValueError):
    pass


@dataclass
class ImportedFindings:
    findings: list[Finding] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    skipped: int = 0


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")[:40] or "issue"


def _severity(raw: str) -> Severity:
    return _SEVERITIES.get((raw or "").strip().lower(), Severity.INFO)


def _confidence(raw: str) -> int:
    return _CONFIDENCE.get((raw or "").strip().lower(), 6)


def _own_url(url: str, host: str, path: str) -> str:
    if url.startswith(("http://", "https://")):
        return url
    if host:
        return f"https://{host}{path or '/'}"
    return ""


def _text(element: ElementTree.Element, tag: str) -> str:
    node = element.find(tag)
    return (node.text or "").strip() if node is not None else ""


def _finding(item: dict, scope: Scope) -> Finding | None:
    title = (item.get("name") or item.get("title") or "").strip()
    url = (item.get("url") or "").strip()
    if not title or not url:
        return None
    try:
        scope.check(url)
    except ScopeViolation:
        return None
    hosts = urlsplit(url)
    references = item.get("references") or []
    if isinstance(references, str):
        references = [line.strip() for line in references.splitlines() if line.strip()]
    finding = Finding(
        check_id=f"burp.import.{_slug(title)}",
        title=title[:300],
        category="burp-import",
        severity=_severity(str(item.get("severity") or "info")),
        confidence=_confidence(str(item.get("confidence") or "")),
        verification_status=VerificationStatus.SUSPECTED,
        url=url,
        method="GET",
        description=(item.get("detail") or item.get("description") or "Imported from Burp.")[:8000],
        impact=(item.get("background") or "Imported issue; review the Burp evidence.")[:8000],
        remediation=(
            item.get("remediation") or "Follow the Burp issue guidance and re-test."
        )[:8000],
        references=[str(ref) for ref in references][:15],
        request_evidence={"source": "burp", "host": hosts.hostname or ""},
        response_evidence={"url": url},
    )
    return finding.finalize()


def _items_from_xml(data: bytes) -> list[dict]:
    try:
        root = ElementTree.fromstring(data)
    except ElementTree.ParseError as exc:
        raise BurpImportError(f"Burp XML could not be parsed: {exc}") from exc
    items: list[dict] = []
    for issue in root.iter("issue"):
        host = _text(issue, "host")
        path = _text(issue, "path")
        items.append(
            {
                "name": _text(issue, "name"),
                "severity": _text(issue, "severity"),
                "confidence": _text(issue, "confidence"),
                "url": _own_url(_text(issue, "location"), host, path),
                "detail": _text(issue, "issueDetail"),
                "background": _text(issue, "issueBackground"),
                "remediation": _text(issue, "remediationDetail")
                or _text(issue, "remediationBackground"),
                "references": _text(issue, "references"),
            }
        )
    return items


def _items_from_json(data: bytes) -> list[dict]:
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BurpImportError(f"Burp JSON could not be parsed: {exc}") from exc
    if isinstance(payload, dict):
        payload = payload.get("issues") or payload.get("items") or []
    if not isinstance(payload, list):
        raise BurpImportError("Burp JSON must be a list of issues or an {issues: [...]} object")
    return [item for item in payload if isinstance(item, dict)]


def import_burp(data: bytes, *, fmt: str, scope: Scope) -> ImportedFindings:
    """Import Burp issues, rejecting anything outside the authorized scope."""
    if len(data) > _MAX_IMPORT_BYTES:
        raise BurpImportError("import file exceeds the 5 MB limit")
    if fmt == "xml":
        items = _items_from_xml(data)
    elif fmt == "json":
        items = _items_from_json(data)
    else:
        raise BurpImportError("format must be 'xml' or 'json'")

    result = ImportedFindings()
    for item in items:
        url = (item.get("url") or "").strip()
        if not (item.get("name") or item.get("title")) or not url:
            result.skipped += 1
            continue
        try:
            scope.check(url)
        except ScopeViolation:
            result.out_of_scope.append(url)
            continue
        finding = _finding(item, scope)
        if finding is not None:
            result.findings.append(finding)
    if result.out_of_scope:
        hosts = sorted({urlsplit(url).hostname or "?" for url in result.out_of_scope})
        raise BurpImportError(
            f"{len(result.out_of_scope)} imported URL(s) are outside the authorized scope "
            f"({', '.join(hosts[:5])}); nothing was imported"
        )
    return result


def export_burp_xml(findings: list[Finding]) -> bytes:
    root = ElementTree.Element(
        "issues",
        {
            "burpVersion": "VENOMSCAN-export",
            "exportTime": datetime.now(UTC).strftime("%a %b %d %H:%M:%S UTC %Y"),
        },
    )
    for finding in findings:
        parts = urlsplit(finding.url)
        issue = ElementTree.SubElement(root, "issue")
        ElementTree.SubElement(issue, "type").text = "0"
        ElementTree.SubElement(issue, "name").text = finding.title
        ElementTree.SubElement(issue, "host", {"ip": ""}).text = parts.hostname or ""
        ElementTree.SubElement(issue, "path").text = parts.path or "/"
        ElementTree.SubElement(issue, "location").text = finding.url
        ElementTree.SubElement(issue, "severity").text = finding.severity.value.capitalize()
        ElementTree.SubElement(issue, "confidence").text = (
            "Certain" if finding.verification_status == VerificationStatus.VERIFIED else "Firm"
        )
        ElementTree.SubElement(issue, "issueBackground").text = finding.impact
        ElementTree.SubElement(issue, "remediationBackground").text = finding.remediation
        ElementTree.SubElement(issue, "issueDetail").text = finding.description
        ElementTree.SubElement(issue, "remediationDetail").text = finding.remediation
        ElementTree.SubElement(issue, "references").text = "\n".join(finding.references)
    return ElementTree.tostring(root, encoding="utf-8", xml_declaration=True)
