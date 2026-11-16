from __future__ import annotations

from venomscan_engine.models import endpoint_state

from venomscan_api.db import as_utc, utcnow
from venomscan_api.models import Finding, Scan, Target
from venomscan_api.schemas import (
    AttestIn,
    EndpointOut,
    FindingOut,
    ScanOut,
    TargetOut,
    TechnologyOut,
    VerificationOut,
)
from venomscan_api.services import verification


def authorization_state(target: Target) -> tuple[bool, object | None]:
    auth = target.latest_authorization
    if auth is None or auth.verified_at is None:
        return False, auth
    expires_at = as_utc(auth.expires_at)
    return bool(expires_at and expires_at > utcnow()), auth


def verification_out(target: Target) -> VerificationOut:
    verified, auth = authorization_state(target)
    token = auth.token if auth else ""
    return VerificationOut(
        verified=verified,
        method=auth.method if verified and auth else None,
        verified_at=auth.verified_at if verified and auth else None,
        expires_at=auth.expires_at if verified and auth else None,
        token=token,
        dns_record_name=verification.dns_record_name(target.host),
        dns_record_value=token,
        well_known_url=verification.well_known_url(target.url),
        attestation_required_text=verification.ATTESTATION_TEXT,
    )


def target_out(target: Target, scan_count: int | None = None) -> TargetOut:
    return TargetOut(
        id=target.id,
        name=target.name,
        url=target.url,
        host=target.host,
        scope_notes=target.scope_notes,
        scan_count=len(target.scans) if scan_count is None else scan_count,
        created_at=target.created_at,
        verification=verification_out(target),
    )


def finding_out(finding: Finding, occurrences: int = 1) -> FindingOut:
    return FindingOut(
        id=finding.id,
        scan_id=finding.scan_id,
        check_id=finding.check_id,
        title=finding.title,
        category=finding.category,
        severity=finding.severity,
        verification_status=finding.verification_status,
        confidence=finding.confidence,
        risk_score=finding.risk_score,
        url=finding.url,
        method=finding.method,
        parameter=finding.parameter,
        payload=finding.payload,
        description=finding.description,
        impact=finding.impact,
        remediation=finding.remediation,
        references=finding.references or [],
        cwe=finding.cwe or [],
        owasp=finding.owasp or [],
        cvss_score=finding.cvss_score,
        cvss_vector=finding.cvss_vector,
        request_evidence=finding.request_evidence or {},
        response_evidence=finding.response_evidence or {},
        ai_summary=finding.ai_summary,
        ai_priority=finding.ai_priority,
        ai_false_positive_likelihood=finding.ai_false_positive_likelihood,
        occurrences=occurrences,
        created_at=finding.created_at,
    )


def scan_out(scan: Scan, findings_total: int | None = None) -> ScanOut:
    return ScanOut(
        id=scan.id,
        target_id=scan.target_id,
        target_name=scan.target.name if scan.target else "",
        target_url=scan.target.url if scan.target else "",
        profile=scan.profile,
        status=scan.status,
        phase=scan.phase,
        progress=scan.progress,
        stats=scan.stats or {},
        recon=scan.recon or {},
        summary=scan.summary,
        error=scan.error,
        findings_total=len(scan.findings) if findings_total is None else findings_total,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        created_at=scan.created_at,
    )


def technology_out(
    name: str, version: str | None, category: str, confidence: float
) -> TechnologyOut:
    return TechnologyOut(name=name, version=version, category=category, confidence=confidence)


def endpoint_out(
    url: str,
    method: str,
    source: str,
    status_code: int | None,
    content_type: str | None,
    depth: int = 0,
    parameters: list[str] | None = None,
) -> EndpointOut:
    return EndpointOut(
        url=url,
        method=method,
        source=source,
        status_code=status_code,
        content_type=content_type,
        depth=depth,
        parameters=parameters or [],
        state=endpoint_state(source, status_code),
    )


__all__ = [
    "AttestIn",
    "authorization_state",
    "endpoint_out",
    "finding_out",
    "scan_out",
    "target_out",
    "technology_out",
    "verification_out",
]
