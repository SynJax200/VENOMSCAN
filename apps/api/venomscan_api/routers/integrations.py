from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session
from venomscan_engine.integrations import BurpImportError, export_burp_xml, import_burp
from venomscan_engine.models import Finding as EngineFinding
from venomscan_engine.models import Severity, VerificationStatus
from venomscan_engine.safety.scope import Scope
from venomscan_engine.verify.dedupe import dedupe_findings

from venomscan_api.config import Settings, get_settings
from venomscan_api.db import get_db
from venomscan_api.deps import client_ip, get_current_user, require_csrf
from venomscan_api.models import Endpoint, Finding, Scan, Target, User
from venomscan_api.schemas import BurpImportOut, IntegrationStatusOut, NucleiStatusOut
from venomscan_api.services import audit

router = APIRouter(prefix="/api", tags=["integrations"])

_MAX_BURP_BYTES = 5_000_000


def _owned_target(db: Session, target_id: str, user: User) -> Target:
    target = db.get(Target, target_id)
    if target is None or target.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@router.get("/integrations", response_model=IntegrationStatusOut)
def integration_status(
    settings: Settings = Depends(get_settings),
    user: User = Depends(get_current_user),
) -> IntegrationStatusOut:
    binary = Path(settings.nuclei_binary) if settings.nuclei_binary else None
    templates = Path(settings.nuclei_templates) if settings.nuclei_templates else None
    plugin_dirs = [item for item in settings.plugin_dirs.split(",") if item.strip()]
    return IntegrationStatusOut(
        nuclei=NucleiStatusOut(
            enabled=settings.nuclei_enabled,
            configured=bool(settings.nuclei_binary),
            binary_present=bool(binary and binary.is_absolute() and binary.is_file()),
            templates_present=bool(
                templates is None or (templates.is_absolute() and templates.is_dir())
            ),
            severities=[
                item.strip() for item in settings.nuclei_severities.split(",") if item.strip()
            ],
            rate_limit=settings.nuclei_rate_limit,
            timeout=settings.nuclei_timeout,
        ),
        burp_import=True,
        burp_export=True,
        upstream_proxy=bool(settings.upstream_proxy_url),
        plugin_dirs=[item.strip() for item in plugin_dirs],
    )


@router.post(
    "/targets/{target_id}/integrations/burp/import",
    response_model=BurpImportOut,
    status_code=201,
    dependencies=[Depends(require_csrf)],
)
async def burp_import(
    target_id: str,
    request: Request,
    format: str = "xml",
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> BurpImportOut:
    target = _owned_target(db, target_id, user)
    body = await request.body()
    if len(body) > _MAX_BURP_BYTES:
        raise HTTPException(status_code=413, detail="Import file exceeds the 5 MB limit")
    scope = Scope.from_target(target.url)
    try:
        imported = import_burp(body, fmt=format, scope=scope)
    except BurpImportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    findings = dedupe_findings(imported.findings)
    scan = Scan(
        target_id=target.id,
        profile="import",
        status="completed",
        phase="reporting",
        progress=100,
        summary=(
            f"Imported {len(findings)} finding(s) from a Burp export. "
            "No traffic was sent to the target."
        ),
        stats={
            "source": "burp",
            "imported": len(findings),
            "skipped": imported.skipped,
            "requests": 0,
        },
    )
    db.add(scan)
    db.flush()
    seen_endpoints: set[str] = set()
    for finding in findings:
        db.add(
            Finding(
                scan_id=scan.id,
                dedup_key=finding.dedup_key,
                check_id=finding.check_id,
                title=finding.title,
                category=finding.category,
                severity=finding.severity.value,
                verification_status=finding.verification_status.value,
                confidence=finding.confidence,
                risk_score=finding.risk_score,
                url=finding.url,
                method=finding.method,
                parameter=finding.parameter,
                payload=finding.payload,
                description=finding.description,
                impact=finding.impact,
                remediation=finding.remediation,
                references=finding.references,
                cwe=finding.cwe,
                owasp=finding.owasp,
                cvss_score=finding.cvss_score,
                cvss_vector=finding.cvss_vector,
                request_evidence=finding.request_evidence,
                response_evidence=finding.response_evidence,
            )
        )
        if finding.url not in seen_endpoints:
            seen_endpoints.add(finding.url)
            db.add(
                Endpoint(
                    scan_id=scan.id,
                    url=finding.url,
                    method=finding.method,
                    source="burp",
                )
            )
    audit.record(
        db,
        "burp.import",
        actor=user,
        target_type="scan",
        target_id=scan.id,
        detail={
            "target": target.url,
            "imported": len(findings),
            "skipped": imported.skipped,
            "format": format,
        },
        ip=client_ip(request),
    )
    db.commit()
    return BurpImportOut(
        scan_id=scan.id,
        imported=len(findings),
        skipped=imported.skipped,
        out_of_scope=len(imported.out_of_scope),
    )


@router.get("/scans/{scan_id}/integrations/burp/export")
def burp_export(
    scan_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    scan = db.get(Scan, scan_id)
    if scan is None or scan.target is None or scan.target.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = [
        EngineFinding(
            check_id=finding.check_id,
            title=finding.title,
            category=finding.category,
            severity=Severity(finding.severity),
            confidence=finding.confidence,
            verification_status=VerificationStatus(finding.verification_status),
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
            dedup_key=finding.dedup_key,
            risk_score=finding.risk_score,
        )
        for finding in sorted(scan.findings, key=lambda item: -item.risk_score)
    ]
    audit.record(
        db,
        "burp.export",
        actor=user,
        target_type="scan",
        target_id=scan.id,
        detail={"findings": len(findings)},
        ip=client_ip(request),
    )
    db.commit()
    return Response(
        content=export_burp_xml(findings),
        media_type="application/xml",
        headers={
            "Content-Disposition": f'attachment; filename="venomscan-{scan.id[:8]}-burp.xml"'
        },
    )
