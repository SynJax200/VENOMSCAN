from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from venomscan_api.db import get_db
from venomscan_api.deps import client_ip, get_current_user, require_csrf
from venomscan_api.models import AiAnalysis, Finding, Scan, User
from venomscan_api.schemas import AiAnalysisOut, AssistantIn, AssistantOut
from venomscan_api.services import ai_service, audit

router = APIRouter(prefix="/api", tags=["ai"])

FindingKind = Literal["explanation", "fp_review", "remediation"]
ScanKind = Literal[
    "summary",
    "prioritize",
    "surface_summary",
    "correlate",
    "endpoint_prioritize",
    "next_steps",
    "js_analysis",
    "api_analysis",
    "fp_triage",
]


def _analysis_out(row: AiAnalysis) -> AiAnalysisOut:
    return AiAnalysisOut(
        id=row.id,
        kind=row.kind,
        provider=row.provider,
        model=row.model,
        prompt_version=row.prompt_version,
        grounded=row.grounded,
        fallback=row.fallback,
        payload=row.payload or {},
        created_at=row.created_at,
    )


def _owned_finding(db: Session, finding_id: str, user: User) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None or finding.scan is None or finding.scan.target is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    if finding.scan.target.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


def _owned_scan(db: Session, scan_id: str, user: User) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None or scan.target is None or scan.target.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post(
    "/findings/{finding_id}/ai/{kind}",
    response_model=AiAnalysisOut,
    dependencies=[Depends(require_csrf)],
)
async def analyze_finding(
    finding_id: str,
    kind: FindingKind,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> AiAnalysisOut:
    finding = _owned_finding(db, finding_id, user)
    row = await ai_service.run_finding(db, finding, kind)
    audit.record(
        db,
        "ai.analysis",
        actor=user,
        target_type="finding",
        target_id=finding.id,
        detail={"kind": kind, "provider": row.provider, "fallback": row.fallback},
        ip=client_ip(request),
    )
    db.commit()
    return _analysis_out(row)


@router.get("/findings/{finding_id}/ai", response_model=list[AiAnalysisOut])
def list_finding_analyses(
    finding_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[AiAnalysisOut]:
    finding = _owned_finding(db, finding_id, user)
    rows = db.scalars(
        select(AiAnalysis)
        .where(AiAnalysis.finding_id == finding.id)
        .order_by(AiAnalysis.created_at.desc())
        .limit(20)
    ).all()
    return [_analysis_out(row) for row in rows]


@router.post(
    "/scans/{scan_id}/ai/{kind}",
    response_model=AiAnalysisOut,
    dependencies=[Depends(require_csrf)],
)
async def analyze_scan(
    scan_id: str,
    kind: ScanKind,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> AiAnalysisOut:
    scan = _owned_scan(db, scan_id, user)
    if kind == "fp_triage":
        row = await ai_service.triage_scan(db, scan)
        if row is None:
            raise HTTPException(status_code=400, detail="Scan has no findings to triage")
    else:
        row = await ai_service.run_scan(db, scan, kind)
    audit.record(
        db,
        "ai.analysis",
        actor=user,
        target_type="scan",
        target_id=scan.id,
        detail={"kind": kind, "provider": row.provider, "fallback": row.fallback},
        ip=client_ip(request),
    )
    db.commit()
    return _analysis_out(row)


@router.get("/scans/{scan_id}/ai", response_model=list[AiAnalysisOut])
def list_scan_analyses(
    scan_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[AiAnalysisOut]:
    scan = _owned_scan(db, scan_id, user)
    rows = db.scalars(
        select(AiAnalysis)
        .where(AiAnalysis.scan_id == scan.id, AiAnalysis.finding_id.is_(None))
        .order_by(AiAnalysis.created_at.desc())
        .limit(30)
    ).all()
    return [_analysis_out(row) for row in rows]


@router.post(
    "/checks/{check_id}/ai/education",
    response_model=AiAnalysisOut,
    dependencies=[Depends(require_csrf)],
)
async def explain_check(
    check_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> AiAnalysisOut:
    from venomscan_engine.checks import check_catalog

    entry = next((item for item in check_catalog() if item["id"] == check_id), None)
    if entry is None:
        raise HTTPException(status_code=404, detail="Check not found")
    row = await ai_service.run_check_education(db, entry)
    audit.record(
        db,
        "ai.analysis",
        actor=user,
        target_type="check",
        target_id=check_id,
        detail={"kind": "education", "provider": row.provider, "fallback": row.fallback},
        ip=client_ip(request),
    )
    db.commit()
    return _analysis_out(row)


@router.post("/assistant", response_model=AssistantOut, dependencies=[Depends(require_csrf)])
async def ask_assistant(
    payload: AssistantIn,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> AssistantOut:
    scan = _owned_scan(db, payload.scan_id, user)
    row = await ai_service.ask(db, scan, payload.question)
    audit.record(
        db,
        "ai.assistant",
        actor=user,
        target_type="scan",
        target_id=scan.id,
        detail={"fallback": row.fallback, "refused": bool(row.payload.get("refused"))},
        ip=client_ip(request),
    )
    db.commit()
    data = row.payload or {}
    return AssistantOut(
        answer=str(data.get("answer", "")),
        grounded=row.grounded,
        fallback=row.fallback,
        provider=row.provider,
        model=row.model,
        prompt_version=row.prompt_version,
        refused=bool(data.get("refused")),
        references=list(data.get("evidence_refs") or []),
    )
