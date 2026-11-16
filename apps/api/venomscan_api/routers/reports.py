from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload
from starlette.concurrency import run_in_threadpool
from venomscan_engine.reports import render_html

from venomscan_api.config import Settings, get_settings
from venomscan_api.db import get_db
from venomscan_api.deps import client_ip, get_current_user, require_csrf
from venomscan_api.models import Report, Scan, Target, User
from venomscan_api.schemas import ReportIn, ReportOut
from venomscan_api.services import ai_service, audit
from venomscan_api.services import reports as report_service

router = APIRouter(prefix="/api", tags=["reports"])


def _owned_scan(db: Session, scan_id: str, user: User) -> Scan:
    scan = db.scalars(
        select(Scan)
        .join(Target, Target.id == Scan.target_id)
        .where(Scan.id == scan_id, Target.owner_id == user.id)
        .options(
            selectinload(Scan.findings),
            selectinload(Scan.technologies),
            selectinload(Scan.endpoints),
        )
    ).first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


def _owned_report(db: Session, report_id: str, user: User) -> Report:
    report = db.scalars(
        select(Report)
        .join(Scan, Scan.id == Report.scan_id)
        .join(Target, Target.id == Scan.target_id)
        .where(Report.id == report_id, Target.owner_id == user.id)
    ).first()
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.post(
    "/scans/{scan_id}/reports",
    response_model=ReportOut,
    status_code=201,
    dependencies=[Depends(require_csrf)],
)
async def create_report(
    scan_id: str,
    payload: ReportIn,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
) -> ReportOut:
    scan = _owned_scan(db, scan_id, user)
    if scan.status != "completed":
        raise HTTPException(
            status_code=409, detail="Reports can only be generated for completed scans"
        )
    auto_rows = await ai_service.ensure_report_analyses(db, scan)
    for row in auto_rows:
        audit.record(
            db,
            "ai.analysis",
            actor=user,
            target_type="scan" if row.scan_id else "finding",
            target_id=row.scan_id or row.finding_id or "",
            detail={
                "kind": row.kind,
                "provider": row.provider,
                "fallback": row.fallback,
                "automatic": "report",
            },
            ip=client_ip(request),
        )
    try:
        report = await run_in_threadpool(
            report_service.generate, db, scan, user, payload.format, settings
        )
    except report_service.ReportRenderError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    audit.record(
        db,
        "report.created",
        actor=user,
        target_type="report",
        target_id=report.id,
        detail={
            "scan_id": scan.id,
            "format": payload.format,
            "sha256": report.sha256,
            "size": report.size,
        },
        ip=client_ip(request),
    )
    db.commit()
    db.refresh(report)
    return report_service.report_out(report, settings)


@router.get("/reports", response_model=list[ReportOut])
def list_reports(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
) -> list[ReportOut]:
    rows = db.scalars(
        select(Report)
        .join(Scan, Scan.id == Report.scan_id)
        .join(Target, Target.id == Scan.target_id)
        .where(Target.owner_id == user.id)
        .order_by(Report.created_at.desc())
        .limit(100)
    ).all()
    return [report_service.report_out(row, settings) for row in rows]


@router.get("/reports/{report_id}", response_model=ReportOut)
def get_report(
    report_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
) -> ReportOut:
    return report_service.report_out(_owned_report(db, report_id, user), settings)


@router.get("/reports/{report_id}/preview", response_class=HTMLResponse)
def preview_report(
    report_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> HTMLResponse:
    report = _owned_report(db, report_id, user)
    model = report_service.restore_model(report)
    return HTMLResponse(
        render_html(model, report.sha256),
        headers={
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:",
            "X-Frame-Options": "SAMEORIGIN",
        },
    )


def _download(report: Report, fmt: str) -> Response:
    return Response(
        content=report.content,
        media_type=report_service.media_for(fmt),
        headers={
            "Content-Disposition": f'attachment; filename="{report.filename}"',
            "X-Content-SHA256": report.sha256,
            "Cache-Control": "private, no-store",
        },
    )


@router.get("/reports/{report_id}/download")
def download_report(
    report_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    report = _owned_report(db, report_id, user)
    audit.record(
        db,
        "report.downloaded",
        actor=user,
        target_type="report",
        target_id=report.id,
        detail={"format": report.format, "sha256": report.sha256},
        ip=client_ip(request),
    )
    db.commit()
    return _download(report, report.format)


@router.get("/reports/{report_id}/signed/{token}")
def download_signed(
    report_id: str,
    token: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Response:
    if report_service.verify_token(token, settings.secret_key) != report_id:
        raise HTTPException(status_code=403, detail="Signed link is invalid or has expired")
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return _download(report, report.format)
