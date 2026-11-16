from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload
from venomscan_engine.intel import IntelReport, lookup

from venomscan_api.db import get_db, session_factory, utcnow
from venomscan_api.deps import client_ip, get_current_user, require_csrf
from venomscan_api.models import Finding, Scan, Target, User
from venomscan_api.models import ScanEvent as ScanEventRow
from venomscan_api.schemas import (
    CompareFinding,
    FindingOut,
    ScanCompareOut,
    ScanCreate,
    ScanDetailOut,
    ScanEventOut,
    ScanOut,
)
from venomscan_api.services import audit, workspace
from venomscan_api.services.runner import dispatch
from venomscan_api.services.serializers import (
    authorization_state,
    endpoint_out,
    finding_out,
    scan_out,
    technology_out,
)

router = APIRouter(prefix="/api/scans", tags=["scans"])

TERMINAL = {"completed", "failed", "cancelled"}


def _owned_scan(db: Session, scan_id: str, user: User) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None or scan.target is None or scan.target.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


def _detail(scan: Scan) -> ScanDetailOut:
    base = scan_out(scan)
    return ScanDetailOut(
        **base.model_dump(),
        findings=[finding_out(f) for f in sorted(scan.findings, key=lambda f: -f.risk_score)],
        technologies=[
            technology_out(t.name, t.version, t.category, t.confidence) for t in scan.technologies
        ],
        endpoints=[
            endpoint_out(
                e.url,
                e.method,
                e.source,
                e.status_code,
                e.content_type,
                e.depth,
                e.parameters or [],
            )
            for e in scan.endpoints
        ],
    )


@router.get("", response_model=list[ScanOut])
def list_scans(
    limit: int = Query(default=50, ge=1, le=200),
    target_id: str | None = Query(default=None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[ScanOut]:
    query = (
        select(Scan)
        .options(selectinload(Scan.target))
        .join(Target, Target.id == Scan.target_id)
        .where(Target.owner_id == user.id)
        .order_by(Scan.created_at.desc())
        .limit(limit)
    )
    if target_id:
        query = query.where(Scan.target_id == target_id)
    scans = db.scalars(query).all()
    counts = _finding_counts(db, [scan.id for scan in scans])
    return [scan_out(scan, counts.get(scan.id, 0)) for scan in scans]


def _finding_counts(db: Session, scan_ids: list[str]) -> dict[str, int]:
    if not scan_ids:
        return {}
    rows = db.execute(
        select(Finding.scan_id, func.count(Finding.id))
        .where(Finding.scan_id.in_(scan_ids))
        .group_by(Finding.scan_id)
    ).all()
    return {scan_id: int(count) for scan_id, count in rows}


@router.post("", response_model=ScanOut, status_code=201, dependencies=[Depends(require_csrf)])
def create_scan(
    payload: ScanCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> ScanOut:
    target = db.get(Target, payload.target_id)
    if target is None or target.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Target not found")

    verified, auth = authorization_state(target)
    if not verified:
        raise HTTPException(
            status_code=409,
            detail="Target is not verified or its authorization expired. Verify ownership before scanning.",
        )
    profile = payload.profile or workspace.default_profile(db)
    if profile == "active" and not payload.active_consent:
        raise HTTPException(
            status_code=400,
            detail="Active profile requires explicit consent. Re-submit with active_consent=true.",
        )

    scan = Scan(
        target_id=target.id,
        authorization_id=auth.id if auth else None,
        profile=profile,
        status="queued",
        phase="queued",
        options={"active_consent": payload.active_consent},
    )
    db.add(scan)
    db.flush()
    audit.record(
        db,
        "scan.queued",
        actor=user,
        target_type="scan",
        target_id=scan.id,
        detail={"target": target.url, "profile": profile},
        ip=client_ip(request),
    )
    db.commit()
    db.refresh(scan)
    dispatch(scan.id)
    return scan_out(scan)


@router.get("/{scan_id}", response_model=ScanDetailOut)
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> ScanDetailOut:
    return _detail(_owned_scan(db, scan_id, user))


@router.post("/{scan_id}/cancel", response_model=ScanOut, dependencies=[Depends(require_csrf)])
def cancel_scan(
    scan_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> ScanOut:
    scan = _owned_scan(db, scan_id, user)
    if scan.status in TERMINAL:
        raise HTTPException(status_code=409, detail=f"Scan is already {scan.status}")
    scan.status = "cancelled"
    scan.finished_at = utcnow()
    audit.record(
        db,
        "scan.cancelled",
        actor=user,
        target_type="scan",
        target_id=scan.id,
        ip=client_ip(request),
    )
    db.commit()
    db.refresh(scan)
    return scan_out(scan)


@router.get("/{scan_id}/intel", response_model=IntelReport)
def scan_intel(
    scan_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> IntelReport:
    scan = _owned_scan(db, scan_id, user)
    return lookup([(tech.name, tech.version) for tech in scan.technologies])


@router.get("/{scan_id}/compare", response_model=ScanCompareOut)
def compare_scans(
    scan_id: str,
    other: str = Query(min_length=1),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> ScanCompareOut:
    base = _owned_scan(db, scan_id, user)
    if other == scan_id:
        raise HTTPException(status_code=400, detail="Choose two different scans to compare")
    compare = _owned_scan(db, other, user)
    for scan in (base, compare):
        if scan.status != "completed":
            raise HTTPException(
                status_code=409, detail="Only completed scans can be compared"
            )

    def _item(finding) -> CompareFinding:
        return CompareFinding(
            id=finding.id,
            check_id=finding.check_id,
            title=finding.title,
            severity=finding.severity,
            risk_score=finding.risk_score,
            url=finding.url,
            verification_status=finding.verification_status,
        )

    def _sorted(findings) -> list[CompareFinding]:
        return [_item(finding) for finding in sorted(findings, key=lambda f: -f.risk_score)]

    base_map = {finding.dedup_key: finding for finding in base.findings}
    other_map = {finding.dedup_key: finding for finding in compare.findings}
    new = [base_map[key] for key in base_map.keys() - other_map.keys()]
    fixed = [other_map[key] for key in other_map.keys() - base_map.keys()]
    persisting = [base_map[key] for key in base_map.keys() & other_map.keys()]

    def _label(scan: Scan) -> str:
        name = scan.target.name if scan.target else scan.target_id
        stamp = scan.created_at.strftime("%Y-%m-%d %H:%M") if scan.created_at else ""
        return f"{name} · {scan.profile} · {stamp}"

    return ScanCompareOut(
        base_scan_id=base.id,
        other_scan_id=compare.id,
        base_label=_label(base),
        other_label=_label(compare),
        new=_sorted(new),
        fixed=_sorted(fixed),
        persisting=_sorted(persisting),
        counts={
            "new": len(new),
            "fixed": len(fixed),
            "persisting": len(persisting),
        },
    )


@router.get("/{scan_id}/findings", response_model=list[FindingOut])
def scan_findings(
    scan_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[FindingOut]:
    scan = _owned_scan(db, scan_id, user)
    return [finding_out(f) for f in sorted(scan.findings, key=lambda f: -f.risk_score)]


@router.get("/{scan_id}/events", response_model=list[ScanEventOut])
def scan_events(
    scan_id: str,
    after: int = Query(default=0, ge=0),
    limit: int = Query(default=500, ge=1, le=1000),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[ScanEventOut]:
    _owned_scan(db, scan_id, user)
    rows = db.scalars(
        select(ScanEventRow)
        .where(ScanEventRow.scan_id == scan_id, ScanEventRow.id > after)
        .order_by(ScanEventRow.id)
        .limit(limit)
    ).all()
    return [ScanEventOut.model_validate(row, from_attributes=True) for row in rows]


@router.get("/{scan_id}/events/stream")
async def scan_event_stream(
    scan_id: str,
    request: Request,
    after: int = Query(default=0, ge=0),
    user: User = Depends(get_current_user),
) -> StreamingResponse:
    def _authorized() -> bool:
        with session_factory()() as db:
            scan = db.get(Scan, scan_id)
            return bool(scan and scan.target and scan.target.owner_id == user.id)

    if not await asyncio.to_thread(_authorized):
        raise HTTPException(status_code=404, detail="Scan not found")

    async def event_stream():
        cursor = after
        deadline = time.monotonic() + 300
        idle = 0
        # Reconnect hint so EventSource retries automatically after a proxy drop.
        yield "retry: 3000\n\n"
        while time.monotonic() < deadline:
            if await request.is_disconnected():
                break

            def _fetch(cursor_value: int) -> tuple[list[dict], str]:
                with session_factory()() as db:
                    rows = db.scalars(
                        select(ScanEventRow)
                        .where(ScanEventRow.scan_id == scan_id, ScanEventRow.id > cursor_value)
                        .order_by(ScanEventRow.id)
                        .limit(200)
                    ).all()
                    status_row = db.get(Scan, scan_id)
                    return (
                        [
                            ScanEventOut.model_validate(row, from_attributes=True).model_dump(
                                mode="json"
                            )
                            for row in rows
                        ],
                        status_row.status if status_row else "missing",
                    )

            rows, status = await asyncio.to_thread(_fetch, cursor)
            for row in rows:
                cursor = row["id"]
                yield f"id: {cursor}\nevent: scan_event\ndata: {json.dumps(row)}\n\n"

            if status in TERMINAL or status == "missing":
                if not rows:
                    yield f"event: stream_end\ndata: {json.dumps({'status': status})}\n\n"
                    return
            if not rows:
                idle += 1
                if idle % 20 == 0:
                    yield ": keep-alive\n\n"
                await asyncio.sleep(0.7)
            else:
                idle = 0
        yield f"event: stream_end\ndata: {json.dumps({'status': 'timeout', 'at': datetime.now().isoformat()})}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
