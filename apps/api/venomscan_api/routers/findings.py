from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from venomscan_api.db import get_db
from venomscan_api.deps import get_current_user
from venomscan_api.models import Finding, Scan, Target, User
from venomscan_api.schemas import FindingOut
from venomscan_api.services.serializers import finding_out

router = APIRouter(prefix="/api/findings", tags=["findings"])


def merge_findings(rows: list[Finding]) -> list[tuple[Finding, int]]:
    """Collapse repeat hits across scans, keeping the newest instance per dedup key.

    `rows` must be ordered newest first; the count records how many scans observed
    the same evidence so the UI can show persistence without duplicating entries.
    """
    merged: dict[str, list] = {}
    for row in rows:
        key = row.dedup_key or f"{row.check_id}|{row.url}|{row.parameter or ''}"
        entry = merged.get(key)
        if entry is None:
            merged[key] = [row, 1]
        else:
            entry[1] += 1
    return [(finding, count) for finding, count in merged.values()]


def _owned(db: Session, finding_id: str, user: User) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None or finding.scan is None or finding.scan.target is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    if finding.scan.target.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.get("", response_model=list[FindingOut])
def list_findings(
    severity: str | None = Query(default=None),
    scan_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[FindingOut]:
    query = (
        select(Finding)
        .join(Scan, Scan.id == Finding.scan_id)
        .join(Target, Target.id == Scan.target_id)
        .where(Target.owner_id == user.id)
    )
    if severity:
        query = query.where(Finding.severity == severity)
    if scan_id:
        query = query.where(Finding.scan_id == scan_id)
    rows = db.scalars(
        query.order_by(Finding.created_at.desc(), Finding.risk_score.desc()).limit(limit * 4)
    ).all()
    merged = merge_findings(list(rows))
    merged.sort(key=lambda item: (-item[0].risk_score, item[0].check_id, item[0].url))
    return [
        finding_out(finding, occurrences) for finding, occurrences in merged[:limit]
    ]


@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(
    finding_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> FindingOut:
    return finding_out(_owned(db, finding_id, user))
