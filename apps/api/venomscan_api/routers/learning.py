from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from venomscan_api.db import get_db
from venomscan_api.deps import client_ip, get_current_user, require_csrf
from venomscan_api.models import User
from venomscan_api.schemas import (
    LearningPathsOut,
    LearningProgressIn,
    LearningProgressOut,
    PracticeExerciseOut,
    PracticeFindingOut,
    ScanEndpointLearningOut,
    WalkthroughOut,
)
from venomscan_api.services import audit, learning
from venomscan_api.services.finding_integrity import effective_finding_status

router = APIRouter(prefix="/api/learning", tags=["learning"])


@router.get("/paths", response_model=LearningPathsOut)
def list_paths(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> LearningPathsOut:
    return LearningPathsOut(**learning.paths_payload(db, user))


@router.get("/scans/{scan_id}/endpoints", response_model=ScanEndpointLearningOut)
def scan_endpoint_learning(
    scan_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> ScanEndpointLearningOut:
    payload = learning.endpoint_learning(db, user, scan_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanEndpointLearningOut(**payload)


@router.put(
    "/progress/{check_id}",
    response_model=LearningProgressOut,
    dependencies=[Depends(require_csrf)],
)
def update_progress(
    check_id: str,
    payload: LearningProgressIn,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> LearningProgressOut:
    try:
        row = learning.set_progress(db, user, check_id, payload.status)
    except LookupError:
        raise HTTPException(status_code=404, detail="Check not found") from None
    audit.record(
        db,
        "learning.progress",
        actor=user,
        target_type="check",
        target_id=check_id,
        detail={"status": payload.status},
        ip=client_ip(request),
    )
    db.commit()
    if row is None:
        return LearningProgressOut(check_id=check_id, status="not_started", updated_at=None)
    return LearningProgressOut(check_id=row.check_id, status=row.status, updated_at=row.updated_at)


@router.get("/practice", response_model=list[PracticeFindingOut])
def list_practice_findings(
    limit: int = Query(default=12, ge=1, le=25),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[PracticeFindingOut]:
    rows = learning.practice_findings(db, user, limit)
    return [
        PracticeFindingOut(
            id=row.id,
            scan_id=row.scan_id,
            check_id=row.check_id,
            title=row.title,
            category=row.category,
            severity=row.severity,
            verification_status=effective_finding_status(row)[0],
            confidence=row.confidence,
            risk_score=row.risk_score,
            url=row.url,
            method=row.method,
            created_at=row.created_at,
        )
        for row in rows
    ]


@router.post(
    "/findings/{finding_id}/walkthrough",
    response_model=WalkthroughOut,
    dependencies=[Depends(require_csrf)],
)
def walkthrough(
    finding_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> WalkthroughOut:
    payload = learning.walkthrough_for(db, user, finding_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    audit.record(
        db,
        "learning.walkthrough",
        actor=user,
        target_type="finding",
        target_id=finding_id,
        detail={"check_id": payload["check_id"]},
        ip=client_ip(request),
    )
    db.commit()
    return WalkthroughOut(**payload)


@router.post(
    "/findings/{finding_id}/exercises",
    response_model=list[PracticeExerciseOut],
    dependencies=[Depends(require_csrf)],
)
def exercises(
    finding_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[PracticeExerciseOut]:
    payload = learning.exercises_for(db, user, finding_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    audit.record(
        db,
        "learning.exercises",
        actor=user,
        target_type="finding",
        target_id=finding_id,
        detail={"count": len(payload)},
        ip=client_ip(request),
    )
    db.commit()
    return [PracticeExerciseOut(**item) for item in payload]
