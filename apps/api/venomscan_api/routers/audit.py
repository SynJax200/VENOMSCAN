from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from venomscan_api.db import get_db
from venomscan_api.deps import get_current_user
from venomscan_api.models import AuditEvent, User
from venomscan_api.schemas import AuditOut

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("", response_model=list[AuditOut])
def recent_audit(
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[AuditOut]:
    rows = db.scalars(
        select(AuditEvent)
        .where(AuditEvent.actor_id == user.id)
        .order_by(AuditEvent.id.desc())
        .limit(limit)
    ).all()
    return [
        AuditOut(
            id=row.id,
            action=row.action,
            target_type=row.target_type,
            target_id=row.target_id,
            detail=row.detail or {},
            created_at=row.created_at,
        )
        for row in rows
    ]
