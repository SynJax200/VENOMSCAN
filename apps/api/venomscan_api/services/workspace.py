from __future__ import annotations

from sqlalchemy.orm import Session

from venomscan_api.models import WorkspaceSetting

ROW_ID = "default"
DEFAULT_PROFILE = "safe"


def get_row(db: Session) -> WorkspaceSetting:
    row = db.get(WorkspaceSetting, ROW_ID)
    if row is None:
        row = WorkspaceSetting(
            id=ROW_ID, scan_defaults={"profile": DEFAULT_PROFILE}, disabled_checks=[]
        )
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def default_profile(db: Session) -> str:
    row = get_row(db)
    profile = (row.scan_defaults or {}).get("profile", DEFAULT_PROFILE)
    return profile if profile in {"passive", "safe", "active"} else DEFAULT_PROFILE


def disabled_checks(db: Session) -> set[str]:
    row = get_row(db)
    return set(row.disabled_checks or [])
