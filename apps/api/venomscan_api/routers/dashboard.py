from __future__ import annotations

from collections import Counter

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from venomscan_api.db import get_db
from venomscan_api.deps import get_current_user
from venomscan_api.models import Finding, Scan, Target, Technology, User
from venomscan_api.schemas import (
    DashboardOut,
    DashboardScan,
    DashboardTarget,
    SeverityCounts,
    SplitSlice,
    TechSlice,
)
from venomscan_api.services.serializers import authorization_state, target_out, verification_out

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("", response_model=DashboardOut)
def dashboard(
    db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> DashboardOut:
    own_scans = (
        select(Scan.id).join(Target, Target.id == Scan.target_id).where(Target.owner_id == user.id)
    )
    total_scans = (
        db.scalar(select(func.count()).select_from(Scan).where(Scan.id.in_(own_scans))) or 0
    )
    completed = (
        db.scalar(
            select(func.count())
            .select_from(Scan)
            .where(Scan.id.in_(own_scans), Scan.status == "completed")
        )
        or 0
    )
    active = (
        db.scalar(
            select(func.count())
            .select_from(Scan)
            .where(Scan.id.in_(own_scans), Scan.status.in_(("queued", "running")))
        )
        or 0
    )

    severity = SeverityCounts()
    rows = db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.scan_id.in_(own_scans))
        .group_by(Finding.severity)
    ).all()
    for name, count in rows:
        if hasattr(severity, name):
            setattr(severity, name, int(count))
    total_findings = sum(
        [severity.critical, severity.high, severity.medium, severity.low, severity.info]
    )

    recent = db.scalars(
        select(Scan)
        .options(selectinload(Scan.target))
        .join(Target, Target.id == Scan.target_id)
        .where(Target.owner_id == user.id)
        .order_by(Scan.created_at.desc())
        .limit(8)
    ).all()
    recent_counts: dict[str, int] = {}
    if recent:
        recent_counts = {
            scan_id: int(count)
            for scan_id, count in db.execute(
                select(Finding.scan_id, func.count(Finding.id))
                .where(Finding.scan_id.in_([scan.id for scan in recent]))
                .group_by(Finding.scan_id)
            ).all()
        }
    recent_scans = [
        DashboardScan(
            id=scan.id,
            target_name=scan.target.name if scan.target else "",
            target_url=scan.target.url if scan.target else "",
            profile=scan.profile,
            status=scan.status,
            progress=scan.progress,
            findings_total=recent_counts.get(scan.id, 0),
            created_at=scan.created_at,
        )
        for scan in recent
    ]

    tech_rows = db.execute(
        select(Technology.name, func.count(Technology.id))
        .where(Technology.scan_id.in_(own_scans))
        .group_by(Technology.name)
        .order_by(func.count(Technology.id).desc())
        .limit(8)
    ).all()
    technologies = [TechSlice(name=name, count=int(count)) for name, count in tech_rows]

    targets = _target_overview(db, user.id)
    by_check, by_owasp = _vulnerability_split(db, own_scans)

    return DashboardOut(
        total_scans=total_scans,
        completed_scans=completed,
        active_scans=active,
        total_findings=total_findings,
        severity=severity,
        recent_scans=recent_scans,
        technologies=technologies,
        targets=targets,
        by_check=by_check,
        by_owasp=by_owasp,
        insights=_insights(total_scans, active, severity, technologies),
    )


def _target_overview(db: Session, owner_id: str, limit: int = 6) -> list[DashboardTarget]:
    rows = db.execute(
        select(
            Target.id,
            Target.name,
            Target.url,
            func.count(Scan.id),
            func.max(Scan.created_at),
        )
        .outerjoin(Scan, Scan.target_id == Target.id)
        .where(Target.owner_id == owner_id)
        .group_by(Target.id)
        .order_by(func.max(Scan.created_at).desc().nulls_last())
        .limit(limit)
    ).all()
    if not rows:
        return []
    target_ids = [row[0] for row in rows]
    latest = db.scalars(
        select(Scan)
        .where(Scan.target_id.in_(target_ids))
        .order_by(Scan.created_at.desc())
    ).all()
    status_by_target: dict[str, str] = {}
    for scan in latest:
        status_by_target.setdefault(scan.target_id, scan.status)
    finding_rows = db.execute(
        select(Scan.target_id, func.count(Finding.id))
        .join(Finding, Finding.scan_id == Scan.id)
        .where(Scan.target_id.in_(target_ids))
        .group_by(Scan.target_id)
    ).all()
    findings_by_target = {target_id: int(count) for target_id, count in finding_rows}
    return [
        DashboardTarget(
            id=target_id,
            name=name,
            url=url,
            scans=int(scans),
            findings=findings_by_target.get(target_id, 0),
            last_scan_at=last_scan_at,
            last_status=status_by_target.get(target_id, ""),
        )
        for target_id, name, url, scans, last_scan_at in rows
    ]


def _vulnerability_split(
    db: Session, own_scans, check_limit: int = 8, owasp_limit: int = 6
) -> tuple[list[SplitSlice], list[SplitSlice]]:
    check_rows = db.execute(
        select(Finding.check_id, func.count(Finding.id))
        .where(Finding.scan_id.in_(own_scans))
        .group_by(Finding.check_id)
        .order_by(func.count(Finding.id).desc())
        .limit(check_limit)
    ).all()
    by_check = [SplitSlice(name=name, count=int(count)) for name, count in check_rows]

    owasp_counter: Counter[str] = Counter()
    for (labels,) in db.execute(
        select(Finding.owasp).where(Finding.scan_id.in_(own_scans))
    ).all():
        owasp_counter.update(label for label in (labels or []) if label)
    by_owasp = [
        SplitSlice(name=name, count=count)
        for name, count in owasp_counter.most_common(owasp_limit)
    ]
    return by_check, by_owasp


def _insights(
    total_scans: int, active: int, severity: SeverityCounts, techs: list[TechSlice]
) -> list[str]:
    if total_scans == 0:
        return [
            "No scans yet. Add and verify a target, then run a passive scan to establish a baseline.",
        ]
    insights: list[str] = []
    urgent = severity.critical + severity.high
    if urgent:
        insights.append(
            f"{urgent} critical/high findings are open. Triage these before adding scan coverage."
        )
    else:
        insights.append(
            "No critical or high findings across completed scans. Re-scan after every deployment."
        )
    if severity.low or severity.medium:
        insights.append(
            f"{severity.medium} medium and {severity.low} low findings are hardening opportunities "
            "and are usually cheap to fix."
        )
    if active:
        insights.append(
            f"{active} scan(s) are currently running; live events stream on the scan page."
        )
    if techs:
        insights.append(
            f"Most frequently observed technology: {techs[0].name} ({techs[0].count} observations). "
            "Track version advisories for it."
        )
    return insights[:4]


__all__ = ["router", "target_out", "verification_out", "authorization_state"]
