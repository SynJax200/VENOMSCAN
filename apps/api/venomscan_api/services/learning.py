from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session
from venomscan_engine.checks import check_catalog
from venomscan_engine.learning import build_exercises, build_walkthrough, curriculum
from venomscan_engine.models import endpoint_state

from venomscan_api.models import Endpoint, Finding, LearningProgress, Scan, Target, User

STATUSES = {"not_started", "in_progress", "completed"}


def _catalog() -> dict[str, dict]:
    return {entry["id"]: entry for entry in check_catalog()}


def progress_rows(db: Session, user: User) -> list[LearningProgress]:
    return list(
        db.scalars(
            select(LearningProgress)
            .where(LearningProgress.user_id == user.id)
            .order_by(LearningProgress.updated_at.desc())
        ).all()
    )


def paths_payload(db: Session, user: User) -> dict:
    rows = {row.check_id: row for row in progress_rows(db, user)}
    data = curriculum()
    completed = 0
    in_progress = 0
    tracks = []
    for track in data["tracks"]:
        lessons = []
        for lesson in track["lessons"]:
            row = rows.get(lesson["id"])
            status = row.status if row is not None else "not_started"
            lessons.append(
                {
                    **lesson,
                    "status": status,
                    "updated_at": row.updated_at if row is not None else None,
                }
            )
            if status == "completed":
                completed += 1
            elif status == "in_progress":
                in_progress += 1
        total = len(lessons)
        track_completed = sum(1 for lesson in lessons if lesson["status"] == "completed")
        tracks.append(
            {
                **{
                    key: track[key]
                    for key in (
                        "id",
                        "title",
                        "level",
                        "focus",
                        "outcome",
                        "check_ids",
                        "scan_profile",
                        "consent",
                    )
                },
                "lessons": lessons,
                "completed": track_completed,
                "total": total,
                "percent": round(track_completed * 100 / total) if total else 0,
            }
        )
    count = data["check_count"]
    return {
        "tracks": tracks,
        "check_count": count,
        "completed": completed,
        "in_progress": in_progress,
        "percent": round(completed * 100 / count) if count else 0,
    }


def set_progress(db: Session, user: User, check_id: str, status: str) -> LearningProgress | None:
    if check_id not in _catalog():
        raise LookupError(check_id)
    if status not in STATUSES:
        raise ValueError(status)
    row = db.scalar(
        select(LearningProgress).where(
            LearningProgress.user_id == user.id,
            LearningProgress.check_id == check_id,
        )
    )
    if status == "not_started":
        if row is not None:
            db.delete(row)
            db.flush()
        return None
    if row is None:
        row = LearningProgress(user_id=user.id, check_id=check_id, status=status)
        db.add(row)
    else:
        row.status = status
    db.flush()
    return row


def practice_findings(db: Session, user: User, limit: int = 12) -> list[Finding]:
    return list(
        db.scalars(
            select(Finding)
            .join(Scan, Scan.id == Finding.scan_id)
            .join(Target, Target.id == Scan.target_id)
            .where(Target.owner_id == user.id, Finding.verification_status == "verified")
            .order_by(Finding.created_at.desc(), Finding.id)
            .limit(limit)
        ).all()
    )


def owned_finding(db: Session, user: User, finding_id: str) -> Finding | None:
    finding = db.get(Finding, finding_id)
    if finding is None or finding.scan is None or finding.scan.target is None:
        return None
    if finding.scan.target.owner_id != user.id:
        return None
    return finding


def finding_payload(finding: Finding) -> dict:
    return {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "check_id": finding.check_id,
        "title": finding.title,
        "category": finding.category,
        "severity": finding.severity,
        "verification_status": finding.verification_status,
        "confidence": finding.confidence,
        "risk_score": finding.risk_score,
        "url": finding.url,
        "method": finding.method,
        "remediation": finding.remediation,
        "references": list(finding.references or []),
        "request_evidence": finding.request_evidence or {},
        "response_evidence": finding.response_evidence or {},
    }


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def endpoint_learning(db: Session, user: User, scan_id: str) -> dict | None:
    """Group a user's scan endpoints with the lesson attached to each observed finding."""
    scan = db.get(Scan, scan_id)
    if scan is None or scan.target is None or scan.target.owner_id != user.id:
        return None
    catalog = _catalog()
    findings = db.scalars(
        select(Finding)
        .where(Finding.scan_id == scan.id)
        .order_by(Finding.risk_score.desc(), Finding.id)
    ).all()
    by_url: dict[str, list[Finding]] = {}
    for finding in findings:
        by_url.setdefault(finding.url, []).append(finding)
    endpoints = db.scalars(
        select(Endpoint).where(Endpoint.scan_id == scan.id).order_by(Endpoint.depth, Endpoint.id)
    ).all()

    entries: list[dict] = []
    seen: set[str] = set()
    for endpoint in endpoints:
        entries.append(
            _endpoint_entry(
                endpoint.url,
                endpoint.method,
                endpoint.source,
                endpoint.status_code,
                by_url.get(endpoint.url, []),
                catalog,
            )
        )
        seen.add(endpoint.url)
    for url, rows in by_url.items():
        if url in seen:
            continue
        entries.append(
            _endpoint_entry(url, rows[0].method, "finding", None, rows, catalog)
        )
    entries.sort(
        key=lambda entry: (
            min(
                (_SEVERITY_ORDER.get(lesson["severity"], 5) for lesson in entry["lessons"]),
                default=5,
            ),
            entry["url"],
        )
    )
    return {
        "scan_id": scan.id,
        "target_url": scan.target.url,
        "endpoint_count": len(entries),
        "with_findings": sum(1 for entry in entries if entry["lessons"]),
        "endpoints": entries,
    }


def _endpoint_entry(
    url: str,
    method: str,
    source: str,
    status_code: int | None,
    findings: list[Finding],
    catalog: dict[str, dict],
) -> dict:
    lessons = []
    for finding in findings:
        entry = catalog.get(finding.check_id, {})
        learning = entry.get("learning") or {}
        lessons.append(
            {
                "finding_id": finding.id,
                "check_id": finding.check_id,
                "title": finding.title,
                "severity": finding.severity,
                "verification_status": finding.verification_status,
                "risk_score": finding.risk_score,
                "what": learning.get("what", ""),
                "why": learning.get("why", ""),
                "verify": learning.get("verify", ""),
            }
        )
    return {
        "url": url,
        "method": method,
        "source": source,
        "state": endpoint_state(source, status_code),
        "status_code": status_code,
        "finding_count": len(lessons),
        "lessons": lessons,
    }


def walkthrough_for(db: Session, user: User, finding_id: str) -> dict | None:
    finding = owned_finding(db, user, finding_id)
    if finding is None:
        return None
    entry = _catalog().get(finding.check_id, {})
    return build_walkthrough(finding_payload(finding), entry.get("learning") or {})


def exercises_for(db: Session, user: User, finding_id: str) -> list[dict] | None:
    finding = owned_finding(db, user, finding_id)
    if finding is None:
        return None
    entry = _catalog().get(finding.check_id, {})
    siblings = (
        db.scalars(
            select(Finding)
            .where(Finding.scan_id == finding.scan_id, Finding.id != finding.id)
            .order_by(Finding.risk_score.desc(), Finding.id)
            .limit(6)
        ).all()
    )
    sibling_payloads = [
        {"id": row.id, "title": row.title, "risk_score": row.risk_score} for row in siblings
    ]
    return build_exercises(
        finding_payload(finding),
        entry.get("learning") or {},
        check_catalog(),
        sibling_payloads,
    )
