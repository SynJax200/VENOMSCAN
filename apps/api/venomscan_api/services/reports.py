from __future__ import annotations

import hashlib
import hmac
import re
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session
from venomscan_engine.reports import (
    FORMATS,
    ReportAi,
    ReportAuthorization,
    ReportCheck,
    ReportEndpoint,
    ReportFinding,
    ReportModel,
    ReportScan,
    ReportTechnology,
    canonical_json,
    cvss_for,
    render_html,
    render_markdown,
    render_pdf,
    reproduction_steps,
)
from venomscan_engine.reports.renderers import file_extension

from venomscan_api.config import Settings
from venomscan_api.db import as_utc, utcnow
from venomscan_api.models import AiAnalysis, Report, Scan, User
from venomscan_api.schemas import ReportOut
from venomscan_api.services import finding_integrity


class ReportRenderError(RuntimeError):
    pass


def _iso(value) -> str | None:
    return value.isoformat() if value else None


def _ai_summary(payload: dict) -> str:
    if payload.get("summary"):
        return str(payload["summary"])
    if payload.get("answer"):
        return str(payload["answer"])
    headline = str(payload.get("headline") or "")
    priorities = payload.get("priorities") or []
    parts = [headline] if headline else []
    if isinstance(priorities, list):
        parts += [str(item) for item in priorities[:5]]
    return "\n".join(part for part in parts if part)


def _ai_citations(payload: dict) -> list[str]:
    refs = payload.get("evidence_refs") or []
    if not isinstance(refs, list):
        return []
    return [str(ref)[:200] for ref in refs[:20] if str(ref).strip()]


def _ai_steps(payload: dict) -> list[str]:
    steps = payload.get("steps") or []
    if not isinstance(steps, list):
        return []
    cleaned: list[str] = []
    for item in steps[:12]:
        if isinstance(item, dict):
            title = str(item.get("title") or "").strip()
            detail = str(item.get("detail") or "").strip()
            text = f"{title} — {detail}" if title and detail else title or detail
        else:
            text = str(item).strip()
        if text:
            cleaned.append(text[:800])
    return cleaned


def _safe_filename(host: str, scan_id: str, fmt: str) -> str:
    label = re.sub(r"[^a-z0-9.-]+", "-", host.lower()).strip("-") or "target"
    return f"venomscan-{label}-{scan_id[:8]}.{file_extension(fmt)}"


def _check_coverage(scan: Scan) -> list[ReportCheck]:
    from venomscan_engine.checks import check_catalog, checks_for_profile

    selected = {cls.id for cls in checks_for_profile(scan.profile)}
    reported = {finding.check_id for finding in scan.findings}
    checks = [
        ReportCheck(
            id=entry["id"],
            name=entry["name"],
            category=entry["category"],
            profile=entry["profile"],
            severity=entry["severity"],
            result="finding" if entry["id"] in reported else "no finding",
        )
        for entry in check_catalog()
        if entry["id"] in selected
    ]
    return sorted(checks, key=lambda item: (item.category, item.id))


def build_model(db: Session, scan: Scan, user: User) -> ReportModel:
    target = scan.target
    authorization = target.latest_authorization if target else None
    ai_rows = db.scalars(
        select(AiAnalysis)
        .where(AiAnalysis.scan_id == scan.id, AiAnalysis.finding_id.is_(None))
        .order_by(AiAnalysis.created_at)
    ).all()
    findings = []
    for finding in sorted(scan.findings, key=lambda item: -item.risk_score):
        status, reason = finding_integrity.effective_finding_status(finding)
        response_evidence = dict(finding.response_evidence or {})
        if reason:
            response_evidence.setdefault("verification_reason", reason)
        cvss_vector = finding.cvss_vector
        cvss_score = finding.cvss_score
        if cvss_score is None:
            reference = cvss_for(finding.check_id)
            if reference is not None:
                cvss_vector, cvss_score = reference
        finding_model = ReportFinding(
            id=finding.id,
            check_id=finding.check_id,
            title=finding.title,
            category=finding.category,
            severity=finding.severity,
            verification_status=status,
            confidence=finding.confidence,
            risk_score=finding.risk_score,
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
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            request_evidence=finding.request_evidence or {},
            response_evidence=response_evidence,
            ai_summary=finding.ai_summary or "",
        )
        finding_model.reproduction = reproduction_steps(finding_model)
        findings.append(finding_model)
    return ReportModel(
        generated_at=_iso(utcnow()) or "",
        scan=ReportScan(
            id=scan.id,
            target_name=target.name if target else "",
            target_url=target.url if target else "",
            host=target.host if target else "",
            profile=scan.profile,
            status=scan.status,
            summary=scan.summary,
            stats=scan.stats or {},
            recon=scan.recon or {},
            started_at=_iso(scan.started_at),
            finished_at=_iso(scan.finished_at),
            created_at=_iso(scan.created_at),
        ),
        authorization=ReportAuthorization(
            method=authorization.method if authorization and authorization.verified_at else "",
            verified_at=_iso(authorization.verified_at) if authorization else None,
            expires_at=_iso(authorization.expires_at) if authorization else None,
            operator=user.email,
        ),
        findings=findings,
        checks=_check_coverage(scan),
        technologies=[
            ReportTechnology(
                name=tech.name,
                version=tech.version,
                category=tech.category,
                confidence=tech.confidence,
                evidence=tech.evidence,
            )
            for tech in scan.technologies
        ],
        endpoints=[
            ReportEndpoint(
                url=endpoint.url,
                method=endpoint.method,
                source=endpoint.source,
                status_code=endpoint.status_code,
                depth=endpoint.depth,
            )
            for endpoint in scan.endpoints[:1000]
        ],
        ai_analyses=[
            ReportAi(
                kind=row.kind,
                summary=_ai_summary(row.payload or {}),
                steps=_ai_steps(row.payload or {}),
                citations=_ai_citations(row.payload or {}),
                provider=row.provider,
                model=row.model,
                fallback=row.fallback,
                created_at=_iso(row.created_at),
            )
            for row in ai_rows
        ],
    )


def media_for(fmt: str) -> str:
    from venomscan_engine.reports.renderers import media_type

    return media_type(fmt)


def render(model: ReportModel, fmt: str, integrity: str) -> bytes:
    if fmt not in FORMATS:
        raise ValueError(f"unsupported report format {fmt!r}")
    if fmt == "json":
        # The downloaded file is the exact canonical bytes that were hashed, so
        # `sha256sum file` reproduces report.sha256 without any re-serialisation.
        return canonical_json(model)
    if fmt == "markdown":
        return render_markdown(model)
    if fmt == "html":
        return render_html(model, integrity).encode("utf-8")
    try:
        return render_pdf(model, integrity)
    except RuntimeError as exc:
        raise ReportRenderError(str(exc)) from exc


def generate(db: Session, scan: Scan, user: User, fmt: str, settings: Settings) -> Report:
    model = build_model(db, scan, user)
    integrity = hashlib.sha256(canonical_json(model)).hexdigest()
    content = render(model, fmt, integrity)
    host = scan.target.host if scan.target else "target"
    title = f"{scan.target.name if scan.target else host} — {fmt.upper()} assessment report"
    report = Report(
        scan_id=scan.id,
        format=fmt,
        title=title,
        filename=_safe_filename(host, scan.id, fmt),
        content=content,
        model_json=canonical_json(model).decode("utf-8"),
        sha256=integrity,
        size=len(content),
        created_by=user.id,
        expires_at=utcnow() + timedelta(hours=settings.report_link_hours),
    )
    db.add(report)
    db.flush()
    return report


def sign(report_id: str, expires_at, secret: str) -> str:
    stamp = int(as_utc(expires_at).timestamp())
    message = f"{report_id}.{stamp}".encode()
    signature = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()[:40]
    return f"{report_id}.{stamp}.{signature}"


def verify_token(token: str, secret: str) -> str | None:
    """Return the report id for a valid, unexpired signed token."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    report_id, stamp, signature = parts
    expected = hmac.new(
        secret.encode(), f"{report_id}.{stamp}".encode(), hashlib.sha256
    ).hexdigest()[:40]
    if not hmac.compare_digest(expected, signature):
        return None
    try:
        expires = int(stamp)
    except ValueError:
        return None
    if expires < int(utcnow().timestamp()):
        return None
    return report_id


def restore_model(report: Report) -> ReportModel:
    import json

    return ReportModel.model_validate(json.loads(report.model_json or "{}"))


def report_out(report: Report, settings: Settings) -> ReportOut:
    token = sign(report.id, report.expires_at, settings.secret_key)
    return ReportOut(
        id=report.id,
        scan_id=report.scan_id,
        format=report.format,
        title=report.title,
        filename=report.filename,
        sha256=report.sha256,
        size=report.size,
        created_at=report.created_at,
        expires_at=report.expires_at,
        download_url=f"/api/reports/{report.id}/download",
        preview_url=f"/api/reports/{report.id}/preview",
        signed_url=f"/api/reports/{report.id}/signed/{token}",
    )
