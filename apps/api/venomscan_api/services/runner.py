from __future__ import annotations

import asyncio
import json
import threading
import time
from collections import Counter

from sqlalchemy import select
from venomscan_engine import ScanResult
from venomscan_engine.control import ScanCancelled
from venomscan_engine.events import ScanEvent
from venomscan_engine.oob import OobListener

from venomscan_api.config import get_settings
from venomscan_api.crypto import decrypt
from venomscan_api.db import session_factory, utcnow
from venomscan_api.models import Endpoint, Finding, Scan, Technology, TestCredential
from venomscan_api.models import ScanEvent as ScanEventRow

_oob_listener: OobListener | None = None
_oob_lock = threading.Lock()


def _ensure_oob(settings) -> OobListener | None:
    """One listener per process; scans in this process share it via per-scan tokens."""
    global _oob_listener
    if not settings.oob_enabled:
        return None
    with _oob_lock:
        if _oob_listener is None:
            listener = OobListener(
                bind_host=settings.oob_bind_host,
                bind_port=settings.oob_bind_port,
                public_base_url=settings.oob_public_base_url or None,
            )
            try:
                listener.start()
            except OSError:
                return None
            _oob_listener = listener
        return _oob_listener


def _auth_accounts(settings) -> list[dict]:
    """Decrypt configured test accounts for the engine; tokens never leave this scope."""
    with session_factory()() as db:
        rows = db.scalars(select(TestCredential).order_by(TestCredential.created_at)).all()
        accounts: list[dict] = []
        for row in rows[:3]:
            try:
                headers = json.loads(decrypt(settings.secret_key, row.headers_encrypted) or "{}")
            except json.JSONDecodeError:
                continue
            if isinstance(headers, dict) and headers:
                accounts.append(
                    {
                        "label": row.label,
                        "role": row.role,
                        "identity": row.identity,
                        "headers": {str(k): str(v) for k, v in headers.items()},
                    }
                )
        return accounts


def _cancel_watch(scan_id: str):
    """Poll the scan row every 500 ms so the kill switch stops new outbound traffic."""
    state = {"checked": 0.0, "cancelled": False}

    def check() -> bool:
        if state["cancelled"]:
            return True
        now = time.monotonic()
        if now - state["checked"] < 0.5:
            return False
        state["checked"] = now
        with session_factory()() as db:
            scan = db.get(Scan, scan_id)
            state["cancelled"] = scan is None or scan.status == "cancelled"
        return state["cancelled"]

    return check


class DbEventSink:
    """Persist engine events and make cancellation cooperative."""

    def __init__(self, scan_id: str) -> None:
        self.scan_id = scan_id

    async def emit(self, event: ScanEvent) -> None:
        with session_factory()() as db:
            scan = db.get(Scan, self.scan_id)
            if scan is None:
                raise ScanCancelled("scan record no longer exists")
            if scan.status == "cancelled":
                raise ScanCancelled("cancelled by user request")
            db.add(
                ScanEventRow(
                    scan_id=self.scan_id,
                    phase=event.phase,
                    type=event.type,
                    message=event.message,
                    progress=event.progress,
                    payload=event.payload,
                )
            )
            scan.status = "running"
            scan.phase = event.phase
            scan.progress = max(scan.progress, event.progress)
            db.commit()


def _build_summary(result: ScanResult) -> str:
    if not result.findings:
        return (
            "No findings from the checks enabled in this profile. Passive checks only cover "
            "externally observable configuration, so a clean result is not proof the target is secure."
        )
    counts = Counter(finding.severity.value for finding in result.findings)
    breakdown = ", ".join(
        f"{counts[level]} {level}"
        for level in ("critical", "high", "medium", "low", "info")
        if counts.get(level)
    )
    top = result.findings[0]
    seconds = result.stats.duration_ms / 1000
    return (
        f"{len(result.findings)} findings ({breakdown}). Highest risk: {top.title} at {top.url} "
        f"(risk {top.risk_score}/10, {top.verification_status.value}). "
        f"{result.stats.requests} requests in {seconds:.1f}s."
    )


def _finish(scan_id: str, status: str, *, error: str = "") -> None:
    with session_factory()() as db:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return
        scan.status = status
        scan.finished_at = utcnow()
        scan.error = error[:2000]
        db.commit()


def _persist_success(scan_id: str, result: ScanResult, settings) -> None:
    with session_factory()() as db:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return
        if scan.status == "cancelled":
            scan.finished_at = utcnow()
            db.commit()
            return
        for technology in result.technologies:
            db.add(
                Technology(
                    scan_id=scan_id,
                    name=technology.name,
                    version=technology.version,
                    category=technology.category,
                    confidence=technology.confidence,
                    evidence=technology.evidence,
                )
            )
        for endpoint in result.endpoints:
            db.add(
                Endpoint(
                    scan_id=scan_id,
                    url=endpoint.url,
                    method=endpoint.method,
                    source=endpoint.source,
                    status_code=endpoint.status_code,
                    content_type=endpoint.content_type,
                    depth=endpoint.depth,
                    parameters=endpoint.parameters,
                )
            )
        for finding in result.findings:
            db.add(
                Finding(
                    scan_id=scan_id,
                    dedup_key=finding.dedup_key,
                    check_id=finding.check_id,
                    title=finding.title,
                    category=finding.category,
                    severity=finding.severity.value,
                    verification_status=finding.verification_status.value,
                    confidence=finding.confidence,
                    risk_score=finding.risk_score,
                    url=finding.url,
                    method=finding.method,
                    parameter=finding.parameter,
                    payload=finding.payload,
                    description=finding.description,
                    impact=finding.impact,
                    remediation=finding.remediation,
                    references=finding.references,
                    cwe=finding.cwe,
                    owasp=finding.owasp,
                    cvss_score=finding.cvss_score,
                    cvss_vector=finding.cvss_vector,
                    request_evidence=finding.request_evidence,
                    response_evidence=finding.response_evidence,
                )
            )
        scan.status = "completed"
        scan.phase = "reporting"
        scan.progress = 100
        scan.stats = {
            **result.stats.model_dump(mode="json"),
            "max_requests": settings.scan_max_requests,
            "max_seconds": settings.scan_max_seconds,
            "rps": settings.scan_rps,
        }
        scan.recon = result.recon
        scan.summary = _build_summary(result)
        scan.finished_at = utcnow()
        db.commit()


def execute_scan(scan_id: str) -> None:
    settings = get_settings()
    with session_factory()() as db:
        scan = db.get(Scan, scan_id)
        if scan is None or scan.status not in {"queued", "running"}:
            return
        target = scan.target
        scan.status = "running"
        scan.phase = "authorizing"
        scan.started_at = scan.started_at or utcnow()
        db.commit()
        target_url = target.url
        profile = scan.profile
        active_consent = bool((scan.options or {}).get("active_consent"))

    try:
        result = asyncio.run(
            _run_engine(
                scan_id,
                target_url,
                profile,
                settings,
                active_consent,
                cancel_check=_cancel_watch(scan_id),
                oob=_ensure_oob(settings) if profile == "active" else None,
                auth_accounts=_auth_accounts(settings) if profile == "active" else [],
            )
        )
    except ScanCancelled:
        _finish(scan_id, "cancelled", error="Scan cancelled by user")
        return
    except Exception as exc:
        _finish(scan_id, "failed", error=f"{type(exc).__name__}: {exc}")
        return
    _persist_success(scan_id, result, settings)
    if settings.ai_auto_triage:
        from venomscan_api.services import ai_service

        try:
            asyncio.run(ai_service.auto_triage_scan(scan_id))
        except Exception:  # triage must never change a completed scan into a failure
            pass


async def _run_engine(
    scan_id: str,
    target_url: str,
    profile: str,
    settings,
    active_consent: bool = False,
    cancel_check=None,
    oob: OobListener | None = None,
    auth_accounts: list[dict] | None = None,
) -> ScanResult:
    from venomscan_engine.integrations import NucleiConfig
    from venomscan_engine.pipeline import run_scan
    from venomscan_engine.plugins.runner import plugin_dirs_from_env

    from venomscan_api.services import workspace

    with session_factory()() as db:
        disabled = workspace.disabled_checks(db)
    nuclei = None
    if settings.nuclei_enabled and profile == "active":
        nuclei = NucleiConfig(
            binary=settings.nuclei_binary,
            templates=settings.nuclei_templates,
            severities=tuple(
                item.strip() for item in settings.nuclei_severities.split(",") if item.strip()
            ),
            rate_limit=settings.nuclei_rate_limit,
            timeout=settings.nuclei_timeout,
            proxy_url=settings.upstream_proxy_url,
        )
    return await run_scan(
        scan_id,
        target_url,
        profile=profile,
        sink=DbEventSink(scan_id),
        allow_private=settings.allow_private_targets,
        max_requests=settings.scan_max_requests,
        max_seconds=settings.scan_max_seconds,
        rps=settings.scan_rps,
        enable_osint=settings.scan_osint_enabled,
        enable_history=settings.scan_history_enabled,
        enable_ptr_sweep=profile == "active",
        shodan_key=settings.shodan_api_key,
        censys_id=settings.censys_api_id,
        censys_secret=settings.censys_api_secret,
        otx_api_key=settings.otx_api_key,
        enable_spa=settings.scan_spa_enabled,
        enable_dirs=settings.scan_dirs_enabled,
        disabled_checks=disabled,
        active_consent=active_consent,
        cancel_check=cancel_check,
        oob=oob,
        auth_accounts=auth_accounts or [],
        proxy_url=settings.upstream_proxy_url or None,
        nuclei=nuclei,
        plugin_dirs=plugin_dirs_from_env(settings.plugin_dirs),
    )


def dispatch(scan_id: str) -> None:
    settings = get_settings()
    if settings.task_mode == "celery":
        from venomscan_workers.tasks import execute_scan_task

        execute_scan_task.delay(scan_id)
        return
    thread = threading.Thread(
        target=execute_scan,
        args=(scan_id,),
        name=f"venomscan-scan-{scan_id[:8]}",
        daemon=True,
    )
    thread.start()
