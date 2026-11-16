from __future__ import annotations

from datetime import timedelta

import pytest
from venomscan_api import security
from venomscan_api.config import Settings
from venomscan_api.db import init_db, init_engine, session_factory, utcnow
from venomscan_api.models import Authorization, Scan, Target, User
from venomscan_api.services import runner
from venomscan_engine import EndpointRecord, Finding, ScanResult, ScanStats, Severity, Technology
from venomscan_engine.events import ScanEvent
from venomscan_engine.safety.http import TargetUnreachable
from venomscan_engine.verify.verifier import mark_verified


def _seed_scan(profile: str = "safe", options: dict | None = None) -> str:
    with session_factory()() as db:
        user = User(
            email="runner@example.com",
            name="Runner",
            password_hash=security.hash_password("StrongPass123"),
        )
        db.add(user)
        db.flush()
        target = Target(
            owner_id=user.id, name="Runner target", url="http://127.0.0.1:9999/", host="127.0.0.1"
        )
        db.add(target)
        db.flush()
        auth = Authorization(
            target_id=target.id,
            method="manual_attestation",
            token="venomscan-test-token",
            verified_at=utcnow(),
            expires_at=utcnow() + timedelta(days=30),
        )
        db.add(auth)
        db.flush()
        scan = Scan(
            target_id=target.id,
            authorization_id=auth.id,
            profile=profile,
            status="queued",
            phase="queued",
            options=options or {},
        )
        db.add(scan)
        db.commit()
        return scan.id


def _finding() -> Finding:
    return Finding(
        check_id="venom.headers.csp",
        title="Content Security Policy is not set",
        category="config",
        severity=Severity.MEDIUM,
        confidence=9,
        url="http://127.0.0.1:9999/",
        description="d",
        impact="i",
        remediation="r",
    ).finalize()


@pytest.fixture
def database(tmp_path):
    settings = Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'runner.db'}",
        secret_key="runner-test-secret-key-that-is-long-enough",
    )
    init_engine(settings)
    init_db()


def test_execute_scan_persists_results(database, monkeypatch):
    scan_id = _seed_scan()

    async def fake_engine(
        scan_id: str,
        target_url: str,
        profile: str,
        settings,
        active_consent,
        cancel_check=None,
        oob=None,
        auth_accounts=None,
    ):
        sink = runner.DbEventSink(scan_id)
        await sink.emit(
            ScanEvent(phase="recon", type="phase_started", message="fetching", progress=20)
        )
        await sink.emit(
            ScanEvent(phase="analyzing", type="phase_started", message="checks", progress=60)
        )
        finding = _finding()
        mark_verified([finding])
        return ScanResult(
            findings=[finding],
            technologies=[Technology(name="Nginx", category="web-server", confidence=0.85)],
            endpoints=[
                EndpointRecord(
                    url="http://127.0.0.1:9999/search?q=x",
                    source="crawl",
                    status_code=200,
                    depth=2,
                    parameters=["q"],
                )
            ],
            stats=ScanStats(
                requests=3, findings_total=1, endpoints=1, technologies=1, duration_ms=1200
            ),
            recon={"crawl": {"pages": 1, "robots_found": False}},
        )

    monkeypatch.setattr(runner, "_run_engine", fake_engine)
    runner.execute_scan(scan_id)

    with session_factory()() as db:
        scan = db.get(Scan, scan_id)
        assert scan.status == "completed"
        assert scan.progress == 100
        assert scan.phase == "reporting"
        assert len(scan.findings) == 1
        assert scan.findings[0].dedup_key
        assert scan.findings[0].verification_status == "verified"
        assert len(scan.technologies) == 1
        assert len(scan.endpoints) == 1
        assert scan.endpoints[0].depth == 2
        assert scan.endpoints[0].parameters == ["q"]
        assert scan.recon["crawl"]["pages"] == 1
        assert len(scan.events) == 2
        assert "1 findings" in scan.summary
        assert scan.stats["requests"] == 3
        assert scan.stats["max_requests"] >= 3
        assert scan.stats["max_seconds"] > 0
        assert scan.stats["rps"] > 0


def test_execute_scan_passes_active_consent(database, monkeypatch):
    scan_id = _seed_scan(profile="active", options={"active_consent": True})
    captured: dict[str, bool] = {}

    async def consent_engine(
        scan_id: str,
        target_url: str,
        profile: str,
        settings,
        active_consent,
        cancel_check=None,
        oob=None,
        auth_accounts=None,
    ):
        captured["consent"] = active_consent
        captured["profile"] = profile
        return ScanResult(
            stats=ScanStats(requests=1, findings_total=0, endpoints=0, technologies=0, duration_ms=1)
        )

    monkeypatch.setattr(runner, "_run_engine", consent_engine)
    runner.execute_scan(scan_id)

    assert captured == {"consent": True, "profile": "active"}


def test_execute_scan_records_failure(database, monkeypatch):
    scan_id = _seed_scan()

    async def failing_engine(
        scan_id: str,
        target_url: str,
        profile: str,
        settings,
        active_consent,
        cancel_check=None,
        oob=None,
        auth_accounts=None,
    ):
        raise TargetUnreachable("connection refused")

    monkeypatch.setattr(runner, "_run_engine", failing_engine)
    runner.execute_scan(scan_id)

    with session_factory()() as db:
        scan = db.get(Scan, scan_id)
        assert scan.status == "failed"
        assert "connection refused" in scan.error


def test_execute_scan_respects_cancellation(database, monkeypatch):
    scan_id = _seed_scan()

    async def cancelled_engine(
        scan_id: str,
        target_url: str,
        profile: str,
        settings,
        active_consent,
        cancel_check=None,
        oob=None,
        auth_accounts=None,
    ):
        raise runner.ScanCancelled("cancelled by user request")

    monkeypatch.setattr(runner, "_run_engine", cancelled_engine)
    runner.execute_scan(scan_id)

    with session_factory()() as db:
        assert db.get(Scan, scan_id).status == "cancelled"


def test_execute_scan_kill_switch_stops_engine(database, monkeypatch):
    scan_id = _seed_scan()
    observed: dict[str, bool] = {}

    async def cancel_engine(
        scan_id: str,
        target_url: str,
        profile: str,
        settings,
        active_consent,
        cancel_check=None,
        oob=None,
        auth_accounts=None,
    ):
        with session_factory()() as db:
            scan = db.get(Scan, scan_id)
            scan.status = "cancelled"
            db.commit()
        observed["cancel_check"] = cancel_check()
        raise runner.ScanCancelled("scan cancelled by operator")

    monkeypatch.setattr(runner, "_run_engine", cancel_engine)
    runner.execute_scan(scan_id)

    assert observed["cancel_check"] is True
    with session_factory()() as db:
        scan = db.get(Scan, scan_id)
        assert scan.status == "cancelled"
        assert "cancelled" in scan.error.lower()
