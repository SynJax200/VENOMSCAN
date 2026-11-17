from __future__ import annotations

import json

from sqlalchemy import select
from venomscan_api.audit_verification import audit
from venomscan_api.config import Settings
from venomscan_api.db import init_db, init_engine, session_factory
from venomscan_api.models import Finding, Scan, Target, User

_db_url = ""


def _seed() -> None:
    init_engine(
        Settings(
            _env_file=None,
            database_url=_db_url,
            secret_key="test-secret-key-that-is-long-enough-for-hs256",
            environment="test",
        )
    )
    init_db()
    with session_factory()() as db:
        user = User(email="audit@example.com", password_hash="x")
        db.add(user)
        db.flush()
        target = Target(owner_id=user.id, name="t", url="https://example.com/", host="example.com")
        db.add(target)
        db.flush()
        scan = Scan(target_id=target.id)
        db.add(scan)
        db.flush()
        db.add_all(
            [
                Finding(
                    scan_id=scan.id,
                    dedup_key="no-proof",
                    check_id="venom.headers.csp",
                    title="legacy",
                    category="headers",
                    severity="medium",
                    verification_status="verified",
                    confidence=9,
                    url="https://example.com/",
                    description="d",
                    impact="i",
                    remediation="r",
                    request_evidence={},
                    response_evidence={},
                ),
                Finding(
                    scan_id=scan.id,
                    dedup_key="with-proof",
                    check_id="venom.headers.csp",
                    title="current",
                    category="headers",
                    severity="medium",
                    verification_status="verified",
                    confidence=7,
                    url="https://example.com/",
                    description="d",
                    impact="i",
                    remediation="r",
                    request_evidence={"method": "GET", "url": "https://example.com/"},
                    response_evidence={"url": "https://example.com/", "status_code": 200},
                ),
            ]
        )
        db.commit()


def test_audit_dry_run_reports_without_writing(tmp_path):
    global _db_url
    _db_url = f"sqlite:///{tmp_path / 'audit.db'}"
    _seed()
    result = audit(dry_run=True, backup_dir=tmp_path)
    assert result["downgraded"] == 1
    assert not list(tmp_path.glob("verification-audit-*.json"))
    with session_factory()() as db:
        row = db.scalars(select(Finding).where(Finding.dedup_key == "no-proof")).one()
        assert row.verification_status == "verified"


def test_audit_backs_up_then_downgrades_only_unsupported_rows(tmp_path):
    global _db_url
    _db_url = f"sqlite:///{tmp_path / 'audit2.db'}"
    _seed()
    backups = tmp_path / "backups"
    result = audit(dry_run=False, backup_dir=backups)
    assert result == {"checked": 2, "downgraded": 1, "unknown_status": 0, "dry_run": 0}
    written = list(backups.glob("verification-audit-*.json"))
    assert len(written) == 1
    payload = json.loads(written[0].read_text(encoding="utf-8"))
    assert payload["rows"][0]["id"]
    assert payload["rows"][0]["verification_reason"] == "request evidence has no URL"
    with session_factory()() as db:
        bad = db.scalars(select(Finding).where(Finding.dedup_key == "no-proof")).one()
        good = db.scalars(select(Finding).where(Finding.dedup_key == "with-proof")).one()
        assert bad.verification_status == "suspected"
        assert bad.confidence == 5
        assert bad.response_evidence["verification_note"] == "evidence contract incomplete"
        assert good.verification_status == "verified"
        assert good.confidence == 7
