from __future__ import annotations

from sqlalchemy import select
from venomscan_api.config import Settings
from venomscan_api.db import init_db, init_engine, session_factory
from venomscan_api.models import AuditEvent
from venomscan_api.services.audit import record, redact_detail
from venomscan_engine.safety.redact import redact_text


def test_redact_detail_masks_keys_and_values() -> None:
    cleaned = redact_detail(
        {
            "api_key": "sk-live-1234567890",
            "headers": {"Authorization": "Bearer abcdefghijklmnop", "Accept": "*/*"},
            "note": "password=hunter2hunter2 leaked",
            "count": 3,
            "items": ["token=abcdefgh12345678"],
        }
    )
    assert cleaned["api_key"] == "«redacted»"
    assert cleaned["headers"]["Authorization"] == "«redacted»"
    assert cleaned["headers"]["Accept"] == "*/*"
    assert "hunter2hunter2" not in cleaned["note"]
    assert cleaned["count"] == 3


def test_redact_text_masks_authorization_lines() -> None:
    cleaned = redact_text("GET / HTTP/1.1\nAuthorization: Bearer abcdefghijkl\nCookie: sid=xyz")
    assert "abcdefghijkl" not in cleaned
    assert "sid=xyz" not in cleaned
    assert "Authorization: «redacted»" in cleaned


def test_audit_record_stores_redacted_detail(tmp_path) -> None:
    settings = Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'audit.db'}",
        secret_key="test-secret-key-that-is-long-enough-for-hs256",
        environment="test",
    )
    init_engine(settings)
    init_db()
    with session_factory()() as db:
        record(
            db,
            "test.secret",
            detail={"token": "abc123456789", "password": "hunter2hunter2", "safe": "visible"},
        )
        db.commit()
    with session_factory()() as db:
        event = db.scalars(select(AuditEvent).order_by(AuditEvent.id.desc())).first()
        assert event is not None
        assert event.detail["token"] == "«redacted»"
        assert event.detail["password"] == "«redacted»"
        assert event.detail["safe"] == "visible"
