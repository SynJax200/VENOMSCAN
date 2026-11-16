from __future__ import annotations

import re
from typing import Any

from sqlalchemy.orm import Session
from venomscan_engine.safety.redact import redact_text

from venomscan_api.models import AuditEvent, User

_SENSITIVE_KEY = re.compile(
    r"(?i)(authorization|cookie|token|secret|password|passwd|api[-_]?key|credential)"
)


def redact_detail(value: Any, key: str = "") -> Any:
    """Audit details are durable; never store credentials or tokens in them."""
    if _SENSITIVE_KEY.search(key):
        return "«redacted»"
    if isinstance(value, dict):
        return {str(k): redact_detail(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_detail(item, key) for item in value]
    if isinstance(value, str):
        return redact_text(value, limit=2000)
    return value


def record(
    db: Session,
    action: str,
    *,
    actor: User | None = None,
    target_type: str = "",
    target_id: str = "",
    detail: dict[str, Any] | None = None,
    ip: str = "",
) -> AuditEvent:
    event = AuditEvent(
        actor_id=actor.id if actor else None,
        action=action,
        target_type=target_type,
        target_id=target_id,
        detail=redact_detail(detail or {}),
        ip_address=ip,
    )
    db.add(event)
    return event
