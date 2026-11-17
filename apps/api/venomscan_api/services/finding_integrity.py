from __future__ import annotations

from typing import Any

from venomscan_engine.verify import effective_verification

from venomscan_api.models import Finding


def effective_status(
    check_id: str,
    declared: str,
    request_evidence: dict[str, Any] | None,
    response_evidence: dict[str, Any] | None,
) -> tuple[str, str | None]:
    """Return the status the stored evidence supports for a persisted finding."""
    status, reason = effective_verification(
        check_id,
        declared,
        request_evidence or {},
        response_evidence or {},
    )
    return status.value, reason


def effective_finding_status(finding: Finding) -> tuple[str, str | None]:
    return effective_status(
        finding.check_id,
        finding.verification_status,
        finding.request_evidence,
        finding.response_evidence,
    )
