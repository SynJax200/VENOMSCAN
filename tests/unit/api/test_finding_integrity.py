from __future__ import annotations

from types import SimpleNamespace

from venomscan_api.services.finding_integrity import effective_finding_status


def _stored(**overrides) -> SimpleNamespace:
    base = {
        "check_id": "venom.headers.csp",
        "verification_status": "verified",
        "request_evidence": {"method": "GET", "url": "https://example.com/"},
        "response_evidence": {"url": "https://example.com/", "status_code": 200},
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def test_verified_row_with_observed_response_stays_verified():
    assert effective_finding_status(_stored()) == ("verified", None)


def test_verified_row_without_evidence_is_reported_as_suspected():
    status, reason = effective_finding_status(_stored(response_evidence={}))
    assert status == "suspected"
    assert reason == "response evidence is empty"


def test_rejected_row_is_never_rewritten():
    assert effective_finding_status(_stored(verification_status="rejected")) == ("rejected", None)


def test_heuristic_verified_row_is_reported_as_suspected():
    status, reason = effective_finding_status(
        _stored(
            check_id="venom.secrets.js",
            response_evidence={"url": "https://example.com/app.js", "pattern": "AKIA..."},
        )
    )
    assert status == "suspected"
    assert "heuristic" in reason
