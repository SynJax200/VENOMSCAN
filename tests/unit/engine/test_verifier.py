from __future__ import annotations

from venomscan_engine.models import Finding, Severity, VerificationStatus
from venomscan_engine.verify.verifier import evidence_complete, mark_verified


def _finding(**overrides) -> Finding:
    base = {
        "check_id": "venom.xss.reflected",
        "title": "t",
        "category": "injection",
        "severity": Severity.HIGH,
        "confidence": 9,
        "verification_status": VerificationStatus.VERIFIED,
        "url": "https://example.com/search?q=x",
        "description": "d",
        "impact": "i",
        "remediation": "r",
        "request_evidence": {"method": "GET", "url": "https://example.com/search?q=probe"},
        "response_evidence": {"reflection": "raw-payload", "variants_reflected": 2},
    }
    base.update(overrides)
    return Finding(**base)


def test_complete_exploit_evidence_passes():
    finding = _finding()
    assert evidence_complete(finding) is True
    summary = mark_verified([finding])
    assert finding.verification_status is VerificationStatus.VERIFIED
    assert finding.confidence == 9
    assert summary == {"verified": 1, "suspected": 0, "rejected": 0, "downgraded": 0}


def test_missing_request_url_downgrades():
    finding = _finding(request_evidence={"method": "GET"})
    summary = mark_verified([finding])
    assert finding.verification_status is VerificationStatus.SUSPECTED
    assert finding.confidence == 5
    assert finding.response_evidence["verification_note"] == "evidence contract incomplete"
    assert summary["downgraded"] == 1


def test_missing_required_key_downgrades():
    finding = _finding(response_evidence={"reflection": "raw-payload"})
    mark_verified([finding])
    assert finding.verification_status is VerificationStatus.SUSPECTED


def test_empty_required_value_downgrades():
    finding = _finding(response_evidence={"error_family": "", "control_clean": True}, check_id="venom.sqli.error")
    mark_verified([finding])
    assert finding.verification_status is VerificationStatus.SUSPECTED


def test_deterministic_findings_stay_verified_without_evidence():
    finding = _finding(
        check_id="venom.headers.csp",
        verification_status=VerificationStatus.SUSPECTED,
        request_evidence={},
        response_evidence={},
        confidence=8,
    )
    summary = mark_verified([finding])
    assert finding.verification_status is VerificationStatus.VERIFIED
    assert finding.confidence == 8
    assert summary["verified"] == 1


def test_suspected_exploit_findings_are_left_alone():
    finding = _finding(verification_status=VerificationStatus.SUSPECTED, response_evidence={})
    summary = mark_verified([finding])
    assert finding.verification_status is VerificationStatus.SUSPECTED
    assert summary == {"verified": 0, "suspected": 1, "rejected": 0, "downgraded": 0}
