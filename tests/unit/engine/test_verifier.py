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


def test_deterministic_findings_need_the_observed_response():
    finding = _finding(
        check_id="venom.headers.csp",
        verification_status=VerificationStatus.SUSPECTED,
        request_evidence={"method": "GET", "url": "https://example.com/"},
        response_evidence={
            "url": "https://example.com/",
            "status_code": 200,
            "headers": {"server": "demo"},
        },
        confidence=8,
    )
    summary = mark_verified([finding])
    assert finding.verification_status is VerificationStatus.VERIFIED
    assert finding.confidence == 8
    assert summary["verified"] == 1


def test_deterministic_findings_without_evidence_stay_suspected():
    finding = _finding(
        check_id="venom.headers.csp",
        verification_status=VerificationStatus.SUSPECTED,
        request_evidence={},
        response_evidence={},
        confidence=8,
    )
    summary = mark_verified([finding])
    assert finding.verification_status is VerificationStatus.SUSPECTED
    assert summary == {"verified": 0, "suspected": 1, "rejected": 0, "downgraded": 0}


def test_suspected_exploit_findings_are_left_alone():
    finding = _finding(verification_status=VerificationStatus.SUSPECTED, response_evidence={})
    summary = mark_verified([finding])
    assert finding.verification_status is VerificationStatus.SUSPECTED
    assert summary == {"verified": 0, "suspected": 1, "rejected": 0, "downgraded": 0}


def test_observed_api_finding_with_its_contract_stays_verified():
    finding = _finding(
        check_id="venom.api.auth",
        response_evidence={
            "url": "https://example.com",
            "spec": "https://example.com/openapi.json",
            "declared_auth": False,
            "servers": [],
        },
    )
    summary = mark_verified([finding])
    assert finding.verification_status is VerificationStatus.VERIFIED
    assert summary["downgraded"] == 0


def test_observed_api_finding_with_only_a_url_is_downgraded():
    finding = _finding(
        check_id="venom.api.auth",
        response_evidence={"url": "https://example.com", "spec": "https://example.com/openapi.json"},
    )
    mark_verified([finding])
    assert finding.verification_status is VerificationStatus.SUSPECTED


def test_heuristic_finding_is_never_promoted():
    finding = _finding(
        check_id="venom.secrets.js",
        verification_status=VerificationStatus.SUSPECTED,
        response_evidence={"url": "https://example.com/app.js", "pattern": "AKIA..."},
    )
    summary = mark_verified([finding])
    assert finding.verification_status is VerificationStatus.SUSPECTED
    assert summary["verified"] == 0


def test_declared_verified_heuristic_is_downgraded():
    finding = _finding(
        check_id="venom.csrf.token",
        response_evidence={"url": "https://example.com/form", "page": "<form/>"},
    )
    mark_verified([finding])
    assert finding.verification_status is VerificationStatus.SUSPECTED
    assert "heuristic" in finding.response_evidence["verification_reason"]


def test_declared_verified_external_finding_is_downgraded():
    finding = _finding(
        check_id="nuclei.cve-2021-44228",
        response_evidence={"url": "https://example.com", "status_code": 200},
    )
    mark_verified([finding])
    assert finding.verification_status is VerificationStatus.SUSPECTED
    assert "external" in finding.response_evidence["verification_reason"]


def test_unknown_contract_is_downgraded():
    finding = _finding(
        check_id="custom.unofficial",
        response_evidence={"url": "https://example.com", "status_code": 200},
    )
    mark_verified([finding])
    assert finding.verification_status is VerificationStatus.SUSPECTED
    assert finding.response_evidence["verification_reason"] == "check has no evidence contract"


def test_every_evidence_contract_names_a_real_check():
    from venomscan_engine.checks import all_check_ids
    from venomscan_engine.verify.verifier import (
        OBSERVED_RESPONSE_EVIDENCE,
        REQUIRED_RESPONSE_EVIDENCE,
    )

    known = set(all_check_ids())
    contract_ids = set(REQUIRED_RESPONSE_EVIDENCE) | set(OBSERVED_RESPONSE_EVIDENCE)
    assert contract_ids <= known, sorted(contract_ids - known)
