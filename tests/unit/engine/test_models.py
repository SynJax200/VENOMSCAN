from __future__ import annotations

from venomscan_engine.models import (
    EndpointRecord,
    Finding,
    Severity,
    VerificationStatus,
    endpoint_state,
)
from venomscan_engine.verify.dedupe import dedupe_findings


def _finding(**overrides) -> Finding:
    data = {
        "check_id": "venom.headers.csp",
        "title": "CSP missing",
        "category": "config",
        "severity": Severity.MEDIUM,
        "confidence": 9,
        "url": "https://example.com/",
        "description": "d",
        "impact": "i",
        "remediation": "r",
    }
    data.update(overrides)
    return Finding(**data)


def test_risk_formula_scales_confidence_without_inflating_impact():
    low = _finding(severity=Severity.LOW, confidence=9).finalize()
    assert low.risk_score == 2.4
    assert low.severity is Severity.LOW

    medium_weak = _finding(severity=Severity.HIGH, confidence=3).finalize()
    assert medium_weak.risk_score == 5.76
    assert medium_weak.severity is Severity.MEDIUM

    info = _finding(severity=Severity.INFO, confidence=10).finalize()
    assert info.severity is Severity.INFO
    assert info.risk_score == 0.0


def test_cvss_score_overrides_default_impact():
    critical = _finding(severity=Severity.HIGH, confidence=10, cvss_score=9.8).finalize()
    assert critical.risk_score == 9.8
    assert critical.severity is Severity.CRITICAL


def test_dedup_key_ignores_scheme_case_trailing_slash_and_query():
    a = _finding(url="https://Example.com/login/?a=1").finalize()
    b = _finding(url="https://example.com/login").finalize()
    assert a.dedup_key == b.dedup_key


def test_dedup_key_distinguishes_parameters():
    a = _finding(url="https://example.com/search", parameter="q").finalize()
    b = _finding(url="https://example.com/search", parameter="page").finalize()
    assert a.dedup_key != b.dedup_key


def test_dedupe_keeps_highest_risk_and_sorts():
    duplicate_low = _finding(confidence=2, url="https://example.com/")
    duplicate_high = _finding(confidence=10, url="https://example.com/")
    other = _finding(check_id="venom.tls.expired", severity=Severity.HIGH, confidence=10).finalize()

    result = dedupe_findings([duplicate_low, other, duplicate_high])
    assert len(result) == 2
    assert result[0].risk_score >= result[1].risk_score
    csp = next(f for f in result if f.check_id == "venom.headers.csp")
    assert csp.confidence == 10
    assert all(f.dedup_key for f in result)


def test_default_verification_status_is_suspected():
    assert _finding().verification_status is VerificationStatus.SUSPECTED


def test_endpoint_state_separates_live_from_unverified_references():
    assert endpoint_state("crawl", 200) == "live"
    assert endpoint_state("crawl", 404) == "live"
    assert endpoint_state("js", None) == "unverified"
    assert endpoint_state("form", None) == "unverified"
    assert endpoint_state("archive", None) == "archived"

    record = EndpointRecord(url="https://example.com/app.js", source="js")
    assert record.state == "unverified"
    assert record.model_dump()["state"] == "unverified"
    assert EndpointRecord(url="https://example.com/", status_code=200).state == "live"
