from __future__ import annotations

from venomscan_engine.correlate import correlate_findings
from venomscan_engine.models import Finding, Severity


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
    return Finding(**data).finalize()


def test_no_chain_without_both_sides_of_the_rule():
    only_injection = [_finding(check_id="venom.sqli.error", severity=Severity.HIGH)]
    report = correlate_findings(only_injection)
    assert report.chains == []
    assert report.boosted == 0
    assert report.as_dict()["max_multiplier"] == 1.0


def test_auth_and_injection_form_a_chain_and_boost_the_trigger():
    session = _finding(check_id="venom.session", severity=Severity.MEDIUM)
    injection = _finding(check_id="venom.sqli.error", severity=Severity.HIGH)
    baseline = injection.risk_score

    report = correlate_findings([session, injection])

    assert [c.rule_id for c in report.chains] == ["credentialed-injection"]
    assert report.boosted == 1
    assert injection.risk_score == round(min(baseline * 1.25, 10.0), 2)
    assert report.chains[0].gate is session
    assert report.chains[0].triggers == [injection]
    payload = report.as_dict()
    assert payload["chains"][0]["rule_id"] == "credentialed-injection"
    assert payload["max_multiplier"] == 1.25


def test_admin_surface_rule_requires_an_admin_url():
    authz = _finding(check_id="venom.authz.function", severity=Severity.HIGH)
    injection = _finding(
        check_id="venom.xss.reflected",
        severity=Severity.HIGH,
        url="https://example.com/admin/users?q=1",
    )
    report = correlate_findings([authz, injection])
    assert "admin-surface" in {c.rule_id for c in report.chains}
    assert report.boosted == 1

    plain = _finding(
        check_id="venom.xss.reflected",
        severity=Severity.HIGH,
        url="https://example.com/search?q=1",
    )
    report = correlate_findings([authz, plain])
    assert "admin-surface" not in {c.rule_id for c in report.chains}


def test_unauth_api_rule_needs_api_route_and_gate():
    cors = _finding(check_id="venom.cors.misconfig", severity=Severity.LOW)
    leak = _finding(
        check_id="venom.api.sensitive",
        severity=Severity.MEDIUM,
        url="https://example.com/api/v1/orders",
    )
    report = correlate_findings([cors, leak])
    assert [c.rule_id for c in report.chains] == ["unauth-api"]
    assert report.boosted == 1
    assert leak.risk_score == round(min(5.5 * (0.6 + 0.4 * 0.9) * 1.15, 10.0), 2)


def test_secret_chain_and_strongest_multiplier_wins_without_double_boost():
    secrets = _finding(check_id="venom.secrets.js", severity=Severity.MEDIUM)
    errors = _finding(check_id="venom.info.errors", severity=Severity.MEDIUM)

    report = correlate_findings([secrets, errors])
    rules = {c.rule_id for c in report.chains}
    assert "secret-exposure-chain" in rules
    assert report.boosted == 1

    # Two chains touching one finding must apply only the strongest multiplier once.
    injection = _finding(check_id="venom.sqli.error", severity=Severity.HIGH)
    before = injection.risk_score
    report = correlate_findings([secrets, errors, _finding(check_id="venom.session"), injection])
    assert report.boosted == 2
    # session -> credentialed-injection (1.25), the only chain touching the injection.
    assert injection.risk_score == round(min(before * 1.25, 10.0), 2)


def test_boost_can_raise_severity_band():
    session = _finding(check_id="venom.session", severity=Severity.MEDIUM, confidence=10)
    injection = _finding(
        check_id="venom.sqli.error", severity=Severity.HIGH, confidence=10, cvss_score=7.5
    )
    assert injection.severity is Severity.HIGH
    correlate_findings([session, injection])
    assert injection.risk_score == 9.38
    assert injection.severity is Severity.CRITICAL
