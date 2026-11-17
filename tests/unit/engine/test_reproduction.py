from __future__ import annotations

import json

from venomscan_engine.checks import check_catalog
from venomscan_engine.reports import ReportFinding, reproduction_steps


def _finding(**overrides) -> ReportFinding:
    base = {
        "id": "f1",
        "check_id": "venom.headers.csp",
        "title": "Example finding",
        "category": "config",
        "severity": "medium",
        "verification_status": "verified",
        "confidence": 8,
        "risk_score": 5.0,
        "url": "https://demo.example.test/",
        "description": "Observed behaviour.",
        "impact": "Impact.",
        "remediation": "Fix it.",
    }
    base.update(overrides)
    return ReportFinding(**base)


def test_every_registered_check_produces_reproduction_steps() -> None:
    for entry in check_catalog():
        steps = reproduction_steps(_finding(check_id=entry["id"]))
        assert len(steps) >= 2, entry["id"]
        assert all(step.strip() for step in steps), entry["id"]


def test_header_steps_name_the_header_probe() -> None:
    steps = reproduction_steps(_finding(check_id="venom.headers.csp"))
    assert "curl -sS -D - -o /dev/null 'https://demo.example.test/'" in steps[0]
    assert "Content-Security-Policy" in steps[1]


def test_hardening_steps_list_all_hardening_headers() -> None:
    text = " ".join(reproduction_steps(_finding(check_id="venom.headers.hardening")))
    for header in (
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "Cross-Origin-Opener-Policy",
    ):
        assert header in text


def test_cors_steps_use_recorded_canary_origin() -> None:
    finding = _finding(
        check_id="venom.cors.misconfig",
        request_evidence={"origin": "https://canary.example"},
        response_evidence={
            "access_control_allow_origin": "https://canary.example",
            "access_control_allow_credentials": True,
        },
    )
    steps = reproduction_steps(finding)
    assert "Origin: https://canary.example" in steps[0]
    assert "Access-Control-Allow-Origin: https://canary.example" in steps[1]
    assert "Access-Control-Allow-Credentials: true" in steps[1]


def test_tls_steps_use_openssl_against_the_right_port() -> None:
    steps = reproduction_steps(_finding(check_id="venom.tls.expired", url="https://demo.example.test:8443/"))
    assert steps[0] == (
        "Connect to the TLS endpoint: openssl s_client -connect demo.example.test:8443 "
        "-servername demo.example.test </dev/null"
    )
    assert "past" in steps[1]


def test_idor_steps_reference_both_account_labels() -> None:
    finding = _finding(
        check_id="venom.idor",
        request_evidence={"as_owner": "account A", "as_other": "account B"},
    )
    text = " ".join(reproduction_steps(finding))
    assert "account A" in text
    assert "account B" in text
    assert "403/404" in text


def test_post_findings_replay_with_post() -> None:
    steps = reproduction_steps(
        _finding(check_id="venom.api.sensitive", method="POST")
    )
    assert any("curl -sS -X POST" in step for step in steps)


def test_reproduction_round_trips_through_json() -> None:
    finding = _finding()
    finding.reproduction = reproduction_steps(finding)
    payload = json.loads(finding.model_dump_json())
    assert payload["reproduction"] == finding.reproduction
