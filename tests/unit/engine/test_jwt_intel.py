from __future__ import annotations

import base64
import json

from venomscan_engine.intel.jwt import analyze, collect, decode, looks_like_jwt

NOW = 1_700_000_000.0


def _segment(value: dict) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _token(header: dict, claims: dict, signature: str = "signature") -> str:
    return f"{_segment(header)}.{_segment(claims)}.{signature}"


def test_decode_roundtrip_without_verification():
    token = _token({"alg": "HS256", "typ": "JWT"}, {"sub": "42", "exp": NOW + 3600})
    decoded = decode(token)
    assert decoded["header"]["alg"] == "HS256"
    assert decoded["claims"]["sub"] == "42"
    assert looks_like_jwt(token)
    assert decode("not-a-token") is None


def test_alg_none_is_flagged():
    token = _token({"alg": "none"}, {"sub": "1"}, signature="")
    report = analyze(token, location="response body", source="https://api.example.com/me", now=NOW)
    assert "alg_none" in report["flags"]
    assert report["alg"] == "none"


def test_missing_and_long_expiry_are_separated():
    missing = analyze(
        _token({"alg": "HS256"}, {"sub": "1"}),
        location="cookie",
        source="set-cookie",
        now=NOW,
    )
    long_lived = analyze(
        _token({"alg": "HS256"}, {"sub": "1", "exp": NOW + 40 * 86_400}),
        location="cookie",
        source="set-cookie",
        now=NOW,
    )
    fresh = analyze(
        _token({"alg": "HS256"}, {"sub": "1", "exp": NOW + 3600}),
        location="cookie",
        source="set-cookie",
        now=NOW,
    )

    assert "missing_exp" in missing["flags"] and missing["lifetime_days"] is None
    assert "long_lifetime" in long_lived["flags"] and long_lived["lifetime_days"] == 40.0
    assert fresh["flags"] == []
    assert fresh["lifetime_days"] == 0.0


def test_sensitive_claims_are_flagged():
    token = _token({"alg": "HS256"}, {"sub": "1", "refresh_token": "x", "plan": "pro"})
    report = analyze(token, location="response body", source="https://api.example.com/token", now=NOW)
    assert "sensitive_claims" in report["flags"]
    assert "refresh_token" in report["claims"]
    assert report["lifetime_days"] is None


def test_external_key_url_is_flagged_only_for_other_hosts():
    external = analyze(
        _token({"alg": "RS256", "jku": "https://keys.evil.test/jwks.json"}, {"sub": "1"}),
        location="response body",
        source="https://api.example.com/token",
        now=NOW,
    )
    internal = analyze(
        _token({"alg": "RS256", "jku": "https://api.example.com/jwks.json"}, {"sub": "1"}),
        location="response body",
        source="https://api.example.com/token",
        now=NOW,
    )
    assert "external_key_url" in external["flags"]
    assert "external_key_url" not in internal["flags"]


def test_analyze_never_returns_the_raw_token():
    token = _token({"alg": "none"}, {"sub": "1"}, signature="")
    report = analyze(token, location="url query", source=f"https://example.com/cb?t={token}", now=NOW)
    assert "url_exposure" in report["flags"]
    dumped = json.dumps(report)
    assert token not in dumped
    assert report["fingerprint"] and report["prefix"] == token[:10]


def test_collect_harvests_bodies_cookies_and_query_strings():
    body_token = _token({"alg": "HS256"}, {"sub": "body", "exp": NOW + 3600})
    cookie_token = _token({"alg": "HS256"}, {"sub": "cookie", "exp": NOW + 3600})
    query_token = _token({"alg": "HS256"}, {"sub": "query"})
    samples = [
        {
            "url": "https://api.example.com/session",
            "content_type": "application/json",
            "body": json.dumps({"access_token": body_token}),
        },
        {
            "url": "https://api.example.com/session",
            "content_type": "application/json",
            "body": json.dumps({"access_token": body_token}),
        },
    ]

    class Endpoint:
        def __init__(self, url: str) -> None:
            self.url = url

    endpoints = [Endpoint(f"https://api.example.com/callback?state=1&token={query_token}")]
    reports = collect(samples, endpoints, [f"session={cookie_token}; Path=/"], now=NOW)

    locations = {report["location"] for report in reports}
    assert locations == {"response body", "cookie", "url query"}
    assert len(reports) == 3, "duplicate tokens must be collapsed"
    assert all("fingerprint" in report for report in reports)
