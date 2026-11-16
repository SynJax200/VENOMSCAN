from __future__ import annotations

from venomscan_engine.recon.waf import detect_waf
from venomscan_engine.safety.http import ResponseBundle


def _bundle(
    headers: dict[str, str] | None = None, cookies: list[str] | None = None
) -> ResponseBundle:
    return ResponseBundle(
        url="https://shop.example.com/",
        status_code=200,
        headers={key.lower(): value for key, value in (headers or {}).items()},
        body="",
        elapsed_ms=12,
        size=0,
        set_cookies=cookies or [],
    )


def test_detects_cloudflare_from_headers_and_server():
    report = detect_waf(
        _bundle({"Server": "cloudflare", "CF-RAY": "8f2c1a-LHR", "CF-Cache-Status": "HIT"})
    )
    assert report.detected
    assert report.vendors[0].name == "Cloudflare"
    assert report.vendors[0].category == "cdn"
    assert report.vendors[0].confidence >= 0.9
    assert len(report.vendors[0].evidence) >= 2


def test_detects_imperva_and_f5_from_cookies():
    report = detect_waf(
        _bundle(cookies=["incap_ses_1234_5678=abc; Path=/", "BIGipServerpool=xyz; Path=/"])
    )
    names = {vendor.name for vendor in report.vendors}
    assert {"Imperva", "F5 BIG-IP"} <= names


def test_clean_response_has_no_vendor():
    report = detect_waf(_bundle({"Server": "nginx/1.24.0"}))
    assert report.detected is False
    assert report.as_dict()["vendors"] == []
    assert "No WAF" in report.summary()
