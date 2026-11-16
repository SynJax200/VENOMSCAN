from __future__ import annotations

import httpx
import pytest
from venomscan_engine.checks import all_check_ids, checks_for_profile
from venomscan_engine.control import ScanCancelled
from venomscan_engine.events import CollectingSink
from venomscan_engine.models import VerificationStatus
from venomscan_engine.pipeline import run_scan
from venomscan_engine.safety.scope import ScopeViolation


def _handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200,
        headers={
            "Content-Type": "text/html; charset=utf-8",
            "Server": "nginx/1.24.0",
            "Set-Cookie": "session_id=abc123; Path=/",
        },
        text="<html><body><h1>Welcome</h1></body></html>",
    )


def test_registry_filters_by_profile():
    passive_ids = [cls.id for cls in checks_for_profile("passive")]
    active_ids = [cls.id for cls in checks_for_profile("active")]
    assert set(passive_ids) <= set(active_ids)
    assert passive_ids == sorted(passive_ids)
    assert "venom.headers.missing" in all_check_ids()


@pytest.mark.asyncio
async def test_pipeline_produces_verified_findings(public_resolver):
    sink = CollectingSink()
    result = await run_scan(
        "scan-test",
        "http://example.com/",
        profile="safe",
        sink=sink,
        transport=httpx.MockTransport(_handler),
        resolver=public_resolver,
        enable_dns=False,
        enable_osint=False,
        max_requests=40,
        max_seconds=20,
        rps=100,
    )

    assert result.stats.requests >= 1
    assert result.stats.findings_total == len(result.findings)
    assert result.findings, "expected at least one passive finding"
    assert all(f.verification_status is VerificationStatus.VERIFIED for f in result.findings)
    verification = result.recon["verification"]
    assert verification["verified"] == len(result.findings)
    assert verification["downgraded"] == 0
    assert all(f.dedup_key for f in result.findings)
    assert [f.risk_score for f in result.findings] == sorted(
        (f.risk_score for f in result.findings), reverse=True
    )

    check_ids = {f.check_id for f in result.findings}
    assert {"venom.transport.plaintext", "venom.cookies.flags", "venom.headers.csp"} <= check_ids
    assert {"Nginx"} <= {t.name for t in result.technologies}
    assert result.endpoints[0].url == "http://example.com/"
    assert result.endpoints[0].state == "live"
    assert result.stats.endpoints_live + result.stats.endpoints_unverified == result.stats.endpoints

    phases = [event.phase for event in sink.events]
    assert phases[0] == "authorizing"
    assert "recon" in phases and "analyzing" in phases and "reporting" in phases
    completed = sink.events[-1]
    assert completed.type == "scan_completed"
    assert completed.progress == 100


@pytest.mark.asyncio
async def test_pipeline_rejects_unknown_profile(public_resolver):
    with pytest.raises(ValueError):
        await run_scan(
            "scan-bad",
            "http://example.com/",
            profile="turbo",
            transport=httpx.MockTransport(_handler),
            resolver=public_resolver,
            enable_dns=False,
            enable_osint=False,
        )


@pytest.mark.asyncio
async def test_pipeline_requires_consent_for_active_profile(public_resolver):
    with pytest.raises(PermissionError):
        await run_scan(
            "scan-active",
            "http://example.com/",
            profile="active",
            transport=httpx.MockTransport(_handler),
            resolver=public_resolver,
            enable_dns=False,
            enable_osint=False,
        )


@pytest.mark.asyncio
async def test_pipeline_records_waf_and_osint(public_resolver):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "Content-Type": "text/html; charset=utf-8",
                "Server": "nginx/1.24.0",
                "CF-RAY": "8f2c1a-LHR",
            },
            text="<html><body>edge</body></html>",
        )

    def osint(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host == "crt.sh":
            return httpx.Response(200, json=[{"name_value": "api.example.com\n*.example.com"}])
        if host == "data.iana.org":
            return httpx.Response(
                200, json={"services": [[["com"], ["https://rdap.registry.example/v1/"]]]}
            )
        return httpx.Response(200, json={"ldhName": "EXAMPLE.COM", "status": ["active"]})

    sink = CollectingSink()
    result = await run_scan(
        "scan-osint",
        "http://example.com/",
        sink=sink,
        transport=httpx.MockTransport(handler),
        resolver=public_resolver,
        enable_dns=False,
        enable_osint=True,
        osint_transport=httpx.MockTransport(osint),
        max_requests=40,
        max_seconds=30,
        rps=100,
    )

    assert result.recon["waf"]["detected"] is True
    assert result.recon["waf"]["vendors"][0]["name"] == "Cloudflare"
    assert result.recon["subdomains"]["names"] == ["api.example.com"]
    assert result.recon["whois"]["domain"] == "example.com"
    assert result.recon["whois"]["error"] is None
    api_intel = result.recon["api_intel"]
    assert set(api_intel) == {"spec", "jwt", "graphql"}
    assert api_intel["spec"]["documents"] == 0
    assert api_intel["graphql"]["candidates"] == []
    event_types = {event.type for event in sink.events}
    assert {"waf_detected", "subdomains", "whois"} <= event_types


@pytest.mark.asyncio
async def test_pipeline_fails_closed_on_scope_violation(public_resolver):
    def redirector(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "https://evil.test/"})

    with pytest.raises(ScopeViolation):
        await run_scan(
            "scan-redirect",
            "http://example.com/",
            transport=httpx.MockTransport(redirector),
            resolver=public_resolver,
            enable_dns=False,
            enable_osint=False,
            max_requests=5,
            max_seconds=10,
            rps=100,
        )


@pytest.mark.asyncio
async def test_pipeline_honours_cancel_check(public_resolver):
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, headers={"Content-Type": "text/html"}, text="<html>ok</html>")

    def cancel() -> bool:
        return calls["n"] >= 2

    with pytest.raises(ScanCancelled):
        await run_scan(
            "scan-cancel",
            "http://example.com/",
            transport=httpx.MockTransport(handler),
            resolver=public_resolver,
            enable_dns=False,
            enable_osint=False,
            max_requests=20,
            max_seconds=10,
            rps=100,
            cancel_check=cancel,
        )
    assert calls["n"] <= 3
