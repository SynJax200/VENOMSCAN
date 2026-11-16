from __future__ import annotations

import httpx
import pytest
from venomscan_engine.checks.ssrf import SsrfCheck
from venomscan_engine.context import ScanContext
from venomscan_engine.events import CollectingSink, NullSink
from venomscan_engine.models import EndpointRecord, VerificationStatus
from venomscan_engine.oob import OobListener
from venomscan_engine.safety.scope import Scope

HTML = {"Content-Type": "text/html; charset=utf-8"}


def _context(make_bundle, url: str = "https://example.com/fetch?url=https://example.com/a"):
    ctx = ScanContext(
        scan_id="ssrf-test",
        target_url="https://example.com/",
        scope=Scope.from_target("https://example.com/"),
        profile="active",
        sink=NullSink(),
        client=None,
        max_seconds=60,
    )
    ctx.root = make_bundle(url="https://example.com/", headers=HTML)
    ctx.endpoints = [EndpointRecord(url=url, method="GET", parameters=["url"], status_code=200)]
    return ctx


def _fetching_handler(seen: list[str], *, fetch: bool = True):
    def handler(request: httpx.Request) -> httpx.Response:
        callback = request.url.params.get("url", "")
        seen.append(callback)
        if fetch and callback.startswith(("http://", "https://")):
            try:
                httpx.get(callback, timeout=2.0, trust_env=False)
            except httpx.HTTPError:
                pass
        return httpx.Response(200, headers=HTML, text="<html><body>ok</body></html>")

    return handler


@pytest.mark.asyncio
async def test_ssrf_flags_out_of_band_callback(make_bundle, client_factory, monkeypatch):
    monkeypatch.setattr("venomscan_engine.checks.ssrf.CALLBACK_WAIT_SECONDS", 1.0)
    seen: list[str] = []
    with OobListener() as oob:
        ctx = _context(make_bundle)
        ctx.artifacts["oob"] = oob
        async with client_factory(_fetching_handler(seen)) as client:
            ctx.client = client
            findings = await SsrfCheck().run(ctx)
        assert seen and seen[0].startswith(oob.base_url)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.check_id == "venom.ssrf"
    assert finding.verification_status is VerificationStatus.VERIFIED
    assert finding.parameter == "url"
    assert finding.response_evidence["callback_received"] is True
    assert finding.response_evidence["body_stored"] is False
    assert finding.response_evidence["source_ip"] == "127.0.0.1"
    assert "vs-canary" not in finding.response_evidence["callback_path"]


@pytest.mark.asyncio
async def test_ssrf_stays_quiet_without_callback(make_bundle, client_factory, monkeypatch):
    monkeypatch.setattr("venomscan_engine.checks.ssrf.CALLBACK_WAIT_SECONDS", 0.3)
    seen: list[str] = []
    with OobListener() as oob:
        ctx = _context(make_bundle)
        ctx.artifacts["oob"] = oob
        async with client_factory(_fetching_handler(seen, fetch=False)) as client:
            ctx.client = client
            assert await SsrfCheck().run(ctx) == []
        assert len(seen) == 1


@pytest.mark.asyncio
async def test_ssrf_skips_without_listener(make_bundle):
    sink = CollectingSink()
    ctx = _context(make_bundle)
    ctx.sink = sink
    assert await SsrfCheck().run(ctx) == []
    assert any(event.type == "warning" and "SSRF skipped" in event.message for event in sink.events)


@pytest.mark.asyncio
async def test_ssrf_ignores_non_url_parameters(make_bundle, client_factory):
    ctx = _context(make_bundle, "https://example.com/search?q=hello")
    ctx.endpoints = [
        EndpointRecord(url="https://example.com/search?q=hello", method="GET", parameters=["q"], status_code=200),
        EndpointRecord(
            url="https://example.com/profile?token=abc",
            method="GET",
            parameters=["token"],
            status_code=200,
        ),
        EndpointRecord(url="https://example.com/save?url=x", method="POST", parameters=["url"], status_code=200),
    ]
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, headers=HTML, text="ok")

    with OobListener() as oob:
        ctx.artifacts["oob"] = oob
        async with client_factory(handler) as client:
            ctx.client = client
            assert await SsrfCheck().run(ctx) == []
    assert called is False


@pytest.mark.asyncio
async def test_ssrf_accepts_url_shaped_value(make_bundle, client_factory, monkeypatch):
    monkeypatch.setattr("venomscan_engine.checks.ssrf.CALLBACK_WAIT_SECONDS", 0.3)
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.params.get("next", ""))
        return httpx.Response(200, headers=HTML, text="ok")

    ctx = _context(make_bundle, "https://example.com/jump?next=https://example.com/landing")
    ctx.endpoints = [
        EndpointRecord(
            url="https://example.com/jump?next=https://example.com/landing",
            method="GET",
            parameters=["next"],
            status_code=200,
        )
    ]
    with OobListener() as oob:
        base = oob.base_url
        ctx.artifacts["oob"] = oob
        async with client_factory(handler) as client:
            ctx.client = client
            await SsrfCheck().run(ctx)
    assert base and seen and seen[0].startswith(base)


@pytest.mark.asyncio
async def test_ssrf_respects_endpoint_cap(make_bundle, client_factory, monkeypatch):
    monkeypatch.setattr("venomscan_engine.checks.ssrf.CALLBACK_WAIT_SECONDS", 0.2)
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, headers=HTML, text="ok")

    ctx = _context(make_bundle)
    ctx.endpoints = [
        EndpointRecord(url=f"https://example.com/f{i}?url=https://example.com/x", method="GET", status_code=200)
        for i in range(6)
    ]
    with OobListener() as oob:
        ctx.artifacts["oob"] = oob
        async with client_factory(handler) as client:
            ctx.client = client
            assert await SsrfCheck().run(ctx) == []
    assert calls == 2


@pytest.mark.asyncio
async def test_ssrf_stops_when_budget_is_low(make_bundle):
    ctx = ScanContext(
        scan_id="ssrf-budget",
        target_url="https://example.com/",
        scope=Scope.from_target("https://example.com/"),
        profile="active",
        sink=NullSink(),
        client=None,
        max_seconds=5,
    )
    ctx.root = make_bundle(url="https://example.com/", headers=HTML)
    ctx.endpoints = [EndpointRecord(url="https://example.com/f?url=x", method="GET", status_code=200)]
    with OobListener() as oob:
        ctx.artifacts["oob"] = oob
        assert await SsrfCheck().run(ctx) == []
