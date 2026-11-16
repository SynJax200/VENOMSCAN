from __future__ import annotations

import re

import httpx
import pytest
from venomscan_engine.checks.xxe import XxeCheck
from venomscan_engine.context import ScanContext
from venomscan_engine.events import CollectingSink, NullSink
from venomscan_engine.models import EndpointRecord, VerificationStatus
from venomscan_engine.oob import OobListener
from venomscan_engine.safety.scope import Scope

XML = {"Content-Type": "application/xml; charset=utf-8"}
_SYSTEM = re.compile(r'SYSTEM "([^"]+)"')


def _context(make_bundle, endpoints: list[EndpointRecord] | None = None) -> ScanContext:
    ctx = ScanContext(
        scan_id="xxe-test",
        target_url="https://example.com/",
        scope=Scope.from_target("https://example.com/"),
        profile="active",
        sink=NullSink(),
        client=None,
        max_seconds=60,
    )
    ctx.root = make_bundle(url="https://example.com/", headers=XML)
    ctx.endpoints = endpoints or [
        EndpointRecord(url="https://example.com/api/xml", method="POST", parameters=["xml"])
    ]
    return ctx


def _parser_handler(seen: list[httpx.Request], *, fetch: bool = True):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        urls = _SYSTEM.findall(request.content.decode("utf-8", "replace"))
        if fetch:
            for url in urls:
                try:
                    httpx.get(url, timeout=2.0, trust_env=False)
                except httpx.HTTPError:
                    pass
        return httpx.Response(200, headers=XML, text="<ok/>")

    return handler


@pytest.mark.asyncio
async def test_xxe_flags_external_entity_callback(make_bundle, client_factory, monkeypatch):
    monkeypatch.setattr("venomscan_engine.checks.xxe.CALLBACK_WAIT_SECONDS", 1.0)
    seen: list[httpx.Request] = []
    with OobListener() as oob:
        ctx = _context(make_bundle)
        ctx.artifacts["oob"] = oob
        async with client_factory(_parser_handler(seen)) as client:
            ctx.client = client
            findings = await XxeCheck().run(ctx)
        assert seen and seen[0].method == "POST"
        assert seen[0].headers["content-type"] == "application/xml"

    assert len(findings) == 1
    finding = findings[0]
    assert finding.check_id == "venom.xxe"
    assert finding.verification_status is VerificationStatus.VERIFIED
    assert finding.method == "POST"
    assert finding.parameter == "body"
    assert finding.response_evidence["external_entity_fetched"] is True
    assert finding.response_evidence["body_stored"] is False
    assert finding.response_evidence["source_ip"] == "127.0.0.1"


@pytest.mark.asyncio
async def test_xxe_stays_quiet_without_callback(make_bundle, client_factory, monkeypatch):
    monkeypatch.setattr("venomscan_engine.checks.xxe.CALLBACK_WAIT_SECONDS", 0.3)
    seen: list[httpx.Request] = []
    with OobListener() as oob:
        ctx = _context(make_bundle)
        ctx.artifacts["oob"] = oob
        async with client_factory(_parser_handler(seen, fetch=False)) as client:
            ctx.client = client
            assert await XxeCheck().run(ctx) == []
        assert len(seen) == 1


@pytest.mark.asyncio
async def test_xxe_skips_without_listener(make_bundle):
    sink = CollectingSink()
    ctx = _context(make_bundle)
    ctx.sink = sink
    assert await XxeCheck().run(ctx) == []
    assert any(event.type == "warning" and "XXE skipped" in event.message for event in sink.events)


@pytest.mark.asyncio
async def test_xxe_ignores_non_xml_endpoints(make_bundle, client_factory):
    ctx = _context(
        make_bundle,
        [
            EndpointRecord(url="https://example.com/search?q=hello", method="GET", parameters=["q"]),
            EndpointRecord(url="https://example.com/api/save", method="POST", parameters=["json"]),
            EndpointRecord(url="https://other.test/api/xml", method="POST", parameters=["xml"]),
        ],
    )
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, headers=XML, text="ok")

    with OobListener() as oob:
        ctx.artifacts["oob"] = oob
        async with client_factory(handler) as client:
            ctx.client = client
            assert await XxeCheck().run(ctx) == []
    assert called is False


@pytest.mark.asyncio
async def test_xxe_respects_endpoint_cap(make_bundle, client_factory, monkeypatch):
    monkeypatch.setattr("venomscan_engine.checks.xxe.CALLBACK_WAIT_SECONDS", 0.2)
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, headers=XML, text="ok")

    ctx = _context(
        make_bundle,
        [
            EndpointRecord(url=f"https://example.com/xml/{i}", method="POST", parameters=["xml"])
            for i in range(5)
        ],
    )
    with OobListener() as oob:
        ctx.artifacts["oob"] = oob
        async with client_factory(handler) as client:
            ctx.client = client
            assert await XxeCheck().run(ctx) == []
    assert calls == 2


@pytest.mark.asyncio
async def test_xxe_stops_when_budget_is_low(make_bundle):
    ctx = ScanContext(
        scan_id="xxe-budget",
        target_url="https://example.com/",
        scope=Scope.from_target("https://example.com/"),
        profile="active",
        sink=NullSink(),
        client=None,
        max_seconds=5,
    )
    ctx.root = make_bundle(url="https://example.com/", headers=XML)
    ctx.endpoints = [
        EndpointRecord(url="https://example.com/api/xml", method="POST", parameters=["xml"])
    ]
    with OobListener() as oob:
        ctx.artifacts["oob"] = oob
        assert await XxeCheck().run(ctx) == []
