from __future__ import annotations

import httpx
import pytest
from venomscan_engine.checks.authz import FunctionAuthzCheck, IdorCheck
from venomscan_engine.context import ScanContext
from venomscan_engine.events import CollectingSink, NullSink
from venomscan_engine.models import EndpointRecord, VerificationStatus
from venomscan_engine.safety.scope import Scope

HTML = {"Content-Type": "text/html; charset=utf-8"}
ACCOUNTS = [
    {
        "label": "alice",
        "role": "user",
        "identity": "alice@demo.test",
        "headers": {"X-User": "alice"},
    },
    {
        "label": "bob",
        "role": "user",
        "identity": "bob@demo.test",
        "headers": {"X-User": "bob"},
    },
]


def _context(make_bundle, endpoints: list[EndpointRecord], accounts: list[dict] | None = None):
    ctx = ScanContext(
        scan_id="authz-test",
        target_url="https://example.com/",
        scope=Scope.from_target("https://example.com/"),
        profile="active",
        sink=NullSink(),
        client=None,
        max_seconds=60,
    )
    ctx.root = make_bundle(url="https://example.com/", headers=HTML)
    ctx.endpoints = endpoints
    ctx.artifacts["accounts"] = ACCOUNTS if accounts is None else accounts
    return ctx


@pytest.mark.asyncio
async def test_idor_flags_cross_account_object_read(make_bundle, client_factory):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/orders/1":
            return httpx.Response(
                200,
                json={"order": 1, "owner": "alice@demo.test", "total": 42},
            )
        return httpx.Response(404, json={"error": "not found"})

    ctx = _context(
        make_bundle,
        [EndpointRecord(url="https://example.com/api/orders/1", method="GET", status_code=200)],
    )
    async with client_factory(handler) as client:
        ctx.client = client
        findings = await IdorCheck().run(ctx)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.check_id == "venom.idor"
    assert finding.verification_status is VerificationStatus.VERIFIED
    assert finding.severity.value == "high"
    assert finding.response_evidence["identity_exposed_to_other"] is True
    assert finding.response_evidence["body_stored"] is False
    assert finding.response_evidence["owner_status"] == 200
    assert finding.response_evidence["other_status"] == 200


@pytest.mark.asyncio
async def test_idor_stays_quiet_when_objects_are_scoped(make_bundle, client_factory):
    def handler(request: httpx.Request) -> httpx.Response:
        account = request.headers.get("X-User", "")
        return httpx.Response(200, json={"owner": f"{account}@demo.test"})

    ctx = _context(
        make_bundle,
        [EndpointRecord(url="https://example.com/api/orders/1", method="GET", status_code=200)],
    )
    async with client_factory(handler) as client:
        ctx.client = client
        assert await IdorCheck().run(ctx) == []


@pytest.mark.asyncio
async def test_idor_warns_without_two_accounts(make_bundle):
    sink = CollectingSink()
    ctx = _context(
        make_bundle,
        [EndpointRecord(url="https://example.com/api/orders/1", method="GET", status_code=200)],
        accounts=ACCOUNTS[:1],
    )
    ctx.sink = sink
    assert await IdorCheck().run(ctx) == []
    assert any(event.type == "warning" and "IDOR skipped" in event.message for event in sink.events)


@pytest.mark.asyncio
async def test_idor_ignores_endpoints_without_object_ids(make_bundle, client_factory):
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={"owner": "alice@demo.test"})

    ctx = _context(
        make_bundle,
        [
            EndpointRecord(url="https://example.com/about", method="GET", status_code=200),
            EndpointRecord(url="https://example.com/api/orders", method="POST", status_code=200),
        ],
    )
    async with client_factory(handler) as client:
        ctx.client = client
        assert await IdorCheck().run(ctx) == []
    assert called is False


@pytest.mark.asyncio
async def test_idor_stops_when_budget_is_low(make_bundle):
    ctx = ScanContext(
        scan_id="idor-budget",
        target_url="https://example.com/",
        scope=Scope.from_target("https://example.com/"),
        profile="active",
        sink=NullSink(),
        client=None,
        max_seconds=5,
    )
    ctx.root = make_bundle(url="https://example.com/", headers=HTML)
    ctx.endpoints = [EndpointRecord(url="https://example.com/api/orders/1", method="GET", status_code=200)]
    ctx.artifacts["accounts"] = ACCOUNTS
    assert await IdorCheck().run(ctx) == []


@pytest.mark.asyncio
async def test_function_authz_flags_privileged_page(make_bundle, client_factory):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers=HTML,
            text="<html><body><h1>Admin console</h1><p>Rotate keys</p></body></html>",
        )

    ctx = _context(
        make_bundle, [EndpointRecord(url="https://example.com/admin", method="GET", status_code=200)]
    )
    async with client_factory(handler) as client:
        ctx.client = client
        findings = await FunctionAuthzCheck().run(ctx)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.check_id == "venom.authz.function"
    assert finding.verification_status is VerificationStatus.SUSPECTED
    assert finding.response_evidence["login_page_detected"] is False
    assert finding.request_evidence["role"] == "user"


@pytest.mark.asyncio
async def test_function_authz_skips_login_pages(make_bundle, client_factory):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers=HTML,
            text='<html><body><form><input type="password" name="pw"></form></body></html>',
        )

    ctx = _context(
        make_bundle, [EndpointRecord(url="https://example.com/admin", method="GET", status_code=200)]
    )
    async with client_factory(handler) as client:
        ctx.client = client
        assert await FunctionAuthzCheck().run(ctx) == []


@pytest.mark.asyncio
async def test_function_authz_accepts_403(make_bundle, client_factory):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": "forbidden"})

    ctx = _context(
        make_bundle, [EndpointRecord(url="https://example.com/admin/users", method="GET", status_code=200)]
    )
    async with client_factory(handler) as client:
        ctx.client = client
        assert await FunctionAuthzCheck().run(ctx) == []


@pytest.mark.asyncio
async def test_function_authz_warns_without_accounts(make_bundle):
    sink = CollectingSink()
    ctx = _context(
        make_bundle,
        [EndpointRecord(url="https://example.com/admin", method="GET", status_code=200)],
        accounts=[],
    )
    ctx.sink = sink
    assert await FunctionAuthzCheck().run(ctx) == []
    assert any(
        event.type == "warning" and "authorization skipped" in event.message
        for event in sink.events
    )
