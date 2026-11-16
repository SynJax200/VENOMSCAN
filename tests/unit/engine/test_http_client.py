from __future__ import annotations

import httpx
import pytest
from venomscan_engine.control import ScanCancelled
from venomscan_engine.safety.http import (
    BudgetExceeded,
    SafeHttpClient,
    TargetUnreachable,
    TooManyRedirects,
)
from venomscan_engine.safety.scope import Scope, ScopeViolation
from venomscan_engine.safety.ssrf import SSRFBlocked


@pytest.mark.asyncio
async def test_get_returns_bundle_with_lowercase_headers(client_factory):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"Content-Type": "text/html", "Set-Cookie": "a=1; Secure"}, text="ok"
        )

    async with client_factory(handler) as client:
        bundle = await client.get("https://example.com/")

    assert bundle.status_code == 200
    assert bundle.header("content-type") == "text/html"
    assert bundle.set_cookies == ["a=1; Secure"]
    assert client.request_count == 1


@pytest.mark.asyncio
async def test_redirects_within_scope_are_followed(client_factory):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(302, headers={"Location": "/login"})
        return httpx.Response(200, text="login page")

    async with client_factory(handler) as client:
        bundle = await client.get("https://example.com/")

    assert bundle.url == "https://example.com/login"
    assert bundle.redirect_chain == ["https://example.com/"]
    assert bundle.status_code == 200


@pytest.mark.asyncio
async def test_redirect_out_of_scope_is_blocked_before_request(client_factory):
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(302, headers={"Location": "https://evil.test/steal"})

    async with client_factory(handler) as client:
        with pytest.raises(ScopeViolation):
            await client.get("https://example.com/")

    assert seen == ["https://example.com/"]
    assert client.request_count == 1


@pytest.mark.asyncio
async def test_redirect_to_metadata_ip_is_blocked(public_resolver):
    # Even if a host is in the allowlist, SSRF rules still reject metadata ranges.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})

    scope = Scope(hosts=frozenset({"example.com", "169.254.169.254"}))
    client = SafeHttpClient(
        scope,
        transport=httpx.MockTransport(handler),
        resolver=public_resolver,
        max_requests=5,
        max_seconds=10,
        rps=100,
    )
    async with client:
        with pytest.raises(SSRFBlocked):
            await client.get("https://example.com/")


@pytest.mark.asyncio
async def test_redirect_loop_hits_limit(client_factory):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": request.url.path})

    async with client_factory(handler) as client:
        with pytest.raises(TooManyRedirects):
            await client.get("https://example.com/")


@pytest.mark.asyncio
async def test_request_budget_enforced(client_factory):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    async with client_factory(handler, max_requests=1) as client:
        await client.get("https://example.com/")
        with pytest.raises(BudgetExceeded):
            await client.get("https://example.com/two")


@pytest.mark.asyncio
async def test_network_error_wrapped_as_target_unreachable(client_factory):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    async with client_factory(handler) as client:
        with pytest.raises(TargetUnreachable):
            await client.get("https://example.com/")


@pytest.mark.asyncio
async def test_client_requires_context_manager():
    client = SafeHttpClient(Scope.from_target("https://example.com"))
    with pytest.raises(RuntimeError):
        await client.get("https://example.com/")


@pytest.mark.asyncio
async def test_cancelled_scan_blocks_new_requests(client_factory):
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, text="ok")

    async with client_factory(handler, cancel_check=lambda: True) as client:
        with pytest.raises(ScanCancelled):
            await client.get("https://example.com/")
        assert client.request_count == 0
    assert calls == []


@pytest.mark.asyncio
async def test_raw_body_is_forwarded_and_dropped_on_redirect(client_factory):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/submit":
            return httpx.Response(303, headers={"Location": "/done"})
        return httpx.Response(200, text="ok")

    async with client_factory(handler) as client:
        await client.request(
            "POST",
            "https://example.com/submit",
            headers={"Content-Type": "application/xml"},
            content="<note>hi</note>",
        )

    assert seen[0].method == "POST"
    assert seen[0].content == b"<note>hi</note>"
    assert seen[1].method == "GET"
    assert seen[1].content == b""
