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


async def _serve(payloads: dict[str, tuple[int, bytes, dict[str, str]]]) -> tuple[object, int]:
    """Minimal one-shot-per-request HTTP server for pinning tests."""
    import asyncio

    async def handle(reader, writer) -> None:
        raw = await reader.readuntil(b"\r\n\r\n")
        path = raw.split(b" ")[1].decode("latin-1")
        status, body, headers = payloads.get(path, (404, b"missing", {}))
        head = f"HTTP/1.1 {status} X\r\nContent-Length: {len(body)}\r\nConnection: close\r\n"
        head += "".join(f"{key}: {value}\r\n" for key, value in headers.items())
        writer.write(head.encode("latin-1") + b"\r\n" + body)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


@pytest.mark.asyncio
async def test_pinned_backend_rewrites_host_to_validated_address():
    from venomscan_engine.safety.http import _PinnedNetworkBackend

    class FakeInner:
        def __init__(self) -> None:
            self.calls: list[tuple[str, int]] = []

        async def connect_tcp(self, host, port, **kwargs):
            self.calls.append((host, port))
            return "stream"

    backend = _PinnedNetworkBackend({"example.com": "93.184.216.34"})
    backend._inner = FakeInner()
    assert await backend.connect_tcp("example.com", 443) == "stream"
    assert await backend.connect_tcp("other.test", 80) == "stream"
    assert backend._inner.calls == [("93.184.216.34", 443), ("other.test", 80)]


@pytest.mark.asyncio
async def test_client_dials_pinned_ip_and_never_re_resolves():
    # "pinned.test" has no real DNS record; only the pin can reach the server.
    server, port = await _serve({"/": (200, b"pinned", {})})

    async def resolver(host: str, port_arg: int) -> list[str]:
        return ["127.0.0.1"]

    client = SafeHttpClient(
        Scope(hosts=frozenset({"pinned.test"})),
        resolver=resolver,
        allow_private=True,
        max_requests=5,
        max_seconds=10,
        rps=100,
    )
    try:
        async with client:
            bundle = await client.get(f"http://pinned.test:{port}/")
        assert bundle.status_code == 200
        assert bundle.body == "pinned"
        assert client._pins == {"pinned.test": "127.0.0.1"}
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_redirect_host_is_validated_and_pinned_before_connecting():
    import asyncio

    port = 0

    async def handle(reader, writer) -> None:
        raw = await reader.readuntil(b"\r\n\r\n")
        path = raw.split(b" ")[1].decode("latin-1")
        if path == "/":
            status, body, headers = 302, b"", {"Location": f"http://next.test:{port}/final"}
        else:
            status, body, headers = 200, b"final", {}
        head = f"HTTP/1.1 {status} X\r\nContent-Length: {len(body)}\r\nConnection: close\r\n"
        head += "".join(f"{key}: {value}\r\n" for key, value in headers.items())
        writer.write(head.encode("latin-1") + b"\r\n" + body)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    async def resolver(host: str, port_arg: int) -> list[str]:
        return ["127.0.0.1"]

    client = SafeHttpClient(
        Scope(hosts=frozenset({"pinned.test", "next.test"})),
        resolver=resolver,
        allow_private=True,
        max_requests=5,
        max_seconds=10,
        rps=100,
    )
    try:
        async with client:
            bundle = await client.get(f"http://pinned.test:{port}/")
        assert bundle.url == f"http://next.test:{port}/final"
        assert bundle.body == "final"
        assert client._pins == {"pinned.test": "127.0.0.1", "next.test": "127.0.0.1"}
    finally:
        server.close()
        await server.wait_closed()
