from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import httpx
import pytest
from venomscan_engine.checks.dom_xss import DomXssCheck, marker_tag
from venomscan_engine.checks.probes import canary, probe_points, with_value
from venomscan_engine.context import ScanContext
from venomscan_engine.events import NullSink
from venomscan_engine.models import EndpointRecord, VerificationStatus
from venomscan_engine.safety.http import SafeHttpClient
from venomscan_engine.safety.scope import Scope

HTML = {"Content-Type": "text/html; charset=utf-8"}


def _page(script: str) -> str:
    return (
        "<!doctype html><html><body><div id='out'>clean</div>"
        f"<script>{script}</script></body></html>"
    )


SINK_INNER_HTML = _page(
    "const v = new URLSearchParams(location.search).get('q') || '';"
    "document.getElementById('out').innerHTML = v;"
    "fetch('/collect', {method: 'POST', body: 'x'}).catch(() => {});"
)
SINK_TEXT_CONTENT = _page(
    "const v = new URLSearchParams(location.search).get('q') || '';"
    "document.getElementById('out').textContent = v;"
)


class _FixtureServer:
    """Read-only local site so the browser has a real origin to visit."""

    def __init__(self, pages: dict[str, str]) -> None:
        self.hits: list[str] = []
        hits = self.hits

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 (stdlib signature)
                path = urlsplit(self.path).path
                hits.append(self.path)
                payload = pages.get(path)
                encoded = (payload or "<html><body>missing</body></html>").encode()
                self.send_response(200 if payload else 404)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, *args) -> None:
                return

            def do_POST(self) -> None:  # noqa: N802 (stdlib signature)
                hits.append(f"POST {self.path}")
                self.send_response(204)
                self.end_headers()

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self.base = f"http://127.0.0.1:{self._server.server_port}"

    def __enter__(self) -> _FixtureServer:
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)


def _context(make_bundle, base: str, path: str) -> ScanContext:
    ctx = ScanContext(
        scan_id="dom-xss-test",
        target_url=f"{base}{path}?q=hello",
        scope=Scope.from_target(base),
        profile="active",
        sink=NullSink(),
        client=None,
        max_seconds=120,
    )
    ctx.root = make_bundle(url=base, headers=HTML)
    ctx.endpoints = [
        EndpointRecord(url=f"{base}{path}?q=hello", method="GET", parameters=["q"], status_code=200)
    ]
    return ctx


def _clean_client(base: str) -> SafeHttpClient:
    async def resolver(host: str, port: int) -> list[str]:
        return ["127.0.0.1"]

    return SafeHttpClient(
        Scope.from_target(base),
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200, headers=HTML, text="<html><body>clean</body></html>"
            )
        ),
        resolver=resolver,
        allow_private=True,
        max_requests=20,
        max_seconds=30,
        rps=100,
    )


async def _require_chromium() -> None:
    pytest.importorskip("playwright.async_api")
    from playwright.async_api import async_playwright

    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            await browser.close()
    except Exception:
        pytest.skip("chromium browser is not installed")


@pytest.mark.asyncio
async def test_dom_xss_flags_html_sink_in_real_browser(make_bundle):
    await _require_chromium()

    with _FixtureServer({"/inner": SINK_INNER_HTML}) as fixture:
        ctx = _context(make_bundle, fixture.base, "/inner")
        async with _clean_client(fixture.base) as client:
            ctx.client = client
            findings = await DomXssCheck().run(ctx)
        visited = list(fixture.hits)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.check_id == "venom.xss.dom"
    assert finding.verification_status is VerificationStatus.VERIFIED
    assert finding.parameter == "q"
    assert finding.response_evidence["sink"] == "html-element-created"
    assert finding.response_evidence["body_stored"] is False
    assert "%3Cvs-canary-" in finding.request_evidence["url"]
    assert any(hit.startswith("/inner?q=") for hit in visited)
    assert not any(hit.startswith("POST") for hit in visited), "browser must not POST"


@pytest.mark.asyncio
async def test_dom_xss_ignores_text_content_sink(make_bundle):
    await _require_chromium()

    with _FixtureServer({"/safe": SINK_TEXT_CONTENT}) as fixture:
        ctx = _context(make_bundle, fixture.base, "/safe")
        async with _clean_client(fixture.base) as client:
            ctx.client = client
            assert await DomXssCheck().run(ctx) == []


@pytest.mark.asyncio
async def test_dom_xss_skips_pages_the_server_reflects(make_bundle, monkeypatch):
    with _FixtureServer({"/inner": SINK_INNER_HTML}) as fixture:
        ctx = _context(make_bundle, fixture.base, "/inner")
        tag = marker_tag(canary(ctx, "venom.xss.dom", "q"))
        ctx.client = httpx.MockTransport(
            lambda request: httpx.Response(
                200, headers=HTML, text=f"<html><body><{tag}></body></html>"
            )
        )

        async def never(*args, **kwargs) -> bool:
            raise AssertionError("browser must not run when the server reflects the marker")

        monkeypatch.setattr(DomXssCheck, "_probe", never)
        assert await DomXssCheck().run(ctx) == []


@pytest.mark.asyncio
async def test_dom_xss_respects_remaining_budget(make_bundle):
    ctx = ScanContext(
        scan_id="dom-xss-budget",
        target_url="https://example.com/?q=x",
        scope=Scope.from_target("https://example.com/"),
        profile="active",
        sink=NullSink(),
        client=None,
        max_seconds=5,
    )
    ctx.root = make_bundle(url="https://example.com/", headers=HTML)
    ctx.endpoints = [
        EndpointRecord(url="https://example.com/?q=x", method="GET", parameters=["q"], status_code=200)
    ]
    assert await DomXssCheck().run(ctx) == []


def test_marker_and_probe_url_are_encoded():
    tag = marker_tag("deadbeef")
    assert tag == "vs-canary-deadbeef"

    ctx = ScanContext(
        scan_id="dom-xss-url",
        target_url="https://example.com/search?q=a&page=2",
        scope=Scope.from_target("https://example.com/"),
        profile="active",
        sink=NullSink(),
        client=None,
        max_seconds=60,
    )
    ctx.endpoints = [
        EndpointRecord(
            url="https://example.com/search?q=a&page=2",
            method="GET",
            parameters=["q", "page"],
            status_code=200,
        )
    ]
    point = probe_points(ctx, 1)[0]
    encoded = with_value(point, f"<{tag}>")
    assert "%3Cvs-canary-deadbeef%3E" in encoded
    assert "page=2" in encoded
