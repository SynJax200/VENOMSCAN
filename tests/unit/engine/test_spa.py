from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest
from venomscan_engine.context import ScanContext
from venomscan_engine.crawl.spa import SpaReport, _robots_disallows, capture_spa
from venomscan_engine.events import NullSink
from venomscan_engine.safety.scope import Scope

HTML = {"Content-Type": "text/html; charset=utf-8"}

SPA_PAGE = (
    "<!doctype html><html><body>"
    "<a href='/dashboard'>Dashboard</a>"
    "<script>"
    "fetch('/api/items?limit=5');"
    "fetch('https://example.org/leak');"
    "history.pushState({}, '', '/settings');"
    "</script></body></html>"
)


class _FixtureServer:
    def __init__(self) -> None:
        self.hits: list[str] = []
        hits = self.hits

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 (stdlib signature)
                path = urlsplit(self.path).path
                hits.append(self.path)
                if path == "/api/items":
                    encoded = b'{"items": []}'
                    content_type = "application/json"
                else:
                    encoded = SPA_PAGE.encode()
                    content_type = "text/html; charset=utf-8"
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, *args) -> None:
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> _FixtureServer:
        self._thread.start()
        self.base = f"http://127.0.0.1:{self._server.server_port}"
        return self

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)


def _context(make_bundle, base: str) -> ScanContext:
    ctx = ScanContext(
        scan_id="spa-test",
        target_url=f"{base}/",
        scope=Scope.from_target(base),
        profile="safe",
        sink=NullSink(),
        client=None,
        max_seconds=120,
    )
    ctx.root = make_bundle(url=base)
    return ctx


async def _require_chromium() -> None:
    pytest.importorskip("playwright.async_api")
    from playwright.async_api import async_playwright

    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            await browser.close()
    except Exception:
        pytest.skip("chromium browser is not installed")


def test_spa_report_shape_and_robots_filter(make_bundle):
    ctx = _context(make_bundle, "https://example.com")
    ctx.artifacts["robots"] = {"disallow": ["/private"]}
    assert _robots_disallows(ctx, "https://example.com/private/x")
    assert not _robots_disallows(ctx, "https://example.com/public")
    assert SpaReport().as_dict()["routes"] == 0


@pytest.mark.asyncio
async def test_capture_spa_records_routes_and_xhr_in_scope(make_bundle):
    await _require_chromium()

    with _FixtureServer() as fixture:
        ctx = _context(make_bundle, fixture.base)
        report = await capture_spa(ctx, budget_seconds=45)

        sources = {(e.url.split("?")[0], e.source) for e in ctx.endpoints}
        xhr = [e for e in ctx.endpoints if e.source == "spa-xhr"]

    assert report.enabled is True
    assert report.routes >= 2
    assert report.navigated >= 2
    assert any(source == "spa" for _, source in sources)
    assert any("http://127.0.0.1" in e.url and e.url.endswith("/dashboard") for e in ctx.endpoints)
    assert any(e.url.endswith("/api/items?limit=5") for e in xhr)
    assert xhr[0].parameters == ["limit"]
    assert not any("example.org" in e.url for e in ctx.endpoints)
    assert any(hit.startswith("/api/items") for hit in fixture.hits)
    assert report.as_dict()["xhr"] == report.xhr
