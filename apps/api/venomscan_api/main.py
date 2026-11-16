from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from xml.parsers import expat

import httpx
from fastapi import FastAPI, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

from venomscan_api import __version__
from venomscan_api.config import Settings, get_settings
from venomscan_api.db import init_db, init_engine
from venomscan_api.routers import (
    ai,
    audit,
    auth,
    checks,
    dashboard,
    findings,
    integrations,
    learning,
    reports,
    scans,
    targets,
)
from venomscan_api.routers import (
    settings as settings_router,
)
from venomscan_api.services.login_guard import build_login_guard


def _demo_fetch_entity(
    context: str | None, base: str | None, system_id: str | None, public_id: str | None
) -> int:
    """Deliberately resolves external entities so the XXE check has live evidence."""
    if system_id and system_id.startswith(("http://", "https://")):
        try:
            httpx.get(system_id, timeout=2.0, trust_env=False)
        except httpx.HTTPError:
            pass
    return 1


def _demo_parse_xml(body: bytes) -> str:
    parser = expat.ParserCreate()
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_ALWAYS)
    parser.ExternalEntityRefHandler = _demo_fetch_entity
    roots: list[str] = []
    parser.StartElementHandler = lambda name, attrs: roots.append(name)
    parser.Parse(body, True)
    return roots[0] if roots else ""


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        init_engine(settings)
        init_db()
        yield

    app = FastAPI(
        title="VENOMSCAN API",
        version=__version__,
        description="Authorized web application security assessment control plane.",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.login_guard = build_login_guard(
        backend=settings.login_state_backend,
        redis_url=settings.redis_url,
        max_attempts=settings.login_max_attempts,
        ip_max_attempts=settings.login_ip_max_attempts,
        window_seconds=settings.login_window_seconds,
        lockout_seconds=settings.login_lockout_seconds,
    )
    app.dependency_overrides[get_settings] = lambda: settings
    # text/event-stream stays uncompressed (SSE must not be buffered by a compressor).
    app.add_middleware(GZipMiddleware, minimum_size=1024)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    for module in (
        auth,
        targets,
        scans,
        dashboard,
        findings,
        audit,
        settings_router,
        checks,
        ai,
        learning,
        reports,
        integrations,
    ):
        app.include_router(module.router)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "app": settings.app_name, "version": __version__}

    @app.get("/", response_class=JSONResponse)
    def root() -> dict[str, str]:
        return {
            "app": settings.app_name,
            "version": __version__,
            "docs": "/docs",
            "health": "/healthz",
        }

    @app.get("/demo", response_class=HTMLResponse)
    def demo_fixture(request: Request) -> HTMLResponse:
        """Intentionally misconfigured page so a local self-check scan has content."""
        response = HTMLResponse(
            "<!doctype html><html><head><title>VENOMSCAN demo fixture</title></head>"
            "<body><h1>Demo fixture</h1><p>This page intentionally omits security headers.</p>"
            "<form action=\"/demo/search\" method=\"get\">"
            "<input name=\"q\" value=\"demo\"><button type=\"submit\">Search</button></form>"
            "<p><a href=\"/demo/search?q=demo\">Search the demo fixture</a></p>"
            "<p><a href=\"/demo/dom?q=demo\">Demo DOM sink fixture</a></p>"
            "<p><a href=\"/demo/proxy?url=http://127.0.0.1:8000/demo\">Demo URL fetcher</a></p>"
            "<p><a href=\"/demo/api/ping\">Demo API endpoint</a></p>"
            "<p><a href=\"/demo/api/profile\">Demo profile API (leaks a fake token)</a></p>"
            "<p><a href=\"/demo/api/orders/1\">Demo order 1 (alice)</a></p>"
            "<p><a href=\"/demo/api/orders/2\">Demo order 2 (bob)</a></p>"
            "<p><a href=\"/demo/admin\">Demo admin console</a></p>"
            "<form action=\"/demo/xml\" method=\"post\">"
            "<textarea name=\"xml\">&lt;note&gt;demo&lt;/note&gt;</textarea>"
            "<button type=\"submit\">Send XML</button></form>"
            "</body></html>"
        )
        response.set_cookie("session_id", "demo-session", httponly=False, samesite="lax")
        return response

    @app.get("/demo/api/ping")
    def demo_api_ping() -> JSONResponse:
        """JSON fixture so API-surface checks have a real response to inspect."""
        return JSONResponse({"status": "ok", "service": "venomscan-demo"})

    @app.get("/demo/api/profile")
    def demo_api_profile() -> JSONResponse:
        """Deliberately returns a credential-shaped value for the sensitive-data demo."""
        return JSONResponse(
            {
                "user": "demo",
                "token": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkZW1vLXVzZXIifQ.demo-not-a-real-token",
            }
        )

    demo_users = {
        "alice": "alice@demo.test",
        "bob": "bob@demo.test",
        "admin": "admin@demo.test",
    }

    @app.get("/demo/api/orders/{order_id}")
    def demo_order(
        order_id: int, x_demo_user: str | None = Header(default=None)
    ) -> JSONResponse:
        """Deliberately skips ownership checks so the IDOR check has live evidence."""
        if x_demo_user not in demo_users:
            return JSONResponse({"error": "authentication required"}, status_code=401)
        owner = {1: "alice", 2: "bob"}.get(order_id)
        if owner is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        return JSONResponse(
            {"order": order_id, "owner": demo_users[owner], "total": 42, "status": "shipped"}
        )

    @app.get("/demo/admin", response_class=HTMLResponse)
    def demo_admin(x_demo_user: str | None = Header(default=None)) -> HTMLResponse:
        """Deliberately checks authentication but not the role."""
        if x_demo_user not in demo_users:
            return HTMLResponse("<h1>Authentication required</h1>", status_code=401)
        return HTMLResponse(
            "<!doctype html><html><head><title>Admin console</title></head><body>"
            "<h1>Admin console</h1><p>Workspace administration for demo users.</p>"
            "<ul><li>Export all customer records</li><li>Rotate API keys</li></ul>"
            "</body></html>"
        )

    @app.get("/demo/dom", response_class=HTMLResponse)
    def demo_dom_sink() -> HTMLResponse:
        """Client-side sink fixture: the page copies the query string into innerHTML."""
        return HTMLResponse(
            "<!doctype html><html><head><title>Demo DOM sink</title></head><body>"
            "<h1>Client-side search</h1><div id=\"results\">No query yet.</div>"
            "<script>const q = new URLSearchParams(location.search).get('q') || '';"
            "if (q) { document.getElementById('results').innerHTML = q; }</script>"
            "</body></html>"
        )

    @app.get("/demo/proxy")
    async def demo_proxy(url: str = "") -> JSONResponse:
        """Deliberately fetches a caller-chosen URL so the SSRF check has live evidence."""
        if not url.startswith(("http://", "https://")):
            return JSONResponse({"error": "url must be http(s)"}, status_code=400)
        try:
            async with httpx.AsyncClient(timeout=2.0, trust_env=False) as client:
                upstream = await client.get(url)
        except Exception as exc:
            return JSONResponse({"error": type(exc).__name__}, status_code=502)
        return JSONResponse(
            {"status": upstream.status_code, "bytes": len(upstream.content[:2048])}
        )

    @app.post("/demo/xml")
    async def demo_xml(request: Request) -> JSONResponse:
        """Deliberately resolves DOCTYPE entities so the XXE check has live evidence."""
        body = (await request.body())[:20_000]
        try:
            root = await asyncio.to_thread(_demo_parse_xml, body)
        except Exception as exc:
            return JSONResponse({"error": type(exc).__name__}, status_code=400)
        return JSONResponse({"parsed": True, "root": root})

    @app.get("/demo/search", response_class=HTMLResponse)
    def demo_search(q: str = "") -> HTMLResponse:
        """Deliberately vulnerable fixture for the active-profile demo scan."""
        import re

        evaluated = re.sub(
            r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}",
            lambda match: str(int(match.group(1)) * int(match.group(2))),
            q,
        )
        if "'" in evaluated:
            return HTMLResponse(
                "You have an error in your SQL syntax; check the manual that corresponds to "
                "your MySQL server version for the right syntax to use near ''' at line 1",
                status_code=500,
            )
        return HTMLResponse(
            "<!doctype html><html><head><title>Demo search</title></head>"
            f"<body><h1>Results for {evaluated}</h1>"
            "<p>Fixture page: reflects the query without escaping on purpose.</p></body></html>"
        )

    return app


app = create_app()
