from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse

from venomscan_api import __version__
from venomscan_api.config import Settings, get_settings
from venomscan_api.db import init_db, init_engine
from venomscan_api.routers import (
    ai,
    audit,
    auth,
    checks,
    dashboard,
    demo,
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


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    production = settings.is_production

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
        docs_url=None if production else "/docs",
        redoc_url=None if production else "/redoc",
        openapi_url=None if production else "/openapi.json",
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
    if settings.demo_routes_active:
        app.include_router(demo.router)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "app": settings.app_name, "version": __version__}

    @app.get("/", response_class=JSONResponse)
    def root() -> dict[str, str | None]:
        return {
            "app": settings.app_name,
            "version": __version__,
            "docs": None if production else "/docs",
            "health": "/healthz",
        }

    return app


app = create_app()
