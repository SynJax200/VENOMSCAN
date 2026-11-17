from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio
from venomscan_api.config import Settings
from venomscan_api.main import create_app


def _settings(tmp_path, **overrides) -> Settings:
    values = {
        "_env_file": None,
        "database_url": f"sqlite:///{tmp_path / 'surface.db'}",
        "secret_key": "test-secret-key-that-is-long-enough-for-hs256",
        "environment": "test",
        "allow_registration": True,
        "task_mode": "inline",
    }
    values.update(overrides)
    return Settings(**values)


@pytest_asyncio.fixture
async def demo_client(tmp_path) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(_settings(tmp_path, demo_enabled=True))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            yield client


@pytest_asyncio.fixture
async def production_client(tmp_path) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(_settings(tmp_path, environment="production", demo_enabled=True))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            yield client


@pytest.mark.asyncio
async def test_demo_fixtures_and_docs_are_available_in_development(demo_client):
    assert (await demo_client.get("/demo")).status_code == 200
    assert (await demo_client.get("/demo/search?q=2")).status_code == 200
    assert (await demo_client.get("/docs")).status_code == 200
    assert (await demo_client.get("/openapi.json")).status_code == 200
    assert (await demo_client.get("/")).json()["docs"] == "/docs"


@pytest.mark.asyncio
async def test_demo_fixtures_require_the_explicit_flag(tmp_path):
    app = create_app(_settings(tmp_path, demo_enabled=False))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            assert (await client.get("/demo")).status_code == 404
            assert (await client.get("/demo/search?q=2")).status_code == 404


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    [
        "/demo",
        "/demo/",
        "/demo/search",
        "/demo/search/",
        "/demo/api/ping",
        "/demo/admin",
        "/docs",
        "/docs/",
        "/redoc",
        "/openapi.json",
        "/api/../demo",
        "/%64emo",
        "/DEMO",
    ],
)
async def test_production_does_not_expose_demo_or_docs(production_client, path):
    response = await production_client.get(path)
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_production_still_serves_health_and_hides_docs_link(production_client):
    assert (await production_client.get("/healthz")).status_code == 200
    assert (await production_client.get("/")).json()["docs"] is None


@pytest.mark.asyncio
async def test_production_openapi_schema_is_not_generated(production_client):
    assert production_client._transport.app.openapi_url is None
    assert production_client._transport.app.docs_url is None
    assert production_client._transport.app.redoc_url is None
