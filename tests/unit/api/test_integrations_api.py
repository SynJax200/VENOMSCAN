from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select
from venomscan_api.config import Settings
from venomscan_api.main import create_app
from venomscan_api.routers import scans as scans_router

TARGET_URL = "https://int.example.com/"


@pytest.fixture
def api_settings(tmp_path) -> Settings:
    return Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'integrations.db'}",
        secret_key="test-secret-key-that-is-long-enough-for-hs256",
        environment="test",
        allow_private_targets=True,
        task_mode="inline",
    )


@pytest_asyncio.fixture
async def client(api_settings, monkeypatch) -> AsyncIterator[httpx.AsyncClient]:
    monkeypatch.setattr(scans_router, "dispatch", lambda scan_id: None)
    app = create_app(api_settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
            yield http


async def _csrf(client: httpx.AsyncClient) -> str:
    await client.get("/api/auth/csrf")
    return client.cookies.get("vs_csrf")


async def _post(client: httpx.AsyncClient, url: str, payload: dict | None = None) -> httpx.Response:
    return await client.post(url, json=payload or {}, headers={"x-csrf-token": await _csrf(client)})


async def _setup(client: httpx.AsyncClient) -> str:
    response = await _post(
        client, "/api/auth/register", {"email": "int@example.com", "password": "StrongPass123"}
    )
    assert response.status_code == 201, response.text
    created = await _post(client, "/api/targets", {"name": "Integration target", "url": TARGET_URL})
    assert created.status_code == 201, created.text
    return created.json()["id"]


def _burp_xml(url: str) -> bytes:
    return f"""<?xml version="1.0"?>
    <issues burpVersion="2024.1">
      <issue>
        <name>SQL injection</name>
        <host ip="">int.example.com</host>
        <path>/search</path>
        <location><![CDATA[{url}]]></location>
        <severity>High</severity>
        <confidence>Certain</confidence>
        <issueDetail><![CDATA[Error-based SQL injection in q.]]></issueDetail>
        <remediationDetail><![CDATA[Use parameterised queries.]]></remediationDetail>
      </issue>
    </issues>""".encode()


def _seed_scan(dedup_keys: list[str]) -> str:
    from venomscan_api.db import session_factory
    from venomscan_api.models import Finding, Scan, Target

    with session_factory()() as db:
        target = db.scalars(select(Target).order_by(Target.created_at)).all()[-1]
        scan = Scan(
            target_id=target.id,
            profile="safe",
            status="completed",
            phase="reporting",
            progress=100,
        )
        db.add(scan)
        db.flush()
        for index, key in enumerate(dedup_keys):
            db.add(
                Finding(
                    scan_id=scan.id,
                    dedup_key=key,
                    check_id=f"venom.test.{key}",
                    title=f"Finding {key}",
                    category="config",
                    severity="medium",
                    verification_status="suspected",
                    confidence=6,
                    risk_score=4.0 + index,
                    url=TARGET_URL,
                    method="GET",
                    description="desc",
                    impact="impact",
                    remediation="fix",
                )
            )
        db.commit()
        return scan.id


@pytest.mark.asyncio
async def test_integration_status_reports_nuclei_disabled(client):
    await _setup(client)
    response = await client.get("/api/integrations")
    assert response.status_code == 200
    body = response.json()
    assert body["nuclei"]["enabled"] is False
    assert body["nuclei"]["configured"] is False
    assert body["burp_import"] is True
    assert body["upstream_proxy"] is False


@pytest.mark.asyncio
async def test_burp_import_creates_import_scan_and_export_roundtrip(client):
    target_id = await _setup(client)
    token = await _csrf(client)
    imported = await client.post(
        f"/api/targets/{target_id}/integrations/burp/import?format=xml",
        content=_burp_xml(f"{TARGET_URL}search"),
        headers={"x-csrf-token": token, "content-type": "application/xml"},
    )
    assert imported.status_code == 201, imported.text
    body = imported.json()
    assert body["imported"] == 1
    scan_id = body["scan_id"]

    detail = await client.get(f"/api/scans/{scan_id}")
    assert detail.status_code == 200
    assert detail.json()["findings"][0]["check_id"].startswith("burp.import.")
    assert detail.json()["findings"][0]["severity"] == "high"
    assert detail.json()["status"] == "completed"

    exported = await client.get(f"/api/scans/{scan_id}/integrations/burp/export")
    assert exported.status_code == 200
    assert b"SQL injection" in exported.content
    assert b"<issues" in exported.content


@pytest.mark.asyncio
async def test_burp_import_rejects_out_of_scope_urls(client):
    target_id = await _setup(client)
    token = await _csrf(client)
    response = await client.post(
        f"/api/targets/{target_id}/integrations/burp/import?format=xml",
        content=_burp_xml("https://evil.example.com/admin"),
        headers={"x-csrf-token": token},
    )
    assert response.status_code == 422
    assert "outside the authorized scope" in response.json()["detail"]
    scans = await client.get("/api/scans")
    assert scans.json() == []


@pytest.mark.asyncio
async def test_scan_compare_reports_new_fixed_persisting(client):
    await _setup(client)
    base = _seed_scan(["persist", "fixed"])
    other = _seed_scan(["persist", "new"])

    response = await client.get(f"/api/scans/{other}/compare?other={base}")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["counts"] == {"new": 1, "fixed": 1, "persisting": 1}
    assert body["new"][0]["title"] == "Finding new"
    assert body["fixed"][0]["title"] == "Finding fixed"
    assert body["persisting"][0]["title"] == "Finding persist"

    same = await client.get(f"/api/scans/{other}/compare?other={other}")
    assert same.status_code == 400


@pytest.mark.asyncio
async def test_scan_intel_matches_detected_technology(client):
    await _setup(client)
    from venomscan_api.db import session_factory
    from venomscan_api.models import Scan, Target, Technology

    with session_factory()() as db:
        target = db.scalars(select(Target).order_by(Target.created_at)).all()[-1]
        scan = Scan(
            target_id=target.id, profile="safe", status="completed", phase="reporting", progress=100
        )
        db.add(scan)
        db.flush()
        db.add(
            Technology(scan_id=scan.id, name="nginx", version="1.18.0", category="server")
        )
        db.add(
            Technology(scan_id=scan.id, name="jQuery", version="3.4.1", category="js-library")
        )
        db.commit()
        scan_id = scan.id

    response = await client.get(f"/api/scans/{scan_id}/intel")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["snapshot_version"] == "2026-11-15"
    ids = {match["cve"]["id"] for match in body["matches"]}
    assert "CVE-2021-23017" in ids
    assert "CVE-2020-11022" in ids
    assert all(match["cve"]["refs"] for match in body["matches"])


@pytest.mark.asyncio
async def test_plugin_catalog_lists_configured_directory(tmp_path, monkeypatch):
    from pathlib import Path

    examples = Path(__file__).resolve().parents[3] / "examples" / "plugins"  # noqa: ASYNC240
    settings = Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'plugins.db'}",
        secret_key="test-secret-key-that-is-long-enough-for-hs256",
        environment="test",
        plugin_dirs=str(examples),
        task_mode="inline",
    )
    monkeypatch.setattr(scans_router, "dispatch", lambda scan_id: None)
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
            created = await _post(
                http,
                "/api/auth/register",
                {"email": "plugins@example.com", "password": "StrongPass123"},
            )
            assert created.status_code == 201
            response = await http.get("/api/checks/plugins")
            assert response.status_code == 200
            body = response.json()
            assert body["plugins"][0]["check_id"] == "venom.plugin.version_banner"
            assert body["plugins"][0]["profile"] == "safe"
            assert body["problems"] == []
            assert "scrubbed env" in body["isolation"]


@pytest.mark.asyncio
async def test_burp_import_requires_csrf(client):
    target_id = await _setup(client)
    response = await client.post(
        f"/api/targets/{target_id}/integrations/burp/import?format=xml",
        content=_burp_xml(f"{TARGET_URL}search"),
    )
    assert response.status_code == 403
