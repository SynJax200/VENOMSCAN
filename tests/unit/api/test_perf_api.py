from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import inspect, select
from venomscan_api.config import Settings
from venomscan_api.main import create_app


@pytest.fixture
def api_settings(tmp_path) -> Settings:
    return Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'perf.db'}",
        secret_key="test-secret-key-that-is-long-enough-for-hs256",
        environment="test",
        allow_registration=True,
        allow_private_targets=True,
        task_mode="inline",
    )


@pytest_asyncio.fixture
async def client(api_settings) -> AsyncIterator[httpx.AsyncClient]:
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


async def _seed() -> tuple[str, str]:
    from venomscan_api.db import session_factory
    from venomscan_api.models import Finding, Scan, Target, User

    with session_factory()() as db:
        user = db.scalar(select(User))
        target = Target(
            owner_id=user.id,
            name="perf target",
            url="https://perf.example.com/",
            host="perf.example.com",
        )
        db.add(target)
        db.flush()
        scan = Scan(target_id=target.id, profile="safe", status="completed", phase="reporting")
        db.add(scan)
        db.flush()
        for index in range(3):
            db.add(
                Finding(
                    scan_id=scan.id,
                    dedup_key=f"key-{index}",
                    check_id="checks.test",
                    title=f"Finding {index}",
                    category="headers",
                    severity="medium",
                    risk_score=5.0 + index,
                    url=target.url,
                    owasp=["A03:2021 Injection" if index < 2 else "A05:2021 Security Misconfiguration"],
                    description="d",
                    impact="i",
                    remediation="r",
                )
            )
        db.commit()
        return target.id, scan.id


@pytest.mark.asyncio
async def test_schema_indexes_are_created(api_settings) -> None:
    from venomscan_api.db import init_db, init_engine, session_factory

    init_engine(api_settings)
    init_db()
    engine = session_factory().kw["bind"]
    names = {index["name"] for index in inspect(engine).get_indexes("findings")}
    assert "ix_findings_scan_id_risk" in names
    assert "ix_findings_dedup_key" in names


@pytest.mark.asyncio
async def test_counts_use_aggregates(client: httpx.AsyncClient) -> None:
    await _post(client, "/api/auth/register", {"email": "perf@example.com", "password": "StrongPass123"})
    target_id, scan_id = await _seed()

    dashboard = (await client.get("/api/dashboard")).json()
    assert dashboard["total_findings"] == 3
    recent = {scan["id"]: scan for scan in dashboard["recent_scans"]}
    assert recent[scan_id]["findings_total"] == 3

    overview = {target["id"]: target for target in dashboard["targets"]}
    assert overview[target_id]["scans"] == 1
    assert overview[target_id]["findings"] == 3
    assert overview[target_id]["last_status"] == "completed"
    assert overview[target_id]["last_scan_at"]
    assert dashboard["by_check"] == [{"name": "checks.test", "count": 3}]
    owasp = {slice["name"]: slice["count"] for slice in dashboard["by_owasp"]}
    assert owasp["A03:2021 Injection"] == 2
    assert owasp["A05:2021 Security Misconfiguration"] == 1

    scans = (await client.get("/api/scans")).json()
    assert {scan["id"]: scan["findings_total"] for scan in scans}[scan_id] == 3

    targets = (await client.get("/api/targets")).json()
    assert {target["id"]: target["scan_count"] for target in targets}[target_id] == 1
