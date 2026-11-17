from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator
from datetime import timedelta

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select
from venomscan_api.config import Settings
from venomscan_api.db import utcnow
from venomscan_api.main import create_app
from venomscan_api.routers import scans as scans_router

TARGET_URL = "https://reports.example.com/"


@pytest.fixture
def api_settings(tmp_path) -> Settings:
    return Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'reports.db'}",
        secret_key="test-secret-key-that-is-long-enough-for-hs256",
        environment="test",
        allow_registration=True,
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


async def _register(client: httpx.AsyncClient, email: str = "reports@example.com") -> None:
    response = await _post(
        client, "/api/auth/register", {"email": email, "password": "StrongPass123"}
    )
    assert response.status_code == 201, response.text


async def _seed_scan(status: str = "completed") -> str:
    from venomscan_api.db import session_factory
    from venomscan_api.models import Finding, Scan, Target, Technology

    with session_factory()() as db:
        target = db.scalars(select(Target).order_by(Target.created_at)).all()[-1]
        scan = Scan(
            target_id=target.id,
            profile="safe",
            status=status,
            phase="reporting",
            progress=100,
            summary="1 finding (1 medium). Highest risk: CSP.",
            started_at=utcnow() - timedelta(minutes=2),
            finished_at=utcnow(),
        )
        db.add(scan)
        db.flush()
        db.add(
            Finding(
                scan_id=scan.id,
                dedup_key="report-key",
                check_id="venom.headers.csp",
                title="Content Security Policy is not set <unsafe>",
                category="config",
                severity="medium",
                verification_status="suspected",
                confidence=7,
                risk_score=4.62,
                url=TARGET_URL,
                method="GET",
                description="No CSP header was returned.",
                impact="Inline scripts can execute.",
                remediation="Send a strict Content-Security-Policy header.",
                references=["https://developer.mozilla.org/docs/Web/HTTP/CSP"],
            )
        )
        db.add(
            Technology(
                scan_id=scan.id,
                name="nginx",
                version="1.25.3",
                category="server",
                confidence=0.9,
            )
        )
        db.commit()
        return scan.id


async def _setup(client: httpx.AsyncClient) -> str:
    await _register(client)
    created = await _post(
        client, "/api/targets", {"name": "Reports target", "url": TARGET_URL}
    )
    assert created.status_code == 201, created.text
    return await _seed_scan()


@pytest.mark.asyncio
async def test_generate_all_formats_and_integrity(client):
    scan_id = await _setup(client)
    signatures = {}
    for fmt in ("json", "markdown", "html", "pdf"):
        response = await _post(client, f"/api/scans/{scan_id}/reports", {"format": fmt})
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["format"] == fmt
        assert len(body["sha256"]) == 64
        assert body["size"] > 0
        assert body["download_url"].endswith(f"/reports/{body['id']}/download")
        assert body["signed_url"].startswith(f"/api/reports/{body['id']}/signed/")
        signatures[fmt] = body["sha256"]

    assert len(set(signatures.values())) == 4

    listing = await client.get("/api/reports")
    assert listing.status_code == 200
    assert len(listing.json()) == 4
    assert listing.json()[0]["format"] == "pdf"


@pytest.mark.asyncio
async def test_report_creation_autofills_ai_section(client):
    scan_id = await _setup(client)
    created = (
        await _post(client, f"/api/scans/{scan_id}/reports", {"format": "json"})
    ).json()
    payload = (await client.get(created["download_url"])).json()
    kinds = [item["kind"] for item in payload["ai_analyses"]]
    assert "summary" in kinds and "next_steps" in kinds
    summary = next(item for item in payload["ai_analyses"] if item["kind"] == "summary")
    assert summary["citations"]
    assert payload["findings"][0]["ai_summary"]

    again = (
        await _post(client, f"/api/scans/{scan_id}/reports", {"format": "json"})
    ).json()
    payload2 = (await client.get(again["download_url"])).json()
    kinds2 = [item["kind"] for item in payload2["ai_analyses"]]
    assert kinds2.count("summary") == 1
    assert kinds2.count("next_steps") == 1


@pytest.mark.asyncio
async def test_reports_include_evidence_grounded_reproduction_steps(client):
    scan_id = await _setup(client)
    created = (
        await _post(client, f"/api/scans/{scan_id}/reports", {"format": "json"})
    ).json()
    payload = (await client.get(created["download_url"])).json()
    steps = payload["findings"][0]["reproduction"]
    assert len(steps) >= 2
    assert any("curl -sS -D - -o /dev/null" in step for step in steps)
    assert any(TARGET_URL in step for step in steps)
    assert any("Content-Security-Policy" in step for step in steps)

    markdown = (
        await _post(client, f"/api/scans/{scan_id}/reports", {"format": "markdown"})
    ).json()
    text = (await client.get(markdown["download_url"])).text
    assert "**Reproduction (authorized target only).**" in text

    html = (await _post(client, f"/api/scans/{scan_id}/reports", {"format": "html"})).json()
    page = (await client.get(html["download_url"])).text
    assert "<h4>Reproduction (authorized target only)</h4>" in page


@pytest.mark.asyncio
async def test_download_and_preview(client):
    scan_id = await _setup(client)
    created = (
        await _post(client, f"/api/scans/{scan_id}/reports", {"format": "html"})
    ).json()

    preview = await client.get(created["preview_url"])
    assert preview.status_code == 200
    assert "Content Security Policy" in preview.text
    assert "<unsafe>" not in preview.text

    download = await client.get(created["download_url"])
    assert download.status_code == 200
    assert download.content.startswith(b"<!doctype html>")
    assert download.headers["x-content-sha256"] == created["sha256"]
    assert created["filename"] in download.headers["content-disposition"]


@pytest.mark.asyncio
async def test_json_download_matches_integrity_digest(client):
    scan_id = await _setup(client)
    created = (
        await _post(client, f"/api/scans/{scan_id}/reports", {"format": "json"})
    ).json()

    download = await client.get(created["download_url"])
    assert download.status_code == 200
    assert hashlib.sha256(download.content).hexdigest() == created["sha256"]


@pytest.mark.asyncio
async def test_signed_link_works_without_session_and_rejects_tampering(client):
    scan_id = await _setup(client)
    created = (
        await _post(client, f"/api/scans/{scan_id}/reports", {"format": "markdown"})
    ).json()
    signed = created["signed_url"]
    await _post(client, "/api/auth/logout")

    ok = await client.get(signed)
    assert ok.status_code == 200
    assert b"Security assessment" in ok.content

    tampered = signed[:-4] + "0000"
    rejected = await client.get(tampered)
    assert rejected.status_code == 403


@pytest.mark.asyncio
async def test_expired_signed_link_is_rejected(client, api_settings):
    from venomscan_api.services import reports as report_service

    scan_id = await _setup(client)
    created = (await _post(client, f"/api/scans/{scan_id}/reports", {"format": "json"})).json()
    expired = report_service.sign(
        created["id"], utcnow() - timedelta(minutes=1), api_settings.secret_key
    )
    response = await client.get(f"/api/reports/{created['id']}/signed/{expired}")
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_report_requires_completed_scan(client):
    await _register(client)
    created = await _post(client, "/api/targets", {"name": "Pending", "url": TARGET_URL})
    assert created.status_code == 201
    scan_id = await _seed_scan(status="running")
    response = await _post(client, f"/api/scans/{scan_id}/reports", {"format": "json"})
    assert response.status_code == 409


@pytest.mark.asyncio
async def test_unknown_format_is_422(client):
    scan_id = await _setup(client)
    response = await _post(client, f"/api/scans/{scan_id}/reports", {"format": "docx"})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_foreign_report_is_404(client):
    scan_id = await _setup(client)
    created = (await _post(client, f"/api/scans/{scan_id}/reports", {"format": "json"})).json()
    await _post(client, "/api/auth/logout")
    await _register(client, "other@example.com")
    assert (await client.get(created["download_url"])).status_code == 404
