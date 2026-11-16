from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio
from venomscan_api.config import Settings
from venomscan_api.main import create_app
from venomscan_api.routers import scans as scans_router


@pytest.fixture
def api_settings(tmp_path) -> Settings:
    return Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'api.db'}",
        secret_key="test-secret-key-that-is-long-enough-for-hs256",
        environment="test",
        allow_private_targets=True,
        scan_max_requests=5,
        scan_max_seconds=5,
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


async def csrf(client: httpx.AsyncClient) -> str:
    response = await client.get("/api/auth/csrf")
    assert response.status_code == 200
    token = client.cookies.get("vs_csrf")
    assert token
    return token


async def post(client: httpx.AsyncClient, url: str, payload: dict | None = None) -> httpx.Response:
    return await client.post(url, json=payload or {}, headers={"x-csrf-token": await csrf(client)})


async def put(client: httpx.AsyncClient, url: str, payload: dict) -> httpx.Response:
    return await client.put(url, json=payload, headers={"x-csrf-token": await csrf(client)})


async def register(client: httpx.AsyncClient, email: str = "analyst@example.com") -> httpx.Response:
    return await post(
        client,
        "/api/auth/register",
        {"email": email, "password": "StrongPass123", "name": "Analyst"},
    )


@pytest.mark.asyncio
async def test_healthz(client):
    response = await client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_register_login_refresh_logout(client):
    registered = await register(client)
    assert registered.status_code == 201, registered.text
    assert registered.json()["user"]["email"] == "analyst@example.com"

    me = await client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["email"] == "analyst@example.com"

    refreshed = await post(client, "/api/auth/refresh")
    assert refreshed.status_code == 200

    logged_out = await post(client, "/api/auth/logout")
    assert logged_out.status_code == 200
    assert (await client.get("/api/auth/me")).status_code == 401

    bad_login = await post(
        client, "/api/auth/login", {"email": "analyst@example.com", "password": "wrong-password"}
    )
    assert bad_login.status_code == 401

    good_login = await post(
        client, "/api/auth/login", {"email": "analyst@example.com", "password": "StrongPass123"}
    )
    assert good_login.status_code == 200


@pytest.mark.asyncio
async def test_duplicate_registration_rejected(client):
    assert (await register(client)).status_code == 201
    assert (await register(client)).status_code == 409


@pytest.mark.asyncio
async def test_registration_can_be_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(scans_router, "dispatch", lambda scan_id: None)
    settings = Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'closed.db'}",
        secret_key="test-secret-key-that-is-long-enough-for-hs256",
        environment="test",
        allow_registration=False,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
            response = await register(http, email="late@example.com")
            assert response.status_code == 403
            assert "closed" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_login_locks_out_after_repeated_failures(client):
    await register(client, email="throttled@example.com")

    for _ in range(4):
        response = await post(
            client,
            "/api/auth/login",
            {"email": "throttled@example.com", "password": "WrongPass123"},
        )
        assert response.status_code == 401

    blocked = await post(
        client, "/api/auth/login", {"email": "throttled@example.com", "password": "WrongPass123"}
    )
    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) > 0
    assert "locked" in blocked.json()["detail"].lower()

    still_locked = await post(
        client, "/api/auth/login", {"email": "throttled@example.com", "password": "StrongPass123"}
    )
    assert still_locked.status_code == 429


@pytest.mark.asyncio
async def test_csrf_required_for_mutations(client):
    await csrf(client)
    response = await client.post(
        "/api/auth/register",
        json={"email": "nocsrf@example.com", "password": "StrongPass123", "name": ""},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_unauthenticated_access_denied(client):
    assert (await client.get("/api/targets")).status_code == 401
    assert (await client.get("/api/dashboard")).status_code == 401


@pytest.mark.asyncio
async def test_target_verification_gate_and_scan_flow(client):
    await register(client)

    created = await post(
        client,
        "/api/targets",
        {"name": "Lab app", "url": "https://lab.example.com/app", "scope_notes": "staging only"},
    )
    assert created.status_code == 201, created.text
    target = created.json()
    target_id = target["id"]
    assert target["verification"]["verified"] is False
    assert target["verification"]["token"]
    assert target["verification"]["dns_record_name"].startswith("_venomscan.")

    blocked = await post(client, "/api/scans", {"target_id": target_id, "profile": "safe"})
    assert blocked.status_code == 409

    attested = await post(
        client,
        f"/api/targets/{target_id}/verify/attest",
        {
            "attestation": "I own this staging application and authorize the assessment.",
            "accepted": True,
        },
    )
    assert attested.status_code == 200, attested.text
    assert attested.json()["verification"]["verified"] is True
    assert attested.json()["verification"]["method"] == "manual_attestation"

    no_consent = await post(client, "/api/scans", {"target_id": target_id, "profile": "active"})
    assert no_consent.status_code == 400
    assert "consent" in no_consent.json()["detail"].lower()

    scan = await post(client, "/api/scans", {"target_id": target_id, "profile": "safe"})
    assert scan.status_code == 201, scan.text
    scan_id = scan.json()["id"]
    assert scan.json()["status"] == "queued"

    listed = await client.get("/api/scans")
    assert [item["id"] for item in listed.json()] == [scan_id]

    cancelled = await post(client, f"/api/scans/{scan_id}/cancel")
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelled"
    assert (await post(client, f"/api/scans/{scan_id}/cancel")).status_code == 409

    empty_dashboard = await client.get("/api/dashboard")
    assert empty_dashboard.status_code == 200
    body = empty_dashboard.json()
    assert body["total_scans"] == 1
    assert body["active_scans"] == 0


@pytest.mark.asyncio
async def test_pending_verification_token_is_stable(client, monkeypatch):
    from venomscan_api.services import verification

    seen: list[str] = []
    calls = {"n": 0}
    issued: dict[str, str] = {}

    async def fake_well_known(url: str, token: str, *, allow_private: bool) -> tuple[bool, str]:
        calls["n"] += 1
        seen.append(token)
        return calls["n"] > 1, "checked"

    monkeypatch.setattr(verification, "check_well_known", fake_well_known)
    await register(client)
    created = await post(
        client, "/api/targets", {"name": "Stable", "url": "https://stable.example.com"}
    )
    target = created.json()
    issued["token"] = target["verification"]["token"]
    target_id = target["id"]

    failed = await post(client, f"/api/targets/{target_id}/verify/well-known")
    assert failed.status_code == 400
    after_failure = await client.get(f"/api/targets/{target_id}")
    assert after_failure.json()["verification"]["token"] == issued["token"]

    verified = await post(client, f"/api/targets/{target_id}/verify/well-known")
    assert verified.status_code == 200, verified.text
    assert verified.json()["verification"]["verified"] is True
    assert verified.json()["verification"]["method"] == "well_known"
    assert seen == [issued["token"], issued["token"]]


@pytest.mark.asyncio
async def test_target_attestation_requires_acceptance(client):
    await register(client)
    created = await post(
        client, "/api/targets", {"name": "Target X", "url": "https://x.example.com"}
    )
    target_id = created.json()["id"]
    rejected = await post(
        client,
        f"/api/targets/{target_id}/verify/attest",
        {
            "attestation": "I own this target and take responsibility for the scan.",
            "accepted": False,
        },
    )
    assert rejected.status_code == 422


@pytest.mark.asyncio
async def test_tenancy_isolation(api_settings, monkeypatch):
    monkeypatch.setattr(scans_router, "dispatch", lambda scan_id: None)
    app = create_app(api_settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with (
            httpx.AsyncClient(transport=transport, base_url="http://testserver") as first,
            httpx.AsyncClient(transport=transport, base_url="http://testserver") as second,
        ):
            await register(first, "one@example.com")
            created = await post(
                first, "/api/targets", {"name": "One", "url": "https://one.example.com"}
            )
            target_id = created.json()["id"]

            await register(second, "two@example.com")
            assert (await second.get(f"/api/targets/{target_id}")).status_code == 404
            assert (await second.get("/api/targets")).json() == []
            hijack = await post(second, "/api/scans", {"target_id": target_id, "profile": "safe"})
            assert hijack.status_code == 404


@pytest.mark.asyncio
async def test_delete_target_cascades(client):
    await register(client)
    created = await post(
        client, "/api/targets", {"name": "Doomed", "url": "https://doomed.example.com"}
    )
    target_id = created.json()["id"]
    deleted = await client.request(
        "DELETE", f"/api/targets/{target_id}", headers={"x-csrf-token": await csrf(client)}
    )
    assert deleted.status_code == 204
    assert (await client.get(f"/api/targets/{target_id}")).status_code == 404


@pytest.mark.asyncio
async def test_settings_catalog_and_scan_defaults(client):
    await register(client)

    catalog = await client.get("/api/checks")
    assert catalog.status_code == 200
    entries = {item["id"]: item for item in catalog.json()}
    assert "venom.secrets.js" in entries
    assert entries["venom.secrets.js"]["learning"]["what"]
    assert entries["venom.secrets.js"]["profile"] == "safe"

    settings = await client.get("/api/settings")
    assert settings.status_code == 200
    assert settings.json()["scan_defaults"]["profile"] == "safe"
    assert settings.json()["disabled_checks"] == []

    updated = await put(
        client,
        "/api/settings",
        {
            "scan_defaults": {"profile": "passive"},
            "disabled_checks": ["venom.secrets.js"],
        },
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["scan_defaults"]["profile"] == "passive"
    assert updated.json()["disabled_checks"] == ["venom.secrets.js"]

    invalid = await put(
        client,
        "/api/settings",
        {"scan_defaults": {"profile": "safe"}, "disabled_checks": ["venom.fake.check"]},
    )
    assert invalid.status_code == 422

    created = await post(
        client, "/api/targets", {"name": "Defaults", "url": "https://defaults.example.com"}
    )
    target_id = created.json()["id"]
    await post(
        client,
        f"/api/targets/{target_id}/verify/attest",
        {
            "attestation": "I own this target and authorize the assessment.",
            "accepted": True,
        },
    )
    scan = await post(client, "/api/scans", {"target_id": target_id})
    assert scan.status_code == 201, scan.text
    assert scan.json()["profile"] == "passive"


@pytest.mark.asyncio
async def test_findings_merge_across_scans(client):
    from venomscan_api.db import session_factory
    from venomscan_api.models import Finding, Scan

    await register(client)
    created = await post(
        client, "/api/targets", {"name": "Merge", "url": "https://merge.example.com"}
    )
    target_id = created.json()["id"]

    with session_factory()() as db:
        for _ in range(2):
            scan = Scan(
                target_id=target_id,
                profile="safe",
                status="completed",
                phase="reporting",
                progress=100,
            )
            db.add(scan)
            db.flush()
            db.add(
                Finding(
                    scan_id=scan.id,
                    dedup_key="repeat-key",
                    check_id="venom.headers.csp",
                    title="Content Security Policy is not set",
                    category="config",
                    severity="medium",
                    verification_status="verified",
                    confidence=9,
                    risk_score=5.28,
                    url="https://merge.example.com/",
                    method="GET",
                    description="d",
                    impact="i",
                    remediation="r",
                )
            )
        db.commit()

    rows = (await client.get("/api/findings")).json()
    assert len(rows) == 1
    assert rows[0]["occurrences"] == 2


@pytest.mark.asyncio
async def test_test_account_credentials_stay_masked(client):
    from venomscan_api.db import session_factory

    await register(client)
    payload = {
        "label": "alice",
        "role": "user",
        "identity": "alice@demo.test",
        "headers": {"X-Demo-User": "alice", "Authorization": "Bearer demo-token"},
    }
    created = await post(client, "/api/settings/credentials", payload)
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["header_names"] == ["Authorization", "X-Demo-User"]
    assert "Bearer demo-token" not in created.text
    assert "headers" not in body

    listed = await client.get("/api/settings/credentials")
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    assert "Bearer demo-token" not in listed.text

    duplicate = await post(client, "/api/settings/credentials", payload)
    assert duplicate.status_code == 409

    with session_factory()() as db:
        from venomscan_api.models import TestCredential

        row = db.query(TestCredential).one()
        assert "demo-token" not in row.headers_encrypted
        assert row.headers_encrypted

    deleted = await client.delete(
        f"/api/settings/credentials/{body['id']}",
        headers={"x-csrf-token": await csrf(client)},
    )
    assert deleted.status_code == 204
    assert (await client.get("/api/settings/credentials")).json() == []


@pytest.mark.asyncio
async def test_invalid_credential_headers_are_rejected(client):
    await register(client)
    bad_name = await post(
        client,
        "/api/settings/credentials",
        {"label": "bad", "headers": {"Bad Header": "x"}},
    )
    assert bad_name.status_code == 422
    newline = await post(
        client,
        "/api/settings/credentials",
        {"label": "bad", "headers": {"X-Test": "value\r\nInjected: 1"}},
    )
    assert newline.status_code == 422


@pytest.mark.asyncio
async def test_ai_settings_hide_the_key(client):
    await register(client)
    initial = await client.get("/api/settings/ai")
    assert initial.status_code == 200
    assert initial.json()["key_configured"] is False

    updated = await put(
        client,
        "/api/settings/ai",
        {
            "provider": "openai_compat",
            "model": "test-model",
            "base_url": "http://127.0.0.1:9999/v1",
            "api_key": "sk-secret-value",
        },
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["key_configured"] is True
    assert updated.json()["model"] == "test-model"
    assert "sk-secret-value" not in updated.text

    reread = await client.get("/api/settings/ai")
    assert reread.json()["key_configured"] is True
    assert "sk-secret-value" not in reread.text

    cleared = await put(
        client,
        "/api/settings/ai",
        {"provider": "openai_compat", "model": "test-model", "base_url": "", "api_key": ""},
    )
    assert cleared.json()["key_configured"] is False
