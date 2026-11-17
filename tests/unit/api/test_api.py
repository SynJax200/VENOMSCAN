from __future__ import annotations

from collections.abc import AsyncIterator
from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio
from venomscan_api.config import Settings
from venomscan_api.db import session_factory
from venomscan_api.deps import client_ip
from venomscan_api.main import create_app
from venomscan_api.models import Finding
from venomscan_api.routers import scans as scans_router


@pytest.fixture
def api_settings(tmp_path) -> Settings:
    return Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'api.db'}",
        secret_key="test-secret-key-that-is-long-enough-for-hs256",
        environment="test",
        allow_registration=True,
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
async def test_dashboard_is_scoped_to_owner(api_settings, monkeypatch):
    monkeypatch.setattr(scans_router, "dispatch", lambda scan_id: None)
    app = create_app(api_settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with (
            httpx.AsyncClient(transport=transport, base_url="http://testserver") as first,
            httpx.AsyncClient(transport=transport, base_url="http://testserver") as second,
        ):
            await register(first, "owner@example.com")
            created = await post(
                first, "/api/targets", {"name": "Owned", "url": "https://owned.example.com"}
            )
            target_id = created.json()["id"]
            attested = await post(
                first,
                f"/api/targets/{target_id}/verify/attest",
                {"accepted": True, "attestation": "I own this host and authorize the assessment."},
            )
            assert attested.status_code == 200, attested.text
            scan = await post(first, "/api/scans", {"target_id": target_id, "profile": "safe"})
            assert scan.status_code == 201, scan.text
            scan_id = scan.json()["id"]

            factory = session_factory()
            with factory() as db:
                db.add(
                    Finding(
                        scan_id=scan_id,
                        dedup_key="dashboard-owner-test",
                        check_id="venom.headers.csp",
                        title="Missing CSP",
                        category="headers",
                        severity="medium",
                        url="https://owned.example.com/",
                        description="No Content-Security-Policy header.",
                        impact="Injected script execution is not mitigated.",
                        remediation="Send a restrictive Content-Security-Policy header.",
                    )
                )
                db.commit()

            own = (await first.get("/api/dashboard")).json()
            assert own["total_scans"] == 1
            assert own["total_findings"] == 1
            assert own["severity"]["medium"] == 1
            assert [item["id"] for item in own["targets"]] == [target_id]
            assert [item["id"] for item in own["recent_scans"]] == [scan_id]

            await register(second, "intruder@example.com")
            other = (await second.get("/api/dashboard")).json()
            assert other["total_scans"] == 0
            assert other["total_findings"] == 0
            assert other["severity"]["medium"] == 0
            assert other["recent_scans"] == []
            assert other["targets"] == []


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
    target = await post(
        client, "/api/targets", {"name": "Creds", "url": "https://creds.example.com"}
    )
    payload = {
        "target_id": target.json()["id"],
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
    target = await post(
        client, "/api/targets", {"name": "Bad headers", "url": "https://bad.example.com"}
    )
    target_id = target.json()["id"]
    bad_name = await post(
        client,
        "/api/settings/credentials",
        {"target_id": target_id, "label": "bad", "headers": {"Bad Header": "x"}},
    )
    assert bad_name.status_code == 422
    newline = await post(
        client,
        "/api/settings/credentials",
        {
            "target_id": target_id,
            "label": "bad",
            "headers": {"X-Test": "value\r\nInjected: 1"},
        },
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
            "base_url": "https://api.openai.com/v1",
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


@pytest.mark.asyncio
async def test_admin_only_global_settings_and_ai_configuration(api_settings, monkeypatch):
    monkeypatch.setattr(scans_router, "dispatch", lambda scan_id: None)
    app = create_app(api_settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with (
            httpx.AsyncClient(transport=transport, base_url="http://testserver") as admin,
            httpx.AsyncClient(transport=transport, base_url="http://testserver") as user,
        ):
            await register(admin, "admin@example.com")
            me = await admin.get("/api/auth/me")
            assert me.json()["role"] == "admin"

            await register(user, "user@example.com")
            assert (await user.get("/api/auth/me")).json()["role"] == "user"

            assert (await user.get("/api/settings/ai")).status_code == 403
            assert (
                await put(user, "/api/settings", {"scan_defaults": {"profile": "passive"}})
            ).status_code == 403
            assert (
                await put(
                    user,
                    "/api/settings/ai",
                    {
                        "provider": "openai_compat",
                        "model": "test-model",
                        "base_url": "https://api.openai.com/v1",
                        "api_key": "sk-user",
                    },
                )
            ).status_code == 403
            assert (await post(user, "/api/settings/ai/test")).status_code == 403

            assert (await admin.get("/api/settings/ai")).status_code == 200
            assert (
                await put(admin, "/api/settings", {"scan_defaults": {"profile": "passive"}})
            ).status_code == 200


@pytest.mark.asyncio
async def test_ai_base_url_rejects_private_and_unapproved_destinations(client):
    await register(client)
    private = await put(
        client,
        "/api/settings/ai",
        {
            "provider": "openai_compat",
            "model": "test-model",
            "base_url": "http://127.0.0.1:9999/v1",
            "api_key": "sk-secret",
        },
    )
    assert private.status_code == 422

    unapproved = await put(
        client,
        "/api/settings/ai",
        {
            "provider": "openai_compat",
            "model": "test-model",
            "base_url": "https://attacker.example/v1",
            "api_key": "sk-secret",
        },
    )
    assert unapproved.status_code == 422

    suffix = await put(
        client,
        "/api/settings/ai",
        {
            "provider": "openai_compat",
            "model": "test-model",
            "base_url": "https://api.openai.com.attacker.example/v1",
            "api_key": "sk-secret",
        },
    )
    assert suffix.status_code == 422

    allowed = await put(
        client,
        "/api/settings/ai",
        {
            "provider": "openai_compat",
            "model": "test-model",
            "base_url": "https://api.openai.com/v1",
            "api_key": "sk-secret",
        },
    )
    assert allowed.status_code == 200, allowed.text

    ollama = await put(
        client,
        "/api/settings/ai",
        {
            "provider": "ollama",
            "model": "test-model",
            "base_url": "http://127.0.0.1:11434",
            "api_key": None,
        },
    )
    assert ollama.status_code == 200, ollama.text


@pytest.mark.asyncio
async def test_credentials_are_owner_and_target_scoped(api_settings, monkeypatch):
    from venomscan_api.services.runner import _auth_accounts

    monkeypatch.setattr(scans_router, "dispatch", lambda scan_id: None)
    app = create_app(api_settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with (
            httpx.AsyncClient(transport=transport, base_url="http://testserver") as first,
            httpx.AsyncClient(transport=transport, base_url="http://testserver") as second,
        ):
            await register(first, "first@example.com")
            await register(second, "second@example.com")

            first_target = await post(
                first, "/api/targets", {"name": "First", "url": "https://first.example.com"}
            )
            second_target = await post(
                second, "/api/targets", {"name": "Second", "url": "https://second.example.com"}
            )
            first_target_id = first_target.json()["id"]
            second_target_id = second_target.json()["id"]

            first_cred = await post(
                first,
                "/api/settings/credentials",
                {
                    "target_id": first_target_id,
                    "label": "first-account",
                    "headers": {"Authorization": "Bearer first-token"},
                },
            )
            assert first_cred.status_code == 201, first_cred.text
            second_cred = await post(
                second,
                "/api/settings/credentials",
                {
                    "target_id": second_target_id,
                    "label": "second-account",
                    "headers": {"Authorization": "Bearer second-token"},
                },
            )
            assert second_cred.status_code == 201, second_cred.text

            assert [row["label"] for row in (await first.get("/api/settings/credentials")).json()] == [
                "first-account"
            ]
            assert [row["label"] for row in (await second.get("/api/settings/credentials")).json()] == [
                "second-account"
            ]
            hijack_target = await post(
                second,
                "/api/settings/credentials",
                {
                    "target_id": first_target_id,
                    "label": "hijack",
                    "headers": {"Authorization": "Bearer nope"},
                },
            )
            assert hijack_target.status_code == 404
            assert (
                await second.delete(
                    f"/api/settings/credentials/{first_cred.json()['id']}",
                    headers={"x-csrf-token": await csrf(second)},
                )
            ).status_code == 404

            await post(
                first,
                f"/api/targets/{first_target_id}/verify/attest",
                {
                    "attestation": "I own this first target and authorize the assessment.",
                    "accepted": True,
                },
            )
            await post(
                second,
                f"/api/targets/{second_target_id}/verify/attest",
                {
                    "attestation": "I own this second target and authorize the assessment.",
                    "accepted": True,
                },
            )
            first_scan = await post(
                first,
                "/api/scans",
                {"target_id": first_target_id, "profile": "active", "active_consent": True},
            )
            second_scan = await post(
                second,
                "/api/scans",
                {"target_id": second_target_id, "profile": "active", "active_consent": True},
            )
            assert first_scan.status_code == 201, first_scan.text
            assert second_scan.status_code == 201, second_scan.text

            assert [row["label"] for row in _auth_accounts(api_settings, first_scan.json()["id"])] == [
                "first-account"
            ]
            assert [row["label"] for row in _auth_accounts(api_settings, second_scan.json()["id"])] == [
                "second-account"
            ]


def _ip_request(peer: str, forwarded: str | None = None, trusted: str = ""):
    settings = Settings(
        _env_file=None,
        database_url="sqlite://",
        secret_key="test-secret-key-that-is-long-enough-for-hs256",
        environment="test",
        trusted_proxies=trusted,
    )
    headers = {"x-forwarded-for": forwarded} if forwarded else {}
    return SimpleNamespace(
        client=SimpleNamespace(host=peer),
        headers=headers,
        app=SimpleNamespace(state=SimpleNamespace(settings=settings)),
    )


def test_client_ip_ignores_forwarded_header_from_untrusted_peer():
    request = _ip_request("8.8.8.8", "203.0.113.9")
    assert client_ip(request) == "8.8.8.8"


def test_client_ip_uses_last_forwarded_hop_from_internal_proxy():
    request = _ip_request("172.18.0.4", "1.2.3.4, 203.0.113.9")
    assert client_ip(request) == "203.0.113.9"


def test_client_ip_honors_explicitly_trusted_public_proxy():
    request = _ip_request("8.8.8.8", "203.0.113.9", trusted="8.8.8.8")
    assert client_ip(request) == "203.0.113.9"


def test_client_ip_normalizes_mapped_ipv6_and_skips_invalid_hops():
    request = _ip_request("::ffff:172.18.0.4", "not-an-ip, ::ffff:203.0.113.9")
    assert client_ip(request) == "203.0.113.9"
