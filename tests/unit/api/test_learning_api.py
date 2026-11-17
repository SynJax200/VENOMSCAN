from __future__ import annotations

import json
from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select
from venomscan_api.config import Settings
from venomscan_api.main import create_app
from venomscan_api.routers import scans as scans_router

BASE_URL = "https://learn.example.com/"


@pytest.fixture
def api_settings(tmp_path) -> Settings:
    return Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'learning.db'}",
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


async def _csrf(client: httpx.AsyncClient) -> str:
    await client.get("/api/auth/csrf")
    return client.cookies.get("vs_csrf")


async def _post(client: httpx.AsyncClient, url: str, payload: dict | None = None) -> httpx.Response:
    return await client.post(url, json=payload or {}, headers={"x-csrf-token": await _csrf(client)})


async def _put(client: httpx.AsyncClient, url: str, payload: dict | None = None) -> httpx.Response:
    return await client.put(url, json=payload or {}, headers={"x-csrf-token": await _csrf(client)})


async def _register(client: httpx.AsyncClient, email: str = "learn@example.com") -> None:
    response = await _post(
        client, "/api/auth/register", {"email": email, "password": "StrongPass123"}
    )
    assert response.status_code == 201, response.text


async def _login(client: httpx.AsyncClient, email: str) -> None:
    response = await _post(client, "/api/auth/login", {"email": email, "password": "StrongPass123"})
    assert response.status_code == 200, response.text


async def _target(client: httpx.AsyncClient, name: str) -> str:
    created = await _post(client, "/api/targets", {"name": name, "url": BASE_URL})
    assert created.status_code == 201, created.text
    return created.json()["id"]


def _seed_findings(target_id: str) -> tuple[str, str, str]:
    from venomscan_api.db import session_factory
    from venomscan_api.models import Finding, Scan

    with session_factory()() as db:
        scan = Scan(
            target_id=target_id,
            profile="safe",
            status="completed",
            phase="reporting",
            progress=100,
        )
        db.add(scan)
        db.flush()

        banner = Finding(
            scan_id=scan.id,
            dedup_key="learn-banner",
            check_id="venom.info.server",
            title="Server banner discloses nginx version",
            category="disclosure",
            severity="low",
            verification_status="verified",
            confidence=8,
            risk_score=3.42,
            url=f"{BASE_URL}app?token=super-secret-token",
            method="GET",
            description="The Server header includes a version.",
            impact="Attackers can match known exploits to the exact version.",
            remediation="Suppress the version token in the Server header.",
            references=["https://nginx.org/en/docs/http/server_names.html"],
            request_evidence={
                "method": "GET",
                "url": f"{BASE_URL}app",
                "headers": {"Authorization": "Bearer super-secret-token"},
            },
            response_evidence={
                "servers": ["nginx/1.18.0"],
                "headers": {"Server": "nginx/1.18.0", "Set-Cookie": "session=abc123"},
            },
        )
        hsts = Finding(
            scan_id=scan.id,
            dedup_key="learn-hsts",
            check_id="venom.headers.missing",
            title="Strict-Transport-Security header is missing",
            category="config",
            severity="medium",
            verification_status="verified",
            confidence=9,
            risk_score=6.1,
            url=BASE_URL,
            method="GET",
            description="No HSTS header.",
            impact="Protocol downgrade becomes possible.",
            remediation="Send Strict-Transport-Security with a long max-age.",
            request_evidence={"method": "GET", "url": BASE_URL},
            response_evidence={
                "url": BASE_URL,
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
            },
        )
        redirect = Finding(
            scan_id=scan.id,
            dedup_key="learn-redirect",
            check_id="venom.redirect.open",
            title="Redirect parameter accepts an external origin",
            category="redirect",
            severity="medium",
            verification_status="suspected",
            confidence=5,
            risk_score=4.0,
            url=f"{BASE_URL}next?to=https%3A%2F%2Fevil.invalid%2F",
            method="GET",
            description="The to parameter is not allow-listed.",
            impact="Phishing links can appear to originate from the target.",
            remediation="Allow-list redirect destinations.",
            response_evidence={"status_code": 302},
        )
        db.add_all([banner, hsts, redirect])
        db.commit()
        return banner.id, hsts.id, redirect.id


async def _setup(client: httpx.AsyncClient, email: str = "learn@example.com") -> tuple[str, str, str]:
    await _register(client, email)
    target_id = await _target(client, "Learning target")
    return _seed_findings(target_id)


@pytest.mark.asyncio
async def test_paths_require_authentication(client):
    response = await client.get("/api/learning/paths")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_paths_expose_the_curriculum_with_empty_progress(client):
    await _register(client)
    response = await client.get("/api/learning/paths")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["check_count"] == 34
    assert body["completed"] == 0
    assert body["in_progress"] == 0
    assert body["percent"] == 0
    assert [track["id"] for track in body["tracks"]] == [
        "surface",
        "transport",
        "browser",
        "access",
        "discovery",
        "injection",
    ]
    lesson_ids = [lesson["id"] for track in body["tracks"] for lesson in track["lessons"]]
    assert len(lesson_ids) == 34
    assert all(lesson["status"] == "not_started" for track in body["tracks"] for lesson in track["lessons"])


@pytest.mark.asyncio
async def test_progress_round_trip_reset_and_validation(client):
    await _register(client)
    missing_csrf = await client.put(
        "/api/learning/progress/venom.info.server", json={"status": "completed"}
    )
    assert missing_csrf.status_code == 403

    completed = await _put(
        client, "/api/learning/progress/venom.info.server", {"status": "completed"}
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["status"] == "completed"
    assert completed.json()["updated_at"]

    started = await _put(client, "/api/learning/progress/venom.tls.weak", {"status": "in_progress"})
    assert started.status_code == 200

    body = (await client.get("/api/learning/paths")).json()
    assert body["completed"] == 1
    assert body["in_progress"] == 1
    assert body["percent"] == round(100 / 34)
    surface = next(track for track in body["tracks"] if track["id"] == "surface")
    assert surface["completed"] == 1
    assert surface["percent"] == 20

    reset = await _put(
        client, "/api/learning/progress/venom.info.server", {"status": "not_started"}
    )
    assert reset.status_code == 200
    assert reset.json() == {
        "check_id": "venom.info.server",
        "status": "not_started",
        "updated_at": None,
    }
    assert (await client.get("/api/learning/paths")).json()["completed"] == 0

    unknown = await _put(client, "/api/learning/progress/venom.nope", {"status": "completed"})
    assert unknown.status_code == 404
    invalid = await _put(
        client, "/api/learning/progress/venom.info.server", {"status": "finished"}
    )
    assert invalid.status_code == 422


@pytest.mark.asyncio
async def test_progress_is_private_to_the_user(client):
    await _register(client, "ai@example.com")
    await _put(client, "/api/learning/progress/venom.info.server", {"status": "completed"})
    await _register(client, "learner@example.com")
    body = (await client.get("/api/learning/paths")).json()
    assert body["completed"] == 0

    from venomscan_api.db import session_factory
    from venomscan_api.models import LearningProgress, User

    with session_factory()() as db:
        rows = db.scalars(select(LearningProgress)).all()
        assert len(rows) == 1
        owner = db.get(User, rows[0].user_id)
        assert owner is not None and owner.email == "ai@example.com"


@pytest.mark.asyncio
async def test_practice_lists_only_verified_owned_findings(client):
    await _setup(client)
    practice = await client.get("/api/learning/practice")
    assert practice.status_code == 200
    titles = {row["title"] for row in practice.json()}
    assert titles == {
        "Server banner discloses nginx version",
        "Strict-Transport-Security header is missing",
    }
    assert all(row["verification_status"] == "verified" for row in practice.json())

    await _register(client, "other@example.com")
    other = await client.get("/api/learning/practice")
    assert other.status_code == 200
    assert other.json() == []


@pytest.mark.asyncio
async def test_walkthrough_redacts_secrets_and_audits(client):
    banner_id, _, _ = await _setup(client)
    missing_csrf = await client.post(f"/api/learning/findings/{banner_id}/walkthrough", json={})
    assert missing_csrf.status_code == 403

    response = await _post(client, f"/api/learning/findings/{banner_id}/walkthrough")
    assert response.status_code == 200, response.text
    body = response.json()
    assert [step["key"] for step in body["steps"]] == [
        "scope",
        "reproduce",
        "signal",
        "judge",
        "fix",
    ]
    assert body["steps"][1]["evidence"]["headers.Authorization"] == "[redacted]"
    assert body["steps"][2]["evidence"]["headers.Set-Cookie"] == "[redacted]"
    assert body["steps"][2]["evidence"]["servers"] == "nginx/1.18.0"
    assert body["learning"]["verify"]
    assert "Stay inside the authorization" in body["safety"]
    assert "super-secret-token" not in response.text
    assert "session=abc123" not in response.text

    from venomscan_api.db import session_factory
    from venomscan_api.models import AuditEvent

    with session_factory()() as db:
        events = db.scalars(
            select(AuditEvent).where(AuditEvent.action == "learning.walkthrough")
        ).all()
        assert len(events) == 1
        assert events[0].target_id == banner_id


@pytest.mark.asyncio
async def test_walkthrough_and_exercises_hide_foreign_findings(client):
    banner_id, _, _ = await _setup(client, "owner@example.com")
    await _register(client, "intruder@example.com")
    walkthrough = await _post(client, f"/api/learning/findings/{banner_id}/walkthrough")
    assert walkthrough.status_code == 404
    exercises = await _post(client, f"/api/learning/findings/{banner_id}/exercises")
    assert exercises.status_code == 404
    unknown = await _post(client, "/api/learning/findings/does-not-exist/walkthrough")
    assert unknown.status_code == 404


@pytest.mark.asyncio
async def test_exercises_are_grounded_deterministic_and_audited(client):
    banner_id, _, _ = await _setup(client)
    first = await _post(client, f"/api/learning/findings/{banner_id}/exercises")
    assert first.status_code == 200, first.text
    items = first.json()
    assert [item["type"] for item in items] == [
        "evidence_read",
        "verify_path",
        "step_order",
        "risk_triage",
    ]
    for item in items:
        assert item["answer"]
        assert set(item["answer"]) <= set(item["options"])
    triage = next(item for item in items if item["type"] == "risk_triage")
    assert triage["answer"][0] == "Strict-Transport-Security header is missing"
    assert triage["answer"][-1] == "Server banner discloses nginx version"

    second = await _post(client, f"/api/learning/findings/{banner_id}/exercises")
    assert second.json() == items

    from venomscan_api.db import session_factory
    from venomscan_api.models import AuditEvent

    with session_factory()() as db:
        events = db.scalars(
            select(AuditEvent).where(AuditEvent.action == "learning.exercises")
        ).all()
        assert len(events) == 2
        assert events[0].detail == {"count": len(items)}


@pytest.mark.asyncio
async def test_practice_limit_is_validated(client):
    await _setup(client)
    assert (await client.get("/api/learning/practice?limit=0")).status_code == 422
    assert (await client.get("/api/learning/practice?limit=99")).status_code == 422
    assert (await client.get("/api/learning/practice?limit=1")).json().__len__() == 1


@pytest.mark.asyncio
async def test_walkthrough_payload_round_trips_as_json(client):
    banner_id, _, _ = await _setup(client)
    body = (await _post(client, f"/api/learning/findings/{banner_id}/walkthrough")).json()
    json.dumps(body)
    assert body["finding_id"] == banner_id
    assert body["check_id"] == "venom.info.server"
    assert len(body["references"]) == 1


def _seed_endpoint_scan(target_id: str) -> str:
    from venomscan_api.db import session_factory
    from venomscan_api.models import Endpoint, Finding, Scan

    with session_factory()() as db:
        scan = Scan(
            target_id=target_id,
            profile="safe",
            status="completed",
            phase="reporting",
            progress=100,
        )
        db.add(scan)
        db.flush()
        db.add_all(
            [
                Endpoint(
                    scan_id=scan.id,
                    url=f"{BASE_URL}admin",
                    method="GET",
                    source="dirs",
                    status_code=200,
                    content_type="text/html",
                    depth=1,
                ),
                Endpoint(
                    scan_id=scan.id,
                    url=f"{BASE_URL}app.js",
                    method="GET",
                    source="js",
                    status_code=None,
                    depth=2,
                ),
                Finding(
                    scan_id=scan.id,
                    dedup_key="ep-admin",
                    check_id="venom.info.dirlist",
                    title="Directory listing is enabled",
                    category="disclosure",
                    severity="medium",
                    verification_status="verified",
                    confidence=8,
                    risk_score=5.2,
                    url=f"{BASE_URL}admin",
                    method="GET",
                    description="The directory index lists files.",
                    impact="Directory contents become discoverable without authentication.",
                    remediation="Disable directory indexes on the web server.",
                    response_evidence={"status_code": 200},
                ),
            ]
        )
        db.commit()
        return scan.id


@pytest.mark.asyncio
async def test_paths_carry_profile_mapping_and_consent(client):
    await _register(client)
    body = (await client.get("/api/learning/paths")).json()
    expected = {"beginner": "passive", "intermediate": "safe", "advanced": "active"}
    for track in body["tracks"]:
        assert track["scan_profile"] == expected[track["level"]]
        assert track["consent"]


@pytest.mark.asyncio
async def test_endpoint_learning_groups_findings_with_lesson_text(client):
    await _register(client)
    target_id = await _target(client, "Endpoint learning target")
    scan_id = _seed_endpoint_scan(target_id)

    response = await client.get(f"/api/learning/scans/{scan_id}/endpoints")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["scan_id"] == scan_id
    assert body["endpoint_count"] == 2
    assert body["with_findings"] == 1

    by_url = {entry["url"]: entry for entry in body["endpoints"]}
    admin = by_url[f"{BASE_URL}admin"]
    assert admin["state"] == "live"
    assert admin["finding_count"] == 1
    lesson = admin["lessons"][0]
    assert lesson["check_id"] == "venom.info.dirlist"
    assert lesson["what"] and lesson["why"] and lesson["verify"]

    script = by_url[f"{BASE_URL}app.js"]
    assert script["state"] == "unverified"
    assert script["lessons"] == []


@pytest.mark.asyncio
async def test_endpoint_learning_is_private_and_validates_scan(client):
    await _register(client, "owner@example.com")
    target_id = await _target(client, "Owned target")
    scan_id = _seed_endpoint_scan(target_id)

    unknown = await client.get("/api/learning/scans/missing/endpoints")
    assert unknown.status_code == 404

    await _register(client, "other@example.com")
    foreign = await client.get(f"/api/learning/scans/{scan_id}/endpoints")
    assert foreign.status_code == 404
