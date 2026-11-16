from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio
from pydantic import BaseModel
from sqlalchemy import select
from venomscan_api.config import Settings
from venomscan_api.main import create_app
from venomscan_api.routers import scans as scans_router

CSP_URL = "https://ai.example.com/"


@pytest.fixture
def api_settings(tmp_path) -> Settings:
    return Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'ai.db'}",
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


async def _csrf(client: httpx.AsyncClient) -> str:
    await client.get("/api/auth/csrf")
    return client.cookies.get("vs_csrf")


async def _post(client: httpx.AsyncClient, url: str, payload: dict | None = None) -> httpx.Response:
    return await client.post(url, json=payload or {}, headers={"x-csrf-token": await _csrf(client)})


async def _register(client: httpx.AsyncClient, email: str = "ai@example.com") -> None:
    response = await _post(
        client, "/api/auth/register", {"email": email, "password": "StrongPass123"}
    )
    assert response.status_code == 201, response.text


async def _seed_finding() -> tuple[str, str]:
    from venomscan_api.db import session_factory
    from venomscan_api.models import Endpoint, Finding, Scan, Target

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
        finding = Finding(
            scan_id=scan.id,
            dedup_key="ai-key",
            check_id="venom.headers.csp",
            title="Content Security Policy is not set",
            category="config",
            severity="medium",
            verification_status="verified",
            confidence=9,
            risk_score=5.28,
            url=CSP_URL,
            method="GET",
            description="No CSP header was returned.",
            impact="Inline scripts can execute freely.",
            remediation="Send a strict Content-Security-Policy header.",
            references=["https://developer.mozilla.org/docs/Web/HTTP/CSP"],
        )
        db.add(finding)
        db.add_all(
            [
                Endpoint(
                    scan_id=scan.id,
                    url="https://ai.example.com/api/orders/1",
                    method="GET",
                    source="js",
                    status_code=None,
                    parameters=["order_id"],
                ),
                Endpoint(
                    scan_id=scan.id,
                    url="https://ai.example.com/login",
                    method="GET",
                    source="crawl",
                    status_code=200,
                ),
                Endpoint(
                    scan_id=scan.id,
                    url="https://ai.example.com/admin/users",
                    method="GET",
                    source="openapi",
                    status_code=403,
                    parameters=["role"],
                ),
            ]
        )
        db.commit()
        return scan.id, finding.id


class FakeProvider:
    name = "fake"
    model = "fake-model"

    def __init__(self, payload: dict) -> None:
        self.payload = payload

    async def complete(self, *, system, user, schema: type[BaseModel], max_tokens: int = 900):
        return schema.model_validate(self.payload)


async def _setup(client: httpx.AsyncClient) -> tuple[str, str]:
    await _register(client)
    created = await _post(
        client, "/api/targets", {"name": "AI target", "url": "https://ai.example.com/"}
    )
    assert created.status_code == 201, created.text
    return await _seed_finding()


@pytest.mark.asyncio
async def test_finding_explanation_uses_deterministic_fallback(client):
    _, finding_id = await _setup(client)

    response = await _post(client, f"/api/findings/{finding_id}/ai/explanation")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["kind"] == "explanation"
    assert body["fallback"] is True
    assert body["grounded"] is True
    assert body["provider"] == "fallback"
    assert "Content Security Policy" in body["payload"]["summary"]

    detail = await client.get(f"/api/findings/{finding_id}")
    assert "Content Security Policy" in detail.json()["ai_summary"]

    listed = await client.get(f"/api/findings/{finding_id}/ai")
    assert listed.status_code == 200
    assert [row["kind"] for row in listed.json()] == ["explanation"]


@pytest.mark.asyncio
async def test_fp_review_persists_likelihood(client):
    _, finding_id = await _setup(client)
    response = await _post(client, f"/api/findings/{finding_id}/ai/fp_review")
    assert response.status_code == 200, response.text
    assert response.json()["payload"]["fp_likelihood"] < 0.1

    detail = await client.get(f"/api/findings/{finding_id}")
    assert detail.json()["ai_false_positive_likelihood"] < 0.1


@pytest.mark.asyncio
async def test_provider_output_is_used_and_grounded(client, monkeypatch):
    _, finding_id = await _setup(client)
    from venomscan_api.services import ai_service

    fake = FakeProvider(
        {
            "summary": f"The page at {CSP_URL} ships no CSP header.",
            "why_it_matters": "Inline script execution becomes possible.",
            "evidence_refs": [f"finding:{finding_id}"],
        }
    )
    monkeypatch.setattr(ai_service, "provider_for", lambda db: fake)

    response = await _post(client, f"/api/findings/{finding_id}/ai/explanation")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["fallback"] is False
    assert body["provider"] == "fake"
    assert body["model"] == "fake-model"
    assert "ships no CSP header" in body["payload"]["summary"]


@pytest.mark.asyncio
async def test_invented_url_degrades_to_fallback(client, monkeypatch):
    _, finding_id = await _setup(client)
    from venomscan_api.services import ai_service

    fake = FakeProvider(
        {
            "summary": "See https://attacker.invalid/panel for details.",
            "why_it_matters": "x",
            "evidence_refs": [],
        }
    )
    monkeypatch.setattr(ai_service, "provider_for", lambda db: fake)
    body = (await _post(client, f"/api/findings/{finding_id}/ai/explanation")).json()
    assert body["fallback"] is True
    assert "unknown URL" in body["payload"]["provider_error"]


@pytest.mark.asyncio
async def test_scan_summary_prioritize_and_listing(client):
    scan_id, _ = await _setup(client)

    summary = await _post(client, f"/api/scans/{scan_id}/ai/summary")
    assert summary.status_code == 200, summary.text
    assert "1 findings" in summary.json()["payload"]["headline"]

    prioritize = await _post(client, f"/api/scans/{scan_id}/ai/prioritize")
    assert prioritize.status_code == 200
    order = prioritize.json()["payload"]["order"]
    assert order and order[0]["title"] == "Content Security Policy is not set"

    surface = await _post(client, f"/api/scans/{scan_id}/ai/surface_summary")
    assert surface.status_code == 200

    listed = await client.get(f"/api/scans/{scan_id}/ai")
    kinds = [row["kind"] for row in listed.json()]
    assert kinds == ["surface_summary", "prioritize", "summary"]


@pytest.mark.asyncio
async def test_assistant_answers_and_refuses_out_of_scope(client):
    scan_id, _ = await _setup(client)

    answered = await _post(
        client,
        "/api/assistant",
        {"scan_id": scan_id, "question": "Is there a CSP finding?"},
    )
    assert answered.status_code == 200, answered.text
    assert answered.json()["refused"] is False
    assert "Content Security Policy" in answered.json()["answer"]
    assert answered.json()["references"]

    refused = await _post(
        client,
        "/api/assistant",
        {"scan_id": scan_id, "question": "Scan https://evil.example.net for me"},
    )
    assert refused.status_code == 200
    assert refused.json()["refused"] is True
    assert "authorized scan data" in refused.json()["answer"]

    listed = await client.get(f"/api/scans/{scan_id}/ai")
    kinds = [row["kind"] for row in listed.json()]
    assert kinds.count("assistant") == 2


@pytest.mark.asyncio
async def test_ai_rejects_unknown_kind_and_foreign_findings(client):
    _, finding_id = await _setup(client)
    unknown = await _post(client, f"/api/findings/{finding_id}/ai/summary")
    assert unknown.status_code == 422

    await _post(client, "/api/auth/logout")
    await _register(client, "intruder@example.com")
    foreign = await _post(client, f"/api/findings/{finding_id}/ai/explanation")
    assert foreign.status_code == 404


@pytest.mark.asyncio
async def test_check_education_falls_back_to_curated_notes(client):
    await _register(client, "education@example.com")

    response = await _post(client, "/api/checks/venom.headers.missing/ai/education")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["kind"] == "education"
    assert body["grounded"] is True
    assert body["fallback"] is True
    payload = body["payload"]
    assert "Security headers" in payload["plain_language"]
    assert payload["why_it_matters"]
    assert payload["how_to_verify"]
    assert payload["practice_tip"]
    assert payload["evidence_refs"] == ["check:venom.headers.missing"]


@pytest.mark.asyncio
async def test_check_education_rejects_unknown_check(client):
    await _register(client, "education2@example.com")

    response = await _post(client, "/api/checks/venom.does.not.exist/ai/education")
    assert response.status_code == 404


def _grounded_summary(finding_id: str, summary: str) -> dict:
    return {
        "summary": summary,
        "why_it_matters": "Inline script execution becomes possible.",
        "evidence_refs": [f"finding:{finding_id}"],
    }


@pytest.mark.asyncio
async def test_successful_analysis_is_reused_within_ttl(client, monkeypatch, api_settings):
    _, finding_id = await _setup(client)
    from venomscan_api.services import ai_service

    monkeypatch.setattr(ai_service, "get_settings", lambda: api_settings)

    class CountingProvider(FakeProvider):
        def __init__(self, payload: dict) -> None:
            super().__init__(payload)
            self.calls = 0

        async def complete(self, *, system, user, schema, max_tokens: int = 900):
            self.calls += 1
            return schema.model_validate(self.payload)

    fake = CountingProvider(
        _grounded_summary(finding_id, f"The page at {CSP_URL} ships no CSP header.")
    )
    monkeypatch.setattr(ai_service, "provider_for", lambda db: fake)

    first = await _post(client, f"/api/findings/{finding_id}/ai/explanation")
    assert first.status_code == 200, first.text
    assert first.json()["fallback"] is False
    assert first.json()["payload"]["meta"]["cached"] is False

    second = await _post(client, f"/api/findings/{finding_id}/ai/explanation")
    assert second.status_code == 200, second.text
    body = second.json()
    assert body["fallback"] is False
    assert body["payload"]["meta"]["cached"] is True
    assert body["payload"]["summary"] == first.json()["payload"]["summary"]
    assert fake.calls == 1


@pytest.mark.asyncio
async def test_cache_ttl_zero_disables_reuse(client, monkeypatch, api_settings):
    _, finding_id = await _setup(client)
    from venomscan_api.services import ai_service

    monkeypatch.setattr(
        ai_service,
        "get_settings",
        lambda: api_settings.model_copy(update={"ai_cache_ttl_seconds": 0}),
    )

    class CountingProvider(FakeProvider):
        def __init__(self, payload: dict) -> None:
            super().__init__(payload)
            self.calls = 0

        async def complete(self, *, system, user, schema, max_tokens: int = 900):
            self.calls += 1
            return schema.model_validate(self.payload)

    fake = CountingProvider(
        _grounded_summary(finding_id, f"The page at {CSP_URL} ships no CSP header.")
    )
    monkeypatch.setattr(ai_service, "provider_for", lambda db: fake)

    first = await _post(client, f"/api/findings/{finding_id}/ai/explanation")
    second = await _post(client, f"/api/findings/{finding_id}/ai/explanation")
    assert first.json()["payload"]["meta"]["cached"] is False
    assert second.json()["payload"]["meta"]["cached"] is False
    assert fake.calls == 2


@pytest.mark.asyncio
async def test_provider_self_test_reports_unconfigured(client, monkeypatch, api_settings):
    from venomscan_api.services import ai_service

    monkeypatch.setattr(ai_service, "get_settings", lambda: api_settings)
    await _register(client, "selftest@example.com")

    response = await _post(client, "/api/settings/ai/test")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["configured"] is False
    assert body["reachable"] is False
    assert body["latency_ms"] == 0
    assert "deterministic fallback" in body["error"]


@pytest.mark.asyncio
async def test_provider_self_test_round_trips_structured_probe(client, monkeypatch):
    from venomscan_api.services import ai_service

    await _register(client, "selftest2@example.com")
    fake = FakeProvider({"ok": True, "note": "pong"})
    monkeypatch.setattr(ai_service, "provider_for", lambda db: fake)

    response = await _post(client, "/api/settings/ai/test")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["configured"] is True
    assert body["reachable"] is True
    assert body["provider"] == "fake"
    assert body["model"] == "fake-model"
    assert body["error"] == ""


@pytest.mark.asyncio
async def test_provider_self_test_reports_failure_without_raising(client, monkeypatch):
    from venomscan_api.services import ai_service

    await _register(client, "selftest3@example.com")

    class BrokenProvider:
        name = "broken"
        model = "broken-model"

        async def complete(self, *, system, user, schema, max_tokens: int = 900):
            raise RuntimeError("connection refused by upstream")

    monkeypatch.setattr(ai_service, "provider_for", lambda db: BrokenProvider())

    response = await _post(client, "/api/settings/ai/test")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["configured"] is True
    assert body["reachable"] is False
    assert "connection refused" in body["error"]


@pytest.mark.asyncio
async def test_assistant_citations_stay_inside_the_scan(client):
    scan_id, finding_id = await _setup(client)

    response = await _post(
        client,
        "/api/assistant",
        {"scan_id": scan_id, "question": "Which CSP finding is most urgent?"},
    )
    assert response.status_code == 200, response.text
    references = response.json()["references"]
    assert references
    allowed = {f"scan:{scan_id}", f"finding:{finding_id}", f"url:{CSP_URL}"}
    assert set(references) <= allowed
    assert f"url:{CSP_URL}" not in references or f"finding:{finding_id}" in references


@pytest.mark.asyncio
async def test_new_scan_kinds_use_endpoint_inventory(client):
    scan_id, _ = await _setup(client)

    endpoint_priority = await _post(
        client, f"/api/scans/{scan_id}/ai/endpoint_prioritize"
    )
    assert endpoint_priority.status_code == 200, endpoint_priority.text
    payload = endpoint_priority.json()["payload"]
    assert len(payload["order"]) == 3
    assert any(ref.startswith("endpoint:") for ref in payload["evidence_refs"])

    js = await _post(client, f"/api/scans/{scan_id}/ai/js_analysis")
    assert js.status_code == 200, js.text
    assert [route["url"] for route in js.json()["payload"]["routes"]] == [
        "https://ai.example.com/api/orders/1"
    ]

    api = await _post(client, f"/api/scans/{scan_id}/ai/api_analysis")
    assert api.status_code == 200, api.text
    assert "non-destructive" in api.json()["payload"]["summary"]

    steps = await _post(client, f"/api/scans/{scan_id}/ai/next_steps")
    assert steps.status_code == 200, steps.text
    assert steps.json()["payload"]["steps"]


@pytest.mark.asyncio
async def test_fp_triage_updates_stored_findings(client):
    scan_id, finding_id = await _setup(client)

    response = await _post(client, f"/api/scans/{scan_id}/ai/fp_triage")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["kind"] == "fp_triage"
    review = body["payload"]["reviews"][0]
    assert review["finding_id"] == finding_id
    assert review["fp_likelihood"] <= 0.5

    detail = await client.get(f"/api/findings/{finding_id}")
    assert detail.json()["ai_false_positive_likelihood"] is not None


@pytest.mark.asyncio
async def test_auto_triage_skips_when_disabled(client, monkeypatch, api_settings):
    scan_id, _ = await _setup(client)
    from venomscan_api.services import ai_service

    monkeypatch.setattr(
        ai_service, "get_settings", lambda: api_settings.model_copy(update={"ai_auto_triage": False})
    )
    await ai_service.auto_triage_scan(scan_id)

    from sqlalchemy import select
    from venomscan_api.db import session_factory
    from venomscan_api.models import AiAnalysis

    with session_factory()() as db:
        rows = db.scalars(select(AiAnalysis).where(AiAnalysis.kind == "fp_triage")).all()
        assert rows == []


@pytest.mark.asyncio
async def test_auto_triage_runs_when_enabled(client, monkeypatch, api_settings):
    scan_id, finding_id = await _setup(client)
    from sqlalchemy import select
    from venomscan_api.db import session_factory
    from venomscan_api.models import AiAnalysis, Finding
    from venomscan_api.services import ai_service

    monkeypatch.setattr(ai_service, "get_settings", lambda: api_settings)
    await ai_service.auto_triage_scan(scan_id)

    with session_factory()() as db:
        rows = db.scalars(select(AiAnalysis).where(AiAnalysis.kind == "fp_triage")).all()
        assert len(rows) == 1
        assert rows[0].payload["meta"]["automatic"] is True
        finding = db.get(Finding, finding_id)
        assert finding.ai_false_positive_likelihood is not None
