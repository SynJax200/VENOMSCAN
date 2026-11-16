from __future__ import annotations

import json

import httpx
import pytest
from pydantic import BaseModel
from venomscan_engine.ai import features
from venomscan_engine.ai.context import (
    digest_highlights,
    recon_digest,
    recon_refs,
    recon_urls,
    relevant_sections,
    slice_digest,
    walk_strings,
)
from venomscan_engine.ai.provider import LLMError, build_provider
from venomscan_engine.ai.providers import _http
from venomscan_engine.ai.providers.openai_compat import OpenAICompatProvider
from venomscan_engine.ai.retrieval import retrieve
from venomscan_engine.ai.schemas import ExplanationPayload

URL = "http://demo.local/"


def _recon() -> dict:
    return {
        "dns": {
            "host": "demo.local",
            "records": {"A": ["10.0.0.5"], "MX": [], "TXT": ["v=spf1 -all"]},
            "mail": {
                "spf": "v=spf1 -all",
                "dmarc": {"policy": "reject", "subdomain_policy": "reject"},
                "dkim": [{"selector": "k1"}],
            },
        },
        "waf": {"detected": True, "vendors": [{"name": "Cloudflare"}]},
        "crawl": {"pages": 12, "links": 40, "forms": 3, "api_endpoints": 5},
        "js_intel": {
            "scripts": 4,
            "api_calls": 9,
            "post_calls": 2,
            "source_maps": [{"url": f"{URL}app.js.map"}],
            "sensitive_paths": [f"/p{i}" for i in range(12)],
        },
        "endpoint_intel": {
            "cluster_count": 3,
            "endpoint_count": 18,
            "templated": 2,
            "api_clusters": 1,
            "clusters": [
                {"template": f"{URL}api/items/{{id}}", "count": 6, "methods": ["GET"], "sources": ["crawl"]}
                for _ in range(12)
            ],
        },
        "api_intel": {
            "spec": {
                "documents": 1,
                "routes": 6,
                "operations": 4,
                "public_write_count": 1,
                "public_writes": [{"method": "POST", "path": "/api/items"}],
                "api_key_query_schemes": ["api_key"],
            },
            "jwt": {"tokens": [{"flags": ["alg-none"]}, {"flags": ["alg-none", "long-expiry"]}]},
            "graphql": {"confirmed": ["/graphql"], "introspection": True},
        },
        "history": {"count": 7, "urls": [{"url": f"{URL}old", "kind": "wayback"}]},
        "dirs": {"probed": 20, "found": 2, "paths": ["/admin", "/backup"]},
        "exposure": [
            {
                "address": "10.0.0.5",
                "source": "shodan",
                "ports": [80, 443, 8080, 8443, 9000, 9090, 9443],
                "vulns": ["CVE-2020-0001", "CVE-2020-0002"],
            }
        ],
        "verification": {"verified": 4, "suspected": 2, "rejected": 1, "downgraded": 1},
        "correlation": {
            "boosted_findings": 2,
            "max_multiplier": 1.5,
            "chains": [
                {
                    "rule_id": "chain-idor-api",
                    "multiplier": 1.5,
                    "gate": {"check_id": "venom.api.bola"},
                    "triggers": [{"check_id": "venom.headers.cors"}],
                }
            ],
        },
        "ip_intel": {},
        "tls": {},
    }


def _finding(**overrides) -> dict:
    data = {
        "id": "f1",
        "check_id": "venom.api.bola",
        "title": "BOLA on invoices",
        "category": "authz",
        "severity": "high",
        "verification_status": "verified",
        "url": f"{URL}api/invoices/1",
        "risk_score": 8.0,
    }
    data.update(overrides)
    return data


def _finding_ctx(**overrides) -> dict:
    finding = _finding(**overrides)
    return {"finding": finding, "refs": [f"finding:{finding['id']}", f"url:{finding['url']}"]}


class FakeProvider:
    name = "fake"
    model = "fake-model"

    def __init__(self, payload: dict) -> None:
        self.payload = payload
        self.calls = 0

    async def complete(self, *, system, user, schema: type[BaseModel], max_tokens: int = 900):
        self.calls += 1
        return schema.model_validate(self.payload)


# --- context digest -------------------------------------------------------


def test_recon_digest_compacts_caps_and_drops_empties():
    digest = recon_digest(_recon())
    assert "ip_intel" not in digest and "tls" not in digest
    assert digest["dns"]["record_counts"] == {"A": 1, "TXT": 1}
    assert len(digest["js_intel"]["sensitive_paths"]) == 8
    assert len(digest["endpoint_intel"]["clusters"]) == 8
    assert len(digest["exposure"][0]["ports"]) == 6
    assert digest["api_intel"]["jwt"]["flags"] == ["alg-none", "long-expiry"]
    assert digest["verification"]["verified"] == 4
    assert len(digest["correlation"]["chains"]) == 1


def test_recon_digest_handles_missing_recon():
    assert recon_digest(None) == {}
    assert recon_digest({}) == {}
    assert recon_digest({"dns": "not-a-dict"}) == {}


def test_recon_refs_and_urls_filter_templates():
    digest = recon_digest(_recon())
    refs = recon_refs(digest)
    assert "recon:dns" in refs and "recon:api_intel" in refs
    assert "recon:tls" not in refs
    urls = recon_urls(digest)
    assert f"{URL}app.js.map" in urls
    assert all("{" not in url and "}" not in url for url in urls)


def test_relevant_sections_mapping():
    assert relevant_sections("venom.api.bola")[:2] == ("api_intel", "api")
    assert relevant_sections("venom.headers.csp") == ("waf", "tls", "verification")
    assert relevant_sections("venom.unknown.check") == ("verification",)


def test_slice_digest_keeps_only_present_sections():
    digest = recon_digest(_recon())
    sliced = slice_digest(digest, ("waf", "tls", "api_intel"))
    assert set(sliced) == {"waf", "api_intel"}


def test_walk_strings_recurses_dicts_and_lists():
    values = list(walk_strings({"a": ["x", {"b": "y"}], "c": 1}))
    assert values == ["x", "y"]


def test_digest_highlights_cover_intelligence_lines():
    lines = digest_highlights(recon_digest(_recon()))
    joined = "\n".join(lines)
    assert "Verification: 4 verified" in joined
    assert "Crawl: 12 page(s)" in joined
    assert "Email authentication:" in joined and "DMARC policy reject" in joined
    assert "WAF: Cloudflare" in joined
    assert "Internet exposure (OSINT, not scanned)" in joined
    assert "JavaScript intelligence:" in joined
    assert "Endpoint clusters: 3 pattern(s)" in joined
    assert "API contract:" in joined
    assert "JWT tokens observed: 2" in joined
    assert "GraphQL: 1 confirmed endpoint(s), introspection enabled" in joined
    assert "Correlation: 1 attack path(s)" in joined
    assert "Directory probes found 2 path(s)" in joined
    assert len(lines) == 12  # history overflows the cap and is trimmed deterministically
    assert "Archived URLs" not in joined
    assert digest_highlights({"history": {"count": 7}}) == ["Archived URLs: 7."]


# --- retrieval ------------------------------------------------------------


def _retrieval_ctx() -> dict:
    return {
        "scan": {
            "id": "s1",
            "target_name": "Demo",
            "target_url": URL,
            "profile": "safe",
            "status": "completed",
            "stats": {},
        },
        "findings": [
            _finding(),
            _finding(
                id="f2",
                check_id="venom.headers.csp",
                title="CSP missing",
                category="config",
                severity="medium",
                url=URL,
                risk_score=3.0,
            ),
        ],
        "endpoints": [
            {"url": f"{URL}api/invoices", "method": "GET", "source": "crawl", "status_code": 200},
            {"url": f"{URL}login", "method": "GET", "source": "crawl", "status_code": 200},
        ],
        "recon": recon_digest(_recon()),
        "refs": [
            "scan:s1",
            "finding:f1",
            "finding:f2",
            f"url:{URL}api/invoices",
            f"url:{URL}login",
            "recon:dns",
            "recon:api_intel",
            "recon:verification",
        ],
    }


def test_retrieve_prioritises_matching_findings_and_endpoints():
    retrieved = retrieve("Which API authorization issue did we find?", _retrieval_ctx())
    assert retrieved.refs[0] == "scan:s1"
    assert retrieved.context["findings"][0]["id"] == "f1"
    assert retrieved.context["endpoints"][0]["url"] == f"{URL}api/invoices"
    assert f"{URL}api/invoices" in retrieved.urls


def test_retrieve_keeps_at_least_four_findings_sorted_by_risk():
    ctx = _retrieval_ctx()
    ctx["findings"] = [_finding(id=f"f{i}", risk_score=float(i)) for i in range(1, 7)]
    retrieved = retrieve("xyzzy", ctx)
    ids = [item["id"] for item in retrieved.context["findings"]]
    assert len(ids) == 4
    assert ids[0] == "f6"


def test_retrieve_surface_question_returns_endpoints_without_token_hits():
    retrieved = retrieve("show me the attack surface", _retrieval_ctx())
    assert len(retrieved.context["endpoints"]) == 2


def test_retrieve_selects_recon_sections_by_tokens_and_keeps_verification():
    ctx = _retrieval_ctx()
    matched = retrieve("what is our spf and dmarc policy?", ctx)
    assert "dns" in matched.context["recon"]
    assert any(ref == "recon:dns" for ref in matched.refs)

    quiet = retrieve("xyzzy", ctx)
    assert "verification" in quiet.context["recon"]


def test_retrieve_refs_stay_inside_the_context():
    ctx = _retrieval_ctx()
    ctx["refs"] = ["scan:s1", "finding:f1", *recon_refs(ctx["recon"])]
    retrieved = retrieve("api authorization", ctx)
    assert set(retrieved.refs) <= set(ctx["refs"])
    assert "finding:f1" in retrieved.refs
    assert "finding:f2" not in retrieved.refs
    assert retrieved.refs[0] == "scan:s1"


# --- output contracts -----------------------------------------------------


@pytest.mark.asyncio
async def test_fp_review_contract_rejects_verified_high_likelihood():
    provider = FakeProvider(
        {"fp_likelihood": 0.9, "reasoning": "looks fake", "evidence_refs": ["finding:f1"]}
    )
    result = await features.analyze(
        "fp_review", _finding_ctx(), provider=provider, allowed_refs=["finding:f1"]
    )
    assert result.fallback
    assert "verified finding" in result.provider_error


@pytest.mark.asyncio
async def test_fp_review_contract_rejects_rejected_low_likelihood():
    provider = FakeProvider(
        {"fp_likelihood": 0.1, "reasoning": "fine", "evidence_refs": []}
    )
    ctx = _finding_ctx(verification_status="rejected")
    result = await features.analyze(
        "fp_review", ctx, provider=provider, allowed_refs=["finding:f1"]
    )
    assert result.fallback
    assert "rejected finding" in result.provider_error


def _priority_ctx() -> dict:
    return {
        "scan": {"id": "s1", "target_name": "Demo", "target_url": URL},
        "findings": [
            _finding(),
            _finding(id="f2", check_id="venom.headers.csp", title="CSP missing", risk_score=3.0),
        ],
        "refs": ["scan:s1", "finding:f1", "finding:f2"],
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("order", "error"),
    [
        ([], "omitted every finding"),
        ([{"finding_id": "zzz", "title": "Invented"}], "unknown finding"),
        ([{"finding_id": "f1", "title": "Wrong title"}], "title mismatch"),
        (
            [
                {"finding_id": "f1", "title": "BOLA on invoices"},
                {"finding_id": "f1", "title": "BOLA on invoices"},
            ],
            "duplicate finding",
        ),
    ],
)
async def test_prioritize_contract_rejects_inconsistent_orders(order, error):
    provider = FakeProvider({"order": order, "evidence_refs": ["finding:f1"]})
    result = await features.analyze(
        "prioritize",
        _priority_ctx(),
        provider=provider,
        allowed_refs=["scan:s1", "finding:f1", "finding:f2"],
    )
    assert result.fallback
    assert error in result.provider_error


@pytest.mark.asyncio
async def test_prioritize_contract_accepts_consistent_order():
    provider = FakeProvider(
        {
            "order": [
                {"finding_id": "f2", "title": "CSP missing", "url": URL, "reason": "headers"},
                {"finding_id": "f1", "title": "BOLA on invoices", "url": URL, "reason": "authz"},
            ],
            "evidence_refs": ["finding:f2", "finding:f1"],
        }
    )
    result = await features.analyze(
        "prioritize",
        _priority_ctx(),
        provider=provider,
        allowed_urls=[URL],
        allowed_refs=["scan:s1", "finding:f1", "finding:f2"],
    )
    assert not result.fallback
    assert [item.finding_id for item in result.payload.order] == ["f2", "f1"]


@pytest.mark.asyncio
async def test_remediation_contract_requires_steps():
    provider = FakeProvider({"summary": "fix it", "steps": [], "evidence_refs": []})
    result = await features.analyze(
        "remediation", _finding_ctx(), provider=provider, allowed_refs=["finding:f1"]
    )
    assert result.fallback
    assert "no actionable steps" in result.provider_error


# --- fallback integration with recon --------------------------------------


@pytest.mark.asyncio
async def test_fallback_summary_mentions_recon_intelligence():
    ctx = {
        "scan": {"id": "s1", "target_name": "Demo", "target_url": URL},
        "findings": [_finding()],
        "recon": recon_digest(_recon()),
        "refs": ["scan:s1", "finding:f1", "recon:verification", "recon:crawl", "recon:dns"],
    }
    result = await features.analyze("summary", ctx)
    assert "Verification: 4 verified" in result.payload.summary
    assert any(ref.startswith("recon:") for ref in result.payload.evidence_refs)


@pytest.mark.asyncio
async def test_fallback_correlate_mentions_attack_paths():
    ctx = {
        "scan": {"id": "s1", "target_name": "Demo", "target_url": URL},
        "findings": [_finding()],
        "recon": recon_digest(_recon()),
        "refs": ["scan:s1", "finding:f1", "recon:correlation"],
    }
    result = await features.analyze("correlate", ctx)
    assert "Documented attack paths: chain-idor-api" in result.payload.summary
    assert any(theme.startswith("Documented attack paths") for theme in result.payload.themes)


def test_retrieval_digest_is_json_serializable():
    digest = recon_digest(_recon())
    assert json.loads(json.dumps(digest, sort_keys=True, default=str))["dns"]["host"] == "demo.local"


# --- provider transport ---------------------------------------------------


@pytest.mark.asyncio
async def test_post_json_retries_transient_status_then_succeeds(monkeypatch):
    delays: list[float] = []

    async def fake_sleep(delay: float) -> None:
        delays.append(delay)

    monkeypatch.setattr(_http, "_sleep", fake_sleep)
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if len(calls) == 1:
            return httpx.Response(503)
        return httpx.Response(200, json={"ok": True})

    response = await _http.post_json(
        "http://llm.test/v1/chat/completions",
        headers={},
        body={},
        timeout_seconds=5,
        transport=httpx.MockTransport(handler),
        retries=1,
    )
    assert response.status_code == 200
    assert len(calls) == 2
    assert delays and delays[0] > 0


@pytest.mark.asyncio
async def test_post_json_caps_retry_after(monkeypatch):
    delays: list[float] = []

    async def fake_sleep(delay: float) -> None:
        delays.append(delay)

    monkeypatch.setattr(_http, "_sleep", fake_sleep)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, headers={"retry-after": "30"})

    with pytest.raises(LLMError, match="HTTP 503"):
        await _http.post_json(
            "http://llm.test/v1/chat/completions",
            headers={},
            body={},
            timeout_seconds=5,
            transport=httpx.MockTransport(handler),
            retries=1,
        )
    assert delays == [2.0]


@pytest.mark.asyncio
async def test_post_json_does_not_retry_client_errors():
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(400, json={"error": "bad key"})

    with pytest.raises(LLMError, match="HTTP 400"):
        await _http.post_json(
            "http://llm.test/v1/chat/completions",
            headers={},
            body={},
            timeout_seconds=5,
            transport=httpx.MockTransport(handler),
            retries=2,
        )
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_post_json_transport_error_fails_after_retries(monkeypatch):
    async def fake_sleep(delay: float) -> None:
        return None

    monkeypatch.setattr(_http, "_sleep", fake_sleep)
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        raise httpx.ConnectError("refused")

    with pytest.raises(LLMError, match="provider unreachable"):
        await _http.post_json(
            "http://llm.test/v1/chat/completions",
            headers={},
            body={},
            timeout_seconds=5,
            transport=httpx.MockTransport(handler),
            retries=1,
        )
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_openai_provider_survives_one_transient_failure(monkeypatch):
    async def fake_sleep(delay: float) -> None:
        return None

    monkeypatch.setattr(_http, "_sleep", fake_sleep)
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(429, headers={"retry-after": "0"})
        content = json.dumps(
            {"summary": "grounded", "why_it_matters": "x", "evidence_refs": ["finding:f1"]}
        )
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    provider = OpenAICompatProvider(
        model="gpt-test",
        base_url="http://llm.local/v1",
        api_key="test-key",
        transport=httpx.MockTransport(handler),
        retries=1,
    )
    payload = await provider.complete(
        system="s", user="u", schema=ExplanationPayload, max_tokens=100
    )
    assert payload.summary == "grounded"
    assert len(calls) == 2


def test_build_provider_passes_timeout_and_retries():
    provider = build_provider("ollama", model="llama3", timeout=9.0, retries=3)
    assert provider is not None
    assert provider.timeout == 9.0
    assert provider.retries == 3
