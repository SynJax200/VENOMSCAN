from __future__ import annotations

import base64
import json
import time

import httpx
import pytest
from venomscan_engine.checks.api_security import (
    ApiAuthConfigCheck,
    ApiDocsExposedCheck,
    ApiRateLimitCheck,
    ApiSensitiveDataCheck,
    ApiSpecRiskCheck,
    ApiUnauthenticatedCheck,
    GraphqlCheck,
    JwtCheck,
)
from venomscan_engine.context import ScanContext
from venomscan_engine.events import NullSink
from venomscan_engine.models import EndpointRecord, Severity, VerificationStatus
from venomscan_engine.safety.scope import Scope

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk"

DOCUMENT = {
    "url": "https://example.com/openapi.json",
    "title": "Example API",
    "version": "1.0",
    "spec_version": "3.1.0",
    "paths": 4,
    "operations": 6,
    "servers": ["https://api.example.com"],
    "security_schemes": ["bearerAuth:http/bearer"],
    "global_security": True,
    "declared_auth": True,
}


def _context(make_bundle, url: str = "https://example.com/", profile: str = "safe") -> ScanContext:
    ctx = ScanContext(
        scan_id="api-test",
        target_url=url,
        scope=Scope.from_target(url),
        profile=profile,
        sink=NullSink(),
        client=None,
        max_seconds=60,
    )
    ctx.root = make_bundle(url=url)
    return ctx


def _spec(ctx: ScanContext, **overrides) -> None:
    document = dict(DOCUMENT)
    document.update(overrides)
    ctx.artifacts["openapi"] = {"documents": [document], "endpoint_count": document["operations"]}


@pytest.mark.asyncio
async def test_api_docs_flags_public_spec(make_bundle):
    ctx = _context(make_bundle)
    _spec(ctx)
    findings = await ApiDocsExposedCheck().run(ctx)
    assert [f.check_id for f in findings] == ["venom.api.docs"]
    assert findings[0].verification_status is VerificationStatus.VERIFIED
    assert findings[0].response_evidence["routes"] == 4


@pytest.mark.asyncio
async def test_api_docs_ignores_spec_without_routes(make_bundle):
    ctx = _context(make_bundle)
    _spec(ctx, paths=0)
    assert await ApiDocsExposedCheck().run(ctx) == []


@pytest.mark.asyncio
async def test_api_auth_accepts_documented_scheme(make_bundle):
    ctx = _context(make_bundle)
    _spec(ctx)
    assert await ApiAuthConfigCheck().run(ctx) == []


@pytest.mark.asyncio
async def test_api_auth_flags_missing_security_scheme(make_bundle):
    ctx = _context(make_bundle)
    _spec(ctx, security_schemes=[], global_security=False, declared_auth=False)
    findings = await ApiAuthConfigCheck().run(ctx)
    assert [f.parameter for f in findings] == ["securitySchemes"]
    assert findings[0].severity is Severity.LOW


@pytest.mark.asyncio
async def test_api_auth_flags_plaintext_server_on_https(make_bundle):
    ctx = _context(make_bundle)
    _spec(ctx, servers=["http://api.example.com"])
    findings = await ApiAuthConfigCheck().run(ctx)
    assert [f.parameter for f in findings] == ["servers"]
    assert findings[0].severity is Severity.MEDIUM


@pytest.mark.asyncio
async def test_api_auth_ignores_plaintext_server_on_http_target(make_bundle):
    ctx = _context(make_bundle, "http://example.com/")
    _spec(ctx, servers=["http://api.example.com"])
    assert await ApiAuthConfigCheck().run(ctx) == []


@pytest.mark.asyncio
async def test_api_sensitive_masks_credential(make_bundle):
    ctx = _context(make_bundle)
    ctx.artifacts["api_samples"] = [
        {
            "url": "https://example.com/api/profile",
            "content_type": "application/json",
            "body": f'{{"user": {{"token": "{JWT}"}}}}',
        }
    ]
    findings = await ApiSensitiveDataCheck().run(ctx)
    assert len(findings) == 1
    assert findings[0].parameter == "$.user.token"
    evidence = findings[0].response_evidence
    assert evidence["pattern"] == "jwt"
    assert evidence["body_stored"] is False
    assert JWT not in findings[0].model_dump_json()
    assert evidence["masked_value"].startswith("eyJh")


@pytest.mark.asyncio
async def test_api_sensitive_ignores_clean_json(make_bundle):
    ctx = _context(make_bundle)
    ctx.artifacts["api_samples"] = [
        {
            "url": "https://example.com/api/ping",
            "content_type": "application/json",
            "body": '{"status": "ok", "items": [1, 2, 3]}',
        }
    ]
    assert await ApiSensitiveDataCheck().run(ctx) == []


def _endpoint(url: str = "https://example.com/api/items", **overrides) -> EndpointRecord:
    data = {
        "url": url,
        "method": "GET",
        "source": "crawl",
        "status_code": 200,
        "content_type": "application/json",
        "parameters": [],
    }
    data.update(overrides)
    return EndpointRecord(**data)


@pytest.mark.asyncio
async def test_api_rate_limit_flags_unthrottled_burst(make_bundle, client_factory):
    ctx = _context(make_bundle, profile="active")
    ctx.endpoints = [_endpoint()]
    async with client_factory(lambda request: httpx.Response(200, json={"ok": True})) as client:
        ctx.client = client
        findings = await ApiRateLimitCheck().run(ctx)
        assert client.request_count == 6
    assert [f.check_id for f in findings] == ["venom.api.ratelimit"]
    assert findings[0].verification_status is VerificationStatus.SUSPECTED


@pytest.mark.asyncio
async def test_api_rate_limit_accepts_throttling(make_bundle, client_factory):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "30"}, json={"error": "slow down"})

    ctx = _context(make_bundle, profile="active")
    ctx.endpoints = [_endpoint()]
    async with client_factory(handler) as client:
        ctx.client = client
        assert await ApiRateLimitCheck().run(ctx) == []
        assert client.request_count == 1


@pytest.mark.asyncio
async def test_api_rate_limit_skips_parameterised_endpoints(make_bundle, client_factory):
    ctx = _context(make_bundle, profile="active")
    ctx.endpoints = [_endpoint(url="https://example.com/api/search?q=x", parameters=["q"])]
    async with client_factory(lambda request: httpx.Response(200)) as client:
        ctx.client = client
        assert await ApiRateLimitCheck().run(ctx) == []
        assert client.request_count == 0


def _jwt(header: dict, claims: dict, signature: str = "sig") -> str:
    def segment(value: dict) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    return f"{segment(header)}.{segment(claims)}.{signature}"


@pytest.mark.asyncio
async def test_api_spec_flags_public_write_operations(make_bundle):
    ctx = _context(make_bundle)
    _spec(
        ctx,
        declared_auth=True,
        public_writes=[{"path": "/items", "method": "POST"}],
        public_write_count=1,
    )
    findings = await ApiSpecRiskCheck().run(ctx)

    assert [f.parameter for f in findings] == ["security"]
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].verification_status is VerificationStatus.VERIFIED
    assert findings[0].response_evidence["operations"] == [{"method": "POST", "path": "/items"}]


@pytest.mark.asyncio
async def test_api_spec_ignores_public_writes_without_declared_auth(make_bundle):
    ctx = _context(make_bundle)
    _spec(
        ctx,
        declared_auth=False,
        public_writes=[{"path": "/items", "method": "POST"}],
        public_write_count=1,
    )
    assert await ApiSpecRiskCheck().run(ctx) == []


@pytest.mark.asyncio
async def test_api_spec_flags_query_key_and_implicit_oauth(make_bundle):
    ctx = _context(make_bundle)
    _spec(ctx, api_key_query_schemes=["apiKeyAuth"], oauth_implicit=["oauth"])
    findings = await ApiSpecRiskCheck().run(ctx)

    assert [f.payload for f in findings] == ["api_key_query", "oauth_implicit"]
    assert all(f.severity is Severity.LOW for f in findings)


@pytest.mark.asyncio
async def test_api_unauth_flags_success_without_credentials(make_bundle, client_factory):
    ctx = _context(make_bundle)
    _spec(ctx, declared_auth=True, protected_gets=[{"path": "/items", "method": "GET"}])
    async with client_factory(lambda request: httpx.Response(200, json={"items": []})) as client:
        ctx.client = client
        findings = await ApiUnauthenticatedCheck().run(ctx)

    assert [f.check_id for f in findings] == ["venom.api.unauth"]
    assert findings[0].verification_status is VerificationStatus.SUSPECTED
    assert findings[0].request_evidence["credentials"] == "none"
    assert findings[0].response_evidence["body_stored"] is False


@pytest.mark.asyncio
async def test_api_unauth_accepts_rejected_and_non_json_answers(make_bundle, client_factory):
    ctx = _context(make_bundle)
    _spec(ctx, declared_auth=True, protected_gets=[{"path": "/items", "method": "GET"}])

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/items":
            return httpx.Response(401, json={"error": "unauthorized"})
        return httpx.Response(200, headers={"Content-Type": "text/html"}, text="<html>login</html>")

    async with client_factory(handler) as client:
        ctx.client = client
        assert await ApiUnauthenticatedCheck().run(ctx) == []


@pytest.mark.asyncio
async def test_jwt_check_flags_unsigned_token_without_storing_it(make_bundle):
    token = _jwt({"alg": "none"}, {"sub": "1"}, signature="")
    ctx = _context(make_bundle)
    ctx.artifacts["api_samples"] = [
        {
            "url": "https://example.com/api/session",
            "content_type": "application/json",
            "body": json.dumps({"token": token}),
        }
    ]
    findings = await JwtCheck().run(ctx)

    titles = {f.title for f in findings}
    assert "JWT uses alg=none (unsigned token)" in titles
    assert "JWT has no expiry claim" in titles
    assert all(f.check_id == "venom.api.jwt" for f in findings)
    assert all(token not in f.model_dump_json() for f in findings)
    assert ctx.artifacts["api_intel"]["jwt"]["tokens"][0]["flags"] == ["alg_none", "missing_exp"]


@pytest.mark.asyncio
async def test_jwt_check_flags_token_in_query_string(make_bundle):
    token = _jwt({"alg": "HS256"}, {"sub": "1", "exp": time.time() + 3600})
    ctx = _context(make_bundle)
    ctx.endpoints = [EndpointRecord(url=f"https://example.com/cb?token={token}", status_code=200)]
    findings = await JwtCheck().run(ctx)

    assert [f.title for f in findings] == ["JWT transported in a URL query string"]
    assert findings[0].parameter == "url query"
    assert token not in findings[0].model_dump_json()


SCHEMA = {
    "queryType": {"name": "Query"},
    "mutationType": {"name": "Mutation"},
    "types": [
        {"name": "Query", "kind": "OBJECT"},
        {"name": "User", "kind": "OBJECT"},
        {"name": "__Schema", "kind": "OBJECT"},
        {"name": "Role", "kind": "ENUM"},
    ],
}


def _graphql_handler(request: httpx.Request) -> httpx.Response:
    if request.url.path != "/graphql":
        return httpx.Response(404, text="missing")
    if request.method == "POST":
        return httpx.Response(405)
    query = request.url.params.get("query", "")
    if "__schema" in query:
        return httpx.Response(200, json={"data": {"__schema": SCHEMA}})
    if "__typename" in query:
        return httpx.Response(200, json={"data": {"__typename": "Query"}})
    return httpx.Response(
        200,
        headers={"Content-Type": "text/html"},
        text="<html><title>GraphiQL</title></html>",
    )


@pytest.mark.asyncio
async def test_graphql_reports_ide_and_introspection(make_bundle, client_factory):
    ctx = _context(make_bundle)
    ctx.endpoints = [EndpointRecord(url="https://example.com/graphql", status_code=200)]
    async with client_factory(_graphql_handler) as client:
        ctx.client = client
        findings = await GraphqlCheck().run(ctx)

    titles = {f.title: f for f in findings}
    assert titles["GraphQL IDE is exposed"].severity is Severity.LOW
    introspection = titles["GraphQL introspection is enabled"]
    assert introspection.severity is Severity.MEDIUM
    assert introspection.response_evidence["type_count"] == 4
    assert introspection.response_evidence["object_count"] == 3
    assert introspection.response_evidence["mutation_available"] is True
    assert introspection.response_evidence["sample_types"] == ["Query", "User"]

    graphql = ctx.artifacts["api_intel"]["graphql"]
    assert graphql["introspection"] is True
    assert graphql["confirmed"] == ["https://example.com/graphql"]
    assert graphql["probed"] == 1


@pytest.mark.asyncio
async def test_graphql_accepts_disabled_introspection(make_bundle, client_factory):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path != "/graphql":
            return httpx.Response(404)
        if "__schema" in request.url.params.get("query", ""):
            return httpx.Response(200, json={"errors": [{"message": "introspection disabled"}]})
        if "__typename" in request.url.params.get("query", ""):
            return httpx.Response(200, json={"data": {"__typename": "Query"}})
        return httpx.Response(200, json={"status": "ok"})

    ctx = _context(make_bundle)
    ctx.endpoints = [EndpointRecord(url="https://example.com/graphql", status_code=200)]
    async with client_factory(handler) as client:
        ctx.client = client
        assert await GraphqlCheck().run(ctx) == []

    graphql = ctx.artifacts["api_intel"]["graphql"]
    assert graphql["introspection"] is False
    assert graphql["confirmed"] == ["https://example.com/graphql"]


@pytest.mark.asyncio
async def test_graphql_active_profile_retries_with_post(make_bundle, client_factory):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path != "/graphql":
            return httpx.Response(404)
        if request.method == "POST":
            return httpx.Response(200, json={"data": {"__schema": SCHEMA}})
        if "__typename" in request.url.params.get("query", ""):
            return httpx.Response(405, text="method not allowed")
        return httpx.Response(200, json={"status": "ok"})

    ctx = _context(make_bundle, profile="active")
    ctx.endpoints = [EndpointRecord(url="https://example.com/graphql", status_code=200)]
    async with client_factory(handler) as client:
        ctx.client = client
        findings = await GraphqlCheck().run(ctx)

    assert [f.method for f in findings] == ["POST"]
    assert findings[0].title == "GraphQL introspection is enabled"


@pytest.mark.asyncio
async def test_graphql_skips_when_no_endpoint_is_known(make_bundle, client_factory):
    ctx = _context(make_bundle)
    ctx.endpoints = [_endpoint(url="https://example.com/api/items")]
    async with client_factory(lambda request: httpx.Response(200)) as client:
        ctx.client = client
        assert await GraphqlCheck().run(ctx) == []
        assert client.request_count == 0
