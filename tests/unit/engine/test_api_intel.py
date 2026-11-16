from __future__ import annotations

from venomscan_engine.intel.api import (
    aggregate_spec,
    build_api_intel,
    graphql_candidates,
    summarize_spec,
)

SPEC = {
    "openapi": "3.1.0",
    "url": "https://example.com/openapi.json",
    "security": [{"bearerAuth": []}],
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer"},
            "apiKeyAuth": {"type": "apiKey", "in": "query", "name": "key"},
            "oauth": {"type": "oauth2", "flows": {"implicit": {"authorizationUrl": "https://a"}}},
        }
    },
    "servers": [{"url": "https://api.example.com/v1"}],
    "paths": {
        "/items": {
            "get": {},
            "post": {"security": []},
        },
        "/admin/users": {
            "delete": {"security": [{"bearerAuth": []}], "deprecated": True},
        },
        "/public": {
            "get": {"security": []},
        },
    },
}


def test_summarize_spec_separates_public_writes_from_protected_gets():
    summary = summarize_spec(SPEC)

    assert summary["operations_by_method"] == {"GET": 2, "POST": 1, "DELETE": 1}
    assert summary["public_writes"] == [{"path": "/items", "method": "POST"}]
    assert summary["public_write_count"] == 1
    assert summary["public_reads"] == 1
    assert [item["path"] for item in summary["protected_gets"]] == ["/items"]
    assert summary["protected_get_count"] == 1


def test_summarize_spec_flags_query_key_and_implicit_oauth():
    summary = summarize_spec(SPEC)

    assert summary["api_key_query_schemes"] == ["apiKeyAuth"]
    assert summary["oauth_implicit"] == ["oauth"]
    assert summary["cross_origin_servers"] == ["https://api.example.com/v1"]
    assert summary["deprecated_count"] == 1
    assert summary["deprecated_operations"] == [{"path": "/admin/users", "method": "DELETE"}]


def test_summarize_spec_inherits_global_security_and_honours_swagger2():
    swagger = {
        "swagger": "2.0",
        "url": "https://example.com/swagger.json",
        "host": "example.com",
        "basePath": "/v2",
        "security": [{"key": []}],
        "securityDefinitions": {"key": {"type": "apiKey", "in": "header", "name": "X-Key"}},
        "paths": {"/orders": {"post": {}}, "/status": {"get": {"security": []}}},
    }
    summary = summarize_spec(swagger)

    assert summary["public_writes"] == []
    assert summary["public_reads"] == 1
    assert [item["path"] for item in summary["protected_gets"]] == []
    assert summary["api_key_query_schemes"] == []
    assert summary["cross_origin_servers"] == []


def test_aggregate_spec_sums_documents():
    other = summarize_spec(
        {
            "url": "https://example.com/v2/openapi.json",
            "security": [{"key": []}],
            "paths": {"/b": {"put": {"security": []}}},
        }
    )
    summary = aggregate_spec([summarize_spec(SPEC), {"paths": 2, "url": "", **other}])

    assert summary["documents"] == 2
    assert summary["routes"] == 2
    assert summary["public_write_count"] == 2
    assert summary["deprecated_count"] == 1
    assert summary["operations_by_method"] == {"GET": 2, "POST": 1, "DELETE": 1, "PUT": 1}


def test_graphql_candidates_come_from_js_and_endpoints_only():
    class Endpoint:
        def __init__(self, url: str) -> None:
            self.url = url

    endpoints = [
        Endpoint("https://example.com/graphql"),
        Endpoint("https://example.com/api/gql/"),
        Endpoint("https://example.com/api/users"),
        Endpoint("https://cdn.example.net/graphql"),
    ]
    js_intel = {"graphql_endpoints": ["https://example.com/graphql?x=1"]}

    candidates = graphql_candidates(endpoints, js_intel, target_host="example.com")
    assert candidates == ["https://example.com/graphql", "https://example.com/api/gql/"]

    capped = graphql_candidates(endpoints, {}, target_host="example.com", cap=1)
    assert capped == ["https://example.com/graphql"]


def test_build_api_intel_shapes_the_artifact():
    class Endpoint:
        url = "https://example.com/graphql"

    intel = build_api_intel(
        [{"paths": 3, "operations": 5, "url": "https://example.com/openapi.json"}],
        [],
        [Endpoint()],
        [],
        {},
        target_host="example.com",
    )
    assert intel["spec"]["routes"] == 3
    assert intel["jwt"]["tokens"] == []
    assert intel["graphql"]["candidates"] == ["https://example.com/graphql"]
    assert intel["graphql"]["introspection"] is False
