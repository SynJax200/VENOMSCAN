from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

from venomscan_engine.intel.jwt import collect

MAX_PUBLIC_WRITES = 25
MAX_PROTECTED_GETS = 25
MAX_DEPRECATED = 15
MAX_SPEC_PATHS = 200
MAX_SERVERS = 3
MAX_CLUSTER_CANDIDATES = 3
_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
_GRAPHQL_PATH = re.compile(r"(?i)(?:^|/)(?:graphql|gql)(?:/|$)")


def _security_schemes(document: dict) -> list[dict]:
    raw: dict = {}
    components = document.get("components")
    if isinstance(components, dict) and isinstance(components.get("securitySchemes"), dict):
        raw = components["securitySchemes"]
    elif isinstance(document.get("securityDefinitions"), dict):
        raw = document["securityDefinitions"]
    schemes: list[dict] = []
    for name, spec in list(raw.items())[:20]:
        if not isinstance(spec, dict):
            continue
        kind = str(spec.get("type") or "").lower()
        location = str(spec.get("in") or "").lower()
        if kind == "oauth2":
            flows = spec.get("flows") if isinstance(spec.get("flows"), dict) else {}
            if "implicit" in flows or str(spec.get("flow") or "").lower() == "implicit":
                location = "implicit"
        schemes.append({"name": str(name)[:60], "type": kind, "in": location})
    return schemes


def _servers(document: dict) -> list[str]:
    out: list[str] = []
    raw = document.get("servers")
    if isinstance(raw, list):
        for item in raw[:MAX_SERVERS]:
            if isinstance(item, dict) and isinstance(item.get("url"), str):
                out.append(item["url"][:200])
    if not out:
        host = document.get("host")
        if isinstance(host, str) and host:
            base = document.get("basePath") if isinstance(document.get("basePath"), str) else ""
            schemes = document.get("schemes") if isinstance(document.get("schemes"), list) else []
            scheme = schemes[0] if schemes else "https"
            out.append(f"{scheme}://{host}{base}"[:200])
    return out


def _requires_auth(operation: dict, global_security: list) -> bool:
    if "security" in operation:
        value = operation.get("security")
        return bool(value)
    return bool(global_security)


def summarize_spec(document: dict, *, target_host: str = "") -> dict:
    """Per-document auth posture with bounded evidence, computed once at crawl time."""
    paths = document.get("paths") if isinstance(document.get("paths"), dict) else {}
    global_security = document.get("security") if isinstance(document.get("security"), list) else []
    public_writes: list[dict] = []
    protected_gets: list[dict] = []
    deprecated: list[dict] = []
    by_method: dict[str, int] = {}
    public_reads = 0

    for path, operations in list(paths.items())[:MAX_SPEC_PATHS]:
        if not isinstance(path, str) or not isinstance(operations, dict):
            continue
        for method, operation in operations.items():
            if method.lower() not in _HTTP_METHODS:
                continue
            upper = method.upper()
            by_method[upper] = by_method.get(upper, 0) + 1
            if not isinstance(operation, dict):
                continue
            if operation.get("deprecated") is True:
                deprecated.append({"path": path[:120], "method": upper})
            if _requires_auth(operation, global_security):
                if upper in {"GET", "HEAD"}:
                    protected_gets.append({"path": path[:120], "method": upper})
                continue
            if upper in {"GET", "HEAD"}:
                public_reads += 1
            else:
                public_writes.append({"path": path[:120], "method": upper})

    schemes = _security_schemes(document)
    host = urlsplit(str(document.get("url") or "")).hostname or ""
    cross_origin = [
        server for server in _servers(document) if urlsplit(server).hostname not in (None, "", host)
    ]
    return {
        "operations_by_method": by_method,
        "public_writes": public_writes[:MAX_PUBLIC_WRITES],
        "public_write_count": len(public_writes),
        "public_reads": public_reads,
        "protected_gets": protected_gets[:MAX_PROTECTED_GETS],
        "protected_get_count": len(protected_gets),
        "api_key_query_schemes": [
            scheme["name"] for scheme in schemes if scheme["type"] == "apikey" and scheme["in"] == "query"
        ],
        "oauth_implicit": [
            scheme["name"] for scheme in schemes if scheme["type"] == "oauth2" and scheme["in"] == "implicit"
        ],
        "cross_origin_servers": cross_origin[:MAX_SERVERS],
        "deprecated_operations": deprecated[:MAX_DEPRECATED],
        "deprecated_count": len(deprecated),
    }


def aggregate_spec(documents: list[dict]) -> dict:
    summary = {
        "documents": 0,
        "routes": 0,
        "operations": 0,
        "public_write_count": 0,
        "public_writes": [],
        "public_reads": 0,
        "api_key_query_schemes": [],
        "oauth_implicit": [],
        "cross_origin_servers": [],
        "deprecated_count": 0,
        "operations_by_method": {},
    }
    for document in documents:
        if not isinstance(document, dict):
            continue
        summary["documents"] += 1
        summary["routes"] += int(document.get("paths") or 0)
        summary["operations"] += int(document.get("operations") or 0)
        summary["public_write_count"] += int(document.get("public_write_count") or 0)
        summary["public_reads"] += int(document.get("public_reads") or 0)
        summary["deprecated_count"] += int(document.get("deprecated_count") or 0)
        summary["public_writes"].extend(document.get("public_writes") or [])
        for key in ("api_key_query_schemes", "oauth_implicit", "cross_origin_servers"):
            for value in document.get(key) or []:
                if value not in summary[key]:
                    summary[key].append(value)
        for method, count in (document.get("operations_by_method") or {}).items():
            summary["operations_by_method"][method] = summary["operations_by_method"].get(method, 0) + int(count)
    return summary


def graphql_candidates(
    endpoints: list, js_intel: dict | None, *, target_host: str = "", cap: int = MAX_CLUSTER_CANDIDATES
) -> list[str]:
    """GraphQL URLs already referenced by the crawl; never guessed beyond the surface."""
    urls: list[str] = []
    for url in (js_intel or {}).get("graphql_endpoints") or []:
        if isinstance(url, str):
            urls.append(url)
    for endpoint in endpoints:
        url = getattr(endpoint, "url", "") or ""
        if _GRAPHQL_PATH.search(urlsplit(url).path):
            urls.append(url)

    found: list[str] = []
    for url in urls:
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"}:
            continue
        if target_host and parts.hostname != target_host:
            continue
        clean = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        if clean not in found:
            found.append(clean)
        if len(found) >= cap:
            break
    return found


def build_api_intel(
    documents: list[dict],
    api_samples: list[dict] | None,
    endpoints: list,
    set_cookies: list[str] | None = None,
    js_intel: dict | None = None,
    *,
    target_host: str = "",
    now: float | None = None,
) -> dict:
    return {
        "spec": aggregate_spec(documents),
        "jwt": {"tokens": collect(api_samples or [], endpoints, set_cookies, now=now)},
        "graphql": {
            "candidates": graphql_candidates(endpoints, js_intel, target_host=target_host),
            "probed": 0,
            "confirmed": [],
            "introspection": False,
            "ide": False,
            "type_count": 0,
            "object_count": 0,
            "mutation_available": False,
            "sample_types": [],
        },
    }


__all__ = [
    "aggregate_spec",
    "build_api_intel",
    "graphql_candidates",
    "summarize_spec",
]
