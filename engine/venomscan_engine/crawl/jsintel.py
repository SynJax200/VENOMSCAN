from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from venomscan_engine.crawl.html_extract import normalize_url

# sourceMappingURL points at build metadata; the URL is recorded, never fetched.
_SOURCE_MAP = re.compile(r"[#@]\s*sourceMappingURL=([^\s*\"']+)")
_AXIOS_CALL = re.compile(
    r"axios\s*\.\s*(get|post|put|patch|delete|head|options)\s*\(\s*[\"'`]([^\"'`\s]{2,300})",
    re.IGNORECASE,
)
_FETCH_CALL = re.compile(r"fetch\s*\(\s*[\"'`]([^\"'`\s]{2,300})")
_XHR_OPEN = re.compile(
    r"\.open\s*\(\s*[\"'`](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)[\"'`]\s*,\s*[\"'`]([^\"'`\s]{2,300})",
    re.IGNORECASE,
)
_TEMPLATE = re.compile(r"(?:\$\{([^{}]+)\}|\{([A-Za-z_][\w-]*)\}|(?<=/):([A-Za-z_][\w-]*))")
_SENSITIVE = re.compile(
    r"/(?:admin|internal|debug|config|token|secret|private|backup|graphql|actuator)(?:/|$)",
    re.IGNORECASE,
)
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")

MAX_SOURCE_MAPS = 8
MAX_PARAMETERS = 40
MAX_HOSTS = 10
MAX_PATHS = 12
MAX_METHODS = 200


def source_maps(body: str, base_url: str) -> list[dict]:
    found: list[dict] = []
    base_host = urlsplit(base_url).hostname or ""
    for match in _SOURCE_MAP.finditer(body):
        # Bundlers sometimes emit the comment inside a template string, so the capture keeps
        # escaped newlines, stray ";" separators and the next comment marker after the URL.
        raw = re.split(r"\\|//#|/\*#", match.group(1))[0].strip().rstrip(";")
        if raw.lower().startswith(("data:", "blob:")):
            continue
        if raw.endswith(".map/"):
            raw = raw.rstrip("/")
        resolved = normalize_url(base_url, raw) or urljoin(base_url, raw)
        if urlsplit(resolved).scheme not in {"http", "https"}:
            continue
        host = urlsplit(resolved).hostname or ""
        entry = {"url": resolved[:300], "same_origin": host == base_host}
        if all(existing["url"] != entry["url"] for existing in found):
            found.append(entry)
        if len(found) >= MAX_SOURCE_MAPS:
            break
    return found


def call_methods(body: str, base_url: str) -> dict[str, str]:
    """Best-effort HTTP method for each URL referenced by fetch/axios/XHR."""
    methods: dict[str, str] = {}
    for method, candidate in _AXIOS_CALL.findall(body):
        normalized = normalize_url(base_url, candidate)
        if normalized:
            methods.setdefault(normalized, method.upper())
    for candidate in _FETCH_CALL.findall(body):
        normalized = normalize_url(base_url, candidate)
        if normalized:
            methods.setdefault(normalized, "GET")
    for method, candidate in _XHR_OPEN.findall(body):
        normalized = normalize_url(base_url, candidate)
        if normalized:
            methods[normalized] = method.upper()
    return methods


def template_parameters(url: str) -> list[str]:
    names: list[str] = []
    for match in _TEMPLATE.finditer(url):
        raw = next((group for group in match.groups() if group), "")
        name = re.split(r"[?.[]", raw.strip())[0].strip()
        if not name or not _IDENTIFIER.match(name) or name in names:
            continue
        names.append(name)
    return names


def sensitive_paths(urls: list[str]) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for url in urls:
        path = urlsplit(url).path
        match = _SENSITIVE.search(path)
        if match is None:
            continue
        keyword = match.group(0).strip("/").lower()
        if keyword in seen:
            continue
        seen.add(keyword)
        found.append(path)
        if len(found) >= MAX_PATHS:
            break
    return found


def analyze_script(base_url: str, body: str) -> dict:
    """Static, offline analysis of one fetched script. No extra requests."""
    return {
        "source_maps": source_maps(body, base_url),
        "methods": call_methods(body, base_url),
    }


def merge_script_intel(artifact: dict, analysis: dict) -> None:
    artifact["scripts"] = artifact.get("scripts", 0) + 1
    maps = artifact.setdefault("source_maps", [])
    for entry in analysis.get("source_maps", []):
        if len(maps) >= MAX_SOURCE_MAPS:
            break
        if any(existing["url"] == entry["url"] for existing in maps):
            continue
        maps.append(entry)
    meta = artifact.setdefault("methods", {})
    for url, method in analysis.get("methods", {}).items():
        if len(meta) >= MAX_METHODS:
            break
        meta.setdefault(url, method)


def summarize(artifact: dict, urls: list[str], base_url: str) -> dict:
    """Fold extracted URLs into the artifact and return the JSON payload."""
    host = urlsplit(base_url).hostname or ""
    api_like = [url for url in urls if "/api" in urlsplit(url).path.lower()]
    graphql = [url for url in urls if "graphql" in url.lower() or "/gql" in url.lower()]
    third_party: list[str] = []
    for url in urls:
        other = urlsplit(url).hostname or ""
        if other and other != host and other not in third_party:
            third_party.append(other)
        if len(third_party) >= MAX_HOSTS:
            break
    parameters: list[str] = list(artifact.get("parameters", []))
    for url in urls:
        for name in template_parameters(url):
            if name not in parameters and len(parameters) < MAX_PARAMETERS:
                parameters.append(name)
    paths = sorted(set(sensitive_paths(urls)) | set(artifact.get("sensitive_paths", [])))[:MAX_PATHS]
    methods = artifact.get("methods", {})
    artifact.update(
        {
            "api_calls": len(api_like),
            "graphql_endpoints": graphql[:MAX_PATHS],
            "third_party_hosts": third_party,
            "sensitive_paths": paths,
            "parameters": parameters,
            "post_calls": sum(1 for method in methods.values() if method != "GET"),
        }
    )
    return artifact


__all__ = [
    "MAX_HOSTS",
    "MAX_PARAMETERS",
    "MAX_PATHS",
    "MAX_SOURCE_MAPS",
    "analyze_script",
    "call_methods",
    "merge_script_intel",
    "sensitive_paths",
    "source_maps",
    "summarize",
    "template_parameters",
]
