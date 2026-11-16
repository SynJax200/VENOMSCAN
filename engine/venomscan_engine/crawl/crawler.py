from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass
from urllib.parse import parse_qsl, urljoin, urlsplit

from venomscan_engine.context import ScanContext
from venomscan_engine.crawl.html_extract import Extraction, extract_document
from venomscan_engine.crawl.js import extract_js_endpoints, is_static_asset
from venomscan_engine.crawl.jsintel import (
    analyze_script,
    merge_script_intel,
    summarize,
    template_parameters,
)
from venomscan_engine.crawl.robots import ALLOW_ALL, RobotsPolicy, parse_robots
from venomscan_engine.crawl.sitemap import looks_like_xml, parse_sitemap
from venomscan_engine.intel.api import summarize_spec
from venomscan_engine.models import EndpointRecord
from venomscan_engine.recon.tech import detect_technologies
from venomscan_engine.safety.http import (
    BudgetExceeded,
    ResponseBundle,
    TargetUnreachable,
    TooManyRedirects,
)
from venomscan_engine.safety.scope import ScopeViolation


@dataclass(frozen=True)
class CrawlLimits:
    max_pages: int
    max_depth: int
    max_path_probes: int = 0
    max_js_files: int = 0
    respect_robots: bool = True


PROFILE_LIMITS: dict[str, CrawlLimits] = {
    "passive": CrawlLimits(max_pages=5, max_depth=1, max_path_probes=0, max_js_files=0),
    "safe": CrawlLimits(max_pages=22, max_depth=2, max_path_probes=6, max_js_files=4),
    "active": CrawlLimits(max_pages=35, max_depth=3, max_path_probes=8, max_js_files=6),
}

# Small, non-destructive probe list: documentation/spec endpoints first because
# they map the API surface cheaply.
PROBE_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/.well-known/security.txt",
    "/api",
    "/login",
    "/admin",
    "/healthz",
)

MAX_API_SPEC_PATHS = 200
MAX_API_SPEC_DOCS = 3
MAX_WARNINGS = 6

# Bounded evidence kept in memory for the analysis phase. Check modules must
# never rely on the crawler retaining every response.
MAX_PAGE_SUMMARIES = 12
MAX_PAGE_BYTES = 8_000
MAX_FORM_SUMMARIES = 40
MAX_SCRIPT_SOURCES = 8
MAX_SCRIPT_BYTES = 120_000
MAX_API_SAMPLES = 6
MAX_API_SAMPLE_BYTES = 4_000


@dataclass
class CrawlReport:
    pages: int = 0
    links: int = 0
    forms: int = 0
    js_files: int = 0
    js_endpoints: int = 0
    probed: int = 0
    api_specs: int = 0
    api_endpoints: int = 0
    robots_found: bool = False
    sitemap_urls: int = 0
    stopped: str = ""

    def as_dict(self) -> dict:
        return {
            "pages": self.pages,
            "links": self.links,
            "forms": self.forms,
            "js_files": self.js_files,
            "js_endpoints": self.js_endpoints,
            "probed": self.probed,
            "api_specs": self.api_specs,
            "api_endpoints": self.api_endpoints,
            "robots_found": self.robots_found,
            "sitemap_urls": self.sitemap_urls,
            "stopped": self.stopped or None,
        }


class Crawler:
    """Bounded breadth-first crawler that only talks through SafeHttpClient."""

    def __init__(self, ctx: ScanContext, limits: CrawlLimits | None = None) -> None:
        self.ctx = ctx
        self.limits = limits or PROFILE_LIMITS.get(ctx.profile, PROFILE_LIMITS["safe"])
        self.policy: RobotsPolicy = ALLOW_ALL
        self.report = CrawlReport()
        self._queue: deque[tuple[str, int, str]] = deque()
        self._seen: set[str] = set()
        self._visited: set[str] = set()
        self._scripts: list[str] = []
        self._warnings = 0

    async def run(self) -> CrawlReport:
        root = self.ctx.root
        if root is None:
            self.report.stopped = "no-root"
            return self.report

        await self._load_robots()
        await self._load_sitemaps()

        content_type = (root.header("content-type") or "").lower()
        self._visited.add(root.url)
        self._seen.add(root.url)
        self.report.pages = 1
        if "html" in content_type:
            self._ingest_html(root.url, root.body, depth=0)
            self._remember_page(root)
        elif "json" in content_type:
            self._remember_api_sample(root)

        await self._crawl_queue()
        await self._crawl_scripts()
        if self.limits.max_path_probes:
            await self._probe_paths()
        return self.report

    # ------------------------------------------------------------------ robots

    async def _load_robots(self) -> None:
        url = urljoin(self._origin(), "/robots.txt")
        bundle = await self._fetch(url)
        if bundle is None:
            return
        self.ctx.add_endpoint(self._endpoint(bundle, source="robots", depth=0))
        content_type = (bundle.header("content-type") or "").lower()
        if bundle.status_code != 200 or "html" in content_type:
            return
        self.policy = parse_robots(bundle.body)
        self.report.robots_found = True
        self.ctx.artifacts["robots"] = {
            "url": bundle.url,
            "allow": list(self.policy.allow),
            "disallow": list(self.policy.disallow),
            "crawl_delay": self.policy.crawl_delay,
            "sitemaps": list(self.policy.sitemaps)[:5],
        }

    async def _load_sitemaps(self) -> None:
        if not self.policy.sitemaps and not self.report.robots_found:
            return
        candidates = list(self.policy.sitemaps) or [urljoin(self._origin(), "/sitemap.xml")]
        for candidate in candidates[:2]:
            if self.ctx.remaining_seconds < 4 or self.report.stopped == "request-budget":
                break
            bundle = await self._fetch(candidate)
            if bundle is None or bundle.status_code != 200:
                continue
            if not looks_like_xml(bundle.body):
                continue
            locations, total = parse_sitemap(bundle.body, bundle.url, limit=200)
            self.report.sitemap_urls = max(self.report.sitemap_urls, total)
            self.ctx.add_endpoint(self._endpoint(bundle, source="sitemap", depth=0))
            for location in locations:
                self._enqueue(location, 1, "sitemap")

    # ------------------------------------------------------------------- crawl

    async def _crawl_queue(self) -> None:
        while self._queue:
            if self.report.pages >= self.limits.max_pages:
                self.report.stopped = "page-cap"
                return
            if self.ctx.remaining_seconds < 4:
                self.report.stopped = "time-budget"
                return
            url, depth, source = self._queue.popleft()
            if url in self._visited:
                continue
            bundle = await self._fetch(url)
            if bundle is None:
                if self.report.stopped == "request-budget":
                    return
                continue
            self._visited.add(url)
            self.report.pages += 1
            self.ctx.add_endpoint(self._endpoint(bundle, source=source, depth=depth))

            content_type = (bundle.header("content-type") or "").lower()
            if looks_like_xml(bundle.body) and "xml" in content_type:
                locations, total = parse_sitemap(bundle.body, bundle.url, limit=100)
                self.report.sitemap_urls = max(self.report.sitemap_urls, total)
                for location in locations:
                    self._enqueue(location, depth, "sitemap")
                continue
            if "html" in content_type:
                document = self._ingest_html(bundle.url, bundle.body, depth=depth)
                self._remember_page(bundle)
                for tech in detect_technologies(bundle):
                    self.ctx.add_technology(tech)
                await self.ctx.emit(
                    "crawling",
                    "page_crawled",
                    f"{urlsplit(bundle.url).path or '/'} → {bundle.status_code}, "
                    f"{len(document.links)} link(s)",
                    payload={
                        "url": bundle.url,
                        "status_code": bundle.status_code,
                        "depth": depth,
                        "links": len(document.links),
                    },
                )
            elif "javascript" in content_type or bundle.url.lower().endswith(".js"):
                self._harvest_js(bundle.url, bundle.body, depth=depth)
            elif "json" in content_type:
                if not self._ingest_api_spec(bundle, depth=depth):
                    self._remember_api_sample(bundle)

    async def _crawl_scripts(self) -> None:
        for script in self._scripts[: self.limits.max_js_files]:
            if self.ctx.remaining_seconds < 4:
                return
            if script in self._visited:
                continue
            bundle = await self._fetch(script)
            if bundle is None:
                if self.report.stopped == "request-budget":
                    return
                continue
            self._visited.add(script)
            self.report.js_files += 1
            self.ctx.add_endpoint(self._endpoint(bundle, source="js", depth=1))
            self._harvest_js(bundle.url, bundle.body, depth=1)
    async def _probe_paths(self) -> None:
        for path in PROBE_PATHS[: self.limits.max_path_probes]:
            if self.ctx.remaining_seconds < 4:
                self.report.stopped = "time-budget"
                return
            url = urljoin(self._origin(), path)
            if (
                url in self._visited
                or is_static_asset(url)
                or (self.limits.respect_robots and not self.policy.allows(url))
            ):
                continue
            bundle = await self._fetch(url)
            if bundle is None:
                if self.report.stopped == "request-budget":
                    return
                continue
            self._visited.add(url)
            self.report.probed += 1
            self.ctx.add_endpoint(self._endpoint(bundle, source="probe", depth=1))
            if bundle.status_code == 200 and (
                path.endswith("openapi.json") or path.endswith("swagger.json")
            ):
                self._ingest_api_spec(bundle, depth=1)

    # ------------------------------------------------------------------ helpers

    def _origin(self) -> str:
        parts = urlsplit(self.ctx.target_url)
        return f"{parts.scheme}://{parts.netloc}"

    def _endpoint(self, bundle: ResponseBundle, *, source: str, depth: int) -> EndpointRecord:
        parameters = [name for name, _ in parse_qsl(urlsplit(bundle.url).query, keep_blank_values=True)]
        return EndpointRecord(
            url=bundle.url,
            method="GET",
            source=source,
            status_code=bundle.status_code,
            content_type=bundle.header("content-type"),
            depth=depth,
            parameters=list(dict.fromkeys(parameters)),
        )

    def _ingest_html(self, url: str, body: str, depth: int) -> Extraction:
        document = extract_document(url, body)
        self.report.links += len(document.links)
        self.report.forms += len(document.forms)
        self._remember_forms(url, document)

        for form in document.forms:
            if form.method not in {"GET", "POST"} or not form.action:
                continue
            self.ctx.add_endpoint(
                EndpointRecord(
                    url=form.action,
                    method=form.method,
                    source="form",
                    depth=depth,
                    parameters=form.parameter_names,
                )
            )
        for link in document.links:
            self._enqueue(link, depth + 1, "crawl")
        for inline in document.inline_scripts:
            self._harvest_js(url, inline, depth=depth, inline=True)
        for script in document.scripts:
            self._enqueue_script(script)
        return document

    def _enqueue(self, url: str, depth: int, source: str) -> None:
        if depth > self.limits.max_depth or is_static_asset(url):
            return
        if url in self._seen or url in self._visited:
            return
        try:
            self.ctx.scope.check(url)
        except ScopeViolation:
            return
        if self.limits.respect_robots and not self.policy.allows(url):
            return
        self._seen.add(url)
        self._queue.append((url, depth, source))

    def _enqueue_script(self, url: str) -> None:
        if len(self._scripts) >= self.limits.max_js_files or url in self._scripts:
            return
        try:
            self.ctx.scope.check(url)
        except ScopeViolation:
            return
        self._scripts.append(url)

    def _harvest_js(self, base_url: str, body: str, *, depth: int, inline: bool = False) -> None:
        found = extract_js_endpoints(body, base_url)
        self.report.js_endpoints += len(found)
        self._remember_script(base_url, body, inline=inline)
        intel = self.ctx.artifacts.setdefault("js_intel", {})
        merge_script_intel(intel, analyze_script(base_url, body))
        summarize(intel, found, self.ctx.target_url)
        methods = intel.get("methods", {})
        for url in found:
            try:
                self.ctx.scope.check(url)
            except ScopeViolation:
                continue
            parameters = [
                name
                for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)
            ]
            parameters.extend(template_parameters(url))
            self.ctx.add_endpoint(
                EndpointRecord(
                    url=url,
                    method=methods.get(url, "GET"),
                    source="js",
                    depth=depth + 1,
                    parameters=list(dict.fromkeys(parameters)),
                )
            )

    def _remember_script(self, base_url: str, body: str, *, inline: bool) -> None:
        sources = self.ctx.artifacts.setdefault("scripts", [])
        if len(sources) >= MAX_SCRIPT_SOURCES or not body.strip():
            return
        label = f"{base_url}#inline-{len(sources)}" if inline else base_url
        if any(source["url"] == label for source in sources):
            return
        sources.append({"url": label, "inline": inline, "body": body[:MAX_SCRIPT_BYTES]})

    def _remember_page(self, bundle: ResponseBundle) -> None:
        pages = self.ctx.artifacts.setdefault("pages", [])
        if len(pages) >= MAX_PAGE_SUMMARIES:
            return
        if any(page["url"] == bundle.url for page in pages):
            return
        pages.append(
            {
                "url": bundle.url,
                "status_code": bundle.status_code,
                "content_type": bundle.header("content-type") or "",
                "cache_control": bundle.header("cache-control") or "",
                "pragma": bundle.header("pragma") or "",
                "set_cookie": bool(bundle.set_cookies),
                "set_cookie_names": [
                    cookie.split("=", 1)[0].strip()
                    for cookie in bundle.set_cookies
                    if "=" in cookie
                ][:10],
                "body": bundle.body[:MAX_PAGE_BYTES],
            }
        )

    def _remember_forms(self, page_url: str, document: Extraction) -> None:
        forms = self.ctx.artifacts.setdefault("forms", [])
        for form in document.forms:
            if len(forms) >= MAX_FORM_SUMMARIES:
                return
            entry = {
                "page": page_url,
                "action": form.action,
                "method": form.method,
                "fields": [
                    {
                        "name": field.name,
                        "type": field.type,
                        "autocomplete": field.autocomplete,
                    }
                    for field in form.fields
                ],
            }
            if any(
                existing["page"] == entry["page"]
                and existing["action"] == entry["action"]
                and existing["method"] == entry["method"]
                for existing in forms
            ):
                continue
            forms.append(entry)

    async def _fetch(self, url: str) -> ResponseBundle | None:
        try:
            return await self.ctx.client.get(url)
        except BudgetExceeded:
            self.report.stopped = "request-budget"
            return None
        except (TargetUnreachable, TooManyRedirects, ScopeViolation) as exc:
            if self._warnings < MAX_WARNINGS:
                self._warnings += 1
                await self.ctx.emit(
                    "crawling",
                    "warning",
                    f"Skipped {urlsplit(url).path or '/'}: {str(exc)[:160]}",
                )
            return None

    def _remember_api_sample(self, bundle: ResponseBundle) -> None:
        samples = self.ctx.artifacts.setdefault("api_samples", [])
        if len(samples) >= MAX_API_SAMPLES or not bundle.body.strip():
            return
        if any(sample["url"] == bundle.url for sample in samples):
            return
        samples.append(
            {
                "url": bundle.url,
                "content_type": bundle.header("content-type") or "",
                "body": bundle.body[:MAX_API_SAMPLE_BYTES],
            }
        )

    def _ingest_api_spec(self, bundle: ResponseBundle, *, depth: int) -> bool:
        document = self._parse_api_spec(bundle.body)
        if not document:
            return False
        discovered = self._spec_operations(document, bundle.url)
        if not discovered:
            return False
        self.report.api_specs += 1
        self.report.api_endpoints += len(discovered)
        self._remember_api_spec(bundle, document, operations=len(discovered))
        for spec_url, method in discovered:
            self.ctx.add_endpoint(
                EndpointRecord(url=spec_url, method=method, source="api-spec", depth=depth)
            )
        return True

    def _remember_api_spec(
        self, bundle: ResponseBundle, document: dict, *, operations: int
    ) -> None:
        artifact = self.ctx.artifacts.get("openapi")
        if not isinstance(artifact, dict):
            artifact = {"documents": [], "endpoint_count": 0}
            self.ctx.artifacts["openapi"] = artifact
        artifact["endpoint_count"] = artifact.get("endpoint_count", 0) + operations
        documents = artifact.setdefault("documents", [])
        if len(documents) >= MAX_API_SPEC_DOCS:
            return
        if any(doc["url"] == bundle.url for doc in documents):
            return
        info = document.get("info") if isinstance(document.get("info"), dict) else {}
        paths = document.get("paths") if isinstance(document.get("paths"), dict) else {}
        servers = self._spec_servers(document)
        schemes = self._spec_security_schemes(document)
        entry = {
            "url": bundle.url,
            "title": str(info.get("title") or "")[:120],
            "version": str(info.get("version") or "")[:40],
            "spec_version": str(document.get("openapi") or document.get("swagger") or "")[:20],
            "paths": len(paths),
            "operations": operations,
            "servers": servers[:3],
            "security_schemes": schemes,
            "global_security": bool(document.get("security")),
            "declared_auth": bool(schemes) or bool(document.get("security")),
        }
        entry.update(summarize_spec({**document, "url": bundle.url}))
        documents.append(entry)

    def _parse_api_spec(self, body: str) -> dict | None:
        try:
            document = json.loads(body)
        except (ValueError, TypeError):
            return None
        if not isinstance(document, dict) or not isinstance(document.get("paths"), dict):
            return None
        return document

    def _spec_operations(self, document: dict, base_url: str) -> list[tuple[str, str]]:
        paths = document.get("paths")
        if not isinstance(paths, dict):
            return []
        found: list[tuple[str, str]] = []
        for path, operations in list(paths.items())[:MAX_API_SPEC_PATHS]:
            if not isinstance(path, str):
                continue
            methods = (
                [method.upper() for method in operations if isinstance(operations, dict)]
                if isinstance(operations, dict)
                else []
            )
            for method in methods or ["GET"]:
                if method in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
                    found.append((urljoin(base_url, path), method))
        return found[:MAX_API_SPEC_PATHS]

    def _spec_servers(self, document: dict) -> list[str]:
        servers: list[str] = []
        raw = document.get("servers")
        if isinstance(raw, list):
            for item in raw[:3]:
                if isinstance(item, dict) and isinstance(item.get("url"), str):
                    servers.append(item["url"][:200])
        if not servers:
            host = document.get("host")
            if isinstance(host, str) and host:
                base = document.get("basePath") if isinstance(document.get("basePath"), str) else ""
                schemes = document.get("schemes")
                if not isinstance(schemes, list) or not schemes:
                    schemes = ["http"]
                for scheme in schemes[:2]:
                    servers.append(f"{scheme}://{host}{base}"[:200])
        return servers

    def _spec_security_schemes(self, document: dict) -> list[str]:
        components = document.get("components")
        definitions = (
            components.get("securitySchemes")
            if isinstance(components, dict)
            else document.get("securityDefinitions")
        )
        if not isinstance(definitions, dict):
            return []
        schemes: list[str] = []
        for name, definition in list(definitions.items())[:8]:
            if not isinstance(definition, dict):
                continue
            kind = str(definition.get("type") or "")
            detail = str(definition.get("scheme") or definition.get("in") or "")
            schemes.append(f"{name}:{kind}{f'/{detail}' if detail else ''}"[:80])
        return schemes


__all__ = ["CrawlLimits", "CrawlReport", "Crawler", "PROFILE_LIMITS", "PROBE_PATHS"]
