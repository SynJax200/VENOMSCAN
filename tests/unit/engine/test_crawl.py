from __future__ import annotations

import json
from urllib.parse import urlsplit

import httpx
import pytest
from venomscan_engine.crawl import CrawlLimits
from venomscan_engine.crawl.html_extract import extract_document
from venomscan_engine.crawl.js import extract_js_endpoints
from venomscan_engine.crawl.robots import parse_robots
from venomscan_engine.crawl.sitemap import parse_sitemap
from venomscan_engine.events import CollectingSink
from venomscan_engine.pipeline import run_scan


def test_html_extraction_resolves_links_forms_and_scripts():
    body = """
    <html><head>
      <link rel="stylesheet" href="/app.css">
      <script src="/static/app.js"></script>
      <meta name="generator" content="Next.js">
    </head><body>
      <a href="/about?ref=nav">About</a>
      <a href="mailto:security@example.com">mail</a>
      <a href="javascript:void(0)">js</a>
      <a href="https://evil.test/out">external</a>
      <form action="/login?next=/home" method="post">
        <input name="email"><input type="password" name="password"><button name="submit">Go</button>
      </form>
      <script>fetch("/api/users?active=1")</script>
    </body></html>
    """
    document = extract_document("https://example.com/base/page", body)

    assert "https://example.com/about?ref=nav" in document.links
    assert "https://evil.test/out" in document.links
    assert not any(link.startswith("mailto:") for link in document.links)
    assert document.scripts == ["https://example.com/static/app.js"]
    assert document.forms[0].action == "https://example.com/login?next=/home"
    assert document.forms[0].method == "POST"
    assert document.forms[0].parameter_names == ["email", "password", "submit"]
    assert "generator: Next.js" in document.comments
    assert any("/api/users?active=1" in script for script in document.inline_scripts)


def test_robots_longest_match_and_sitemaps():
    policy = parse_robots(
        """
        User-agent: *
        Disallow: /admin
        Allow: /admin/public
        Disallow: /*.pdf$
        Crawl-delay: 1.5

        Sitemap: https://example.com/sitemap.xml
        """
    )
    assert policy.allows("/admin/public/report")
    assert not policy.allows("/admin/private")
    assert policy.allows("/about")
    assert not policy.allows("/docs/manual.pdf")
    assert policy.crawl_delay == 1.5
    assert policy.sitemaps == ("https://example.com/sitemap.xml",)


def test_robots_prefers_specific_agent():
    policy = parse_robots(
        """
        User-agent: *
        Allow: /

        User-agent: venomscan
        Disallow: /
        """
    )
    assert not policy.allows("/anything")


def test_sitemap_urlset_and_index():
    urlset = """<?xml version="1.0"?>
      <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
        <url><loc>https://example.com/one</loc></url>
        <url><loc>/two</loc></url>
      </urlset>"""
    locations, total = parse_sitemap(urlset, "https://example.com/")
    assert total == 2
    assert locations == ["https://example.com/one", "https://example.com/two"]

    index = """<sitemapindex><sitemap><loc>https://example.com/sm-1.xml</loc></sitemap></sitemapindex>"""
    locations, total = parse_sitemap(index, "https://example.com/")
    assert locations == ["https://example.com/sm-1.xml"] and total == 1

    assert parse_sitemap("not xml", "https://example.com/") == ([], 0)


def test_js_endpoint_extraction_filters_assets():
    body = """
    fetch("/api/users?page=1");
    axios.get('https://example.com/api/v1/items');
    const img = "/static/logo.png";
    const route = "/dashboard/settings";
    """
    found = extract_js_endpoints(body, "https://example.com/app/main.js")
    assert "https://example.com/api/users?page=1" in found
    assert "https://example.com/api/v1/items" in found
    assert "https://example.com/dashboard/settings" in found
    assert not any(item.endswith(".png") for item in found)


def test_js_endpoint_extraction_drops_route_regex_noise():
    body = """
    const routes = ["/", "/(.+?)", "/([^/]+?)", "^/api$", "/api/users/${id}/posts"];
    """
    found = extract_js_endpoints(body, "https://example.com/app.js")

    assert "https://example.com/api/users/${id}/posts" in found
    assert not any("(.+?)" in item or "([^/]+?)" in item or "api$" in item for item in found)


def _site_handler(seen: list[str]):
    def handler(request: httpx.Request) -> httpx.Response:
        path = urlsplit(str(request.url)).path
        seen.append(path)
        if path == "/robots.txt":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/plain"},
                text="User-agent: *\nDisallow: /b\nSitemap: https://example.com/sitemap.xml",
            )
        if path == "/sitemap.xml":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/xml"},
                text='<urlset><url><loc>https://example.com/sm-page</loc></url></urlset>',
            )
        if path == "/openapi.json":
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                text=json.dumps(
                    {
                        "openapi": "3.0.3",
                        "info": {"title": "Fixture API", "version": "2.1"},
                        "servers": [{"url": "https://api.example.com/v2"}],
                        "components": {
                            "securitySchemes": {
                                "bearerAuth": {"type": "http", "scheme": "bearer"}
                            }
                        },
                        "security": [{"bearerAuth": []}],
                        "paths": {"/v1/a": {"get": {}}, "/v1/b": {"post": {}, "delete": {}}},
                    }
                ),
            )
        if path == "/static/app.js":
            return httpx.Response(
                200,
                headers={"Content-Type": "application/javascript"},
                text=(
                    'fetch("/api/hidden"); const u = "/api/items?id=1";\n'
                    'axios.post("/api/save", {ok: true});\n'
                    'const route = "/api/users/${id}/posts";\n'
                    'fetch("https://cdn.example.net/collect");\n'
                    "//# sourceMappingURL=app.js.map\n"
                ),
            )
        if path == "/a":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                text='<html><a href="/c">c</a></html>',
            )
        if path in {"/c", "/search", "/sm-page"}:
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text="<html>ok</html>")
        if path == "/":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                text="""
                <html><body>
                  <a href="/a">a</a>
                  <a href="/b?x=1">blocked</a>
                  <a href="/search?q=venom&page=2">search</a>
                  <a href="/openapi.json">api docs</a>
                  <a href="https://evil.test/x">out</a>
                  <form method="post" action="/login"><input name="email"></form>
                  <script src="/static/app.js"></script>
                </body></html>
                """,
            )
        return httpx.Response(404, headers={"Content-Type": "text/html"}, text="<html>404</html>")

    return handler


@pytest.mark.asyncio
async def test_crawler_discovers_surface_within_budgets(public_resolver):
    seen: list[str] = []
    sink = CollectingSink()
    result = await run_scan(
        "scan-crawl",
        "https://example.com/",
        profile="safe",
        sink=sink,
        transport=httpx.MockTransport(_site_handler(seen)),
        resolver=public_resolver,
        enable_dns=False,
        max_requests=40,
        max_seconds=20,
        rps=100,
        crawl_limits=CrawlLimits(max_pages=10, max_depth=2, max_path_probes=0, max_js_files=1),
    )

    urls = {endpoint.url: endpoint for endpoint in result.endpoints}
    assert "https://example.com/a" in urls
    assert "https://example.com/c" in urls
    assert "https://example.com/sm-page" in urls
    assert "https://example.com/api/hidden" in urls
    assert "https://example.com/api/items?id=1" in urls
    assert "https://example.com/api/save" in urls
    assert urls["https://example.com/api/save"].method == "POST"
    template = urls["https://example.com/api/users/${id}/posts"]
    assert template.method == "GET"
    assert "id" in template.parameters
    assert "https://example.com/v1/a" in urls
    assert "https://example.com/v1/b" in urls
    assert not any(url.startswith("https://evil.test") for url in urls)
    assert not any(url.startswith("https://cdn.example.net") for url in urls)
    assert "/b" not in seen, "robots.txt disallow must be honoured"

    intel = result.recon["js_intel"]
    assert intel["scripts"] == 1
    assert intel["source_maps"][0]["url"] == "https://example.com/static/app.js.map"
    assert intel["source_maps"][0]["same_origin"] is True
    assert intel["api_calls"] >= 3
    assert intel["post_calls"] >= 1
    assert "cdn.example.net" in intel["third_party_hosts"]
    assert intel["methods"]["https://example.com/api/save"] == "POST"
    assert "id" in intel["parameters"]

    clusters = result.recon["endpoint_intel"]
    assert clusters["endpoint_count"] == len(result.endpoints)
    assert clusters["api_clusters"] >= 1
    assert any(
        cluster["template"] == "https://example.com/api/users/{id}/posts"
        for cluster in clusters["clusters"]
    )

    search = urls["https://example.com/search?q=venom&page=2"]
    assert search.parameters == ["q", "page"]
    assert search.depth == 1
    assert urls["https://example.com/a"].depth == 1
    assert urls["https://example.com/c"].depth == 2

    form = next(
        endpoint for endpoint in result.endpoints if endpoint.url == "https://example.com/login"
    )
    assert form.method == "POST"
    assert form.parameters == ["email"]
    assert urls["https://example.com/v1/b"].method in {"POST", "DELETE"}

    crawl = result.recon["crawl"]
    assert crawl["robots_found"] is True
    assert crawl["sitemap_urls"] == 1
    assert crawl["api_specs"] == 1
    assert crawl["api_endpoints"] == 3
    assert crawl["pages"] >= 3

    api = result.recon["api"]
    assert api["endpoint_count"] == 3
    document = api["documents"][0]
    assert document["url"] == "https://example.com/openapi.json"
    assert document["spec_version"] == "3.0.3"
    assert document["paths"] == 2
    assert document["operations"] == 3
    assert document["servers"] == ["https://api.example.com/v2"]
    assert document["security_schemes"] == ["bearerAuth:http/bearer"]
    assert document["declared_auth"] is True
    assert any(event.type == "page_crawled" for event in sink.events)


@pytest.mark.asyncio
async def test_crawler_stops_at_page_cap(public_resolver):
    def handler(request: httpx.Request) -> httpx.Response:
        path = urlsplit(str(request.url)).path
        if path == "/robots.txt":
            return httpx.Response(404, headers={"Content-Type": "text/plain"}, text="missing")
        number = int(path.strip("/p") or 1) if path.startswith("/p") else 1
        return httpx.Response(
            200,
            headers={"Content-Type": "text/html"},
            text=f'<html><a href="/p{number + 1}">next</a></html>',
        )

    result = await run_scan(
        "scan-cap",
        "https://example.com/",
        profile="safe",
        sink=CollectingSink(),
        transport=httpx.MockTransport(handler),
        resolver=public_resolver,
        enable_dns=False,
        max_requests=40,
        max_seconds=20,
        rps=100,
        crawl_limits=CrawlLimits(max_pages=2, max_depth=5, max_path_probes=0, max_js_files=0),
    )
    assert result.recon["crawl"]["pages"] == 2
    assert result.recon["crawl"]["stopped"] == "page-cap"
