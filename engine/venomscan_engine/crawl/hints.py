from __future__ import annotations

from venomscan_engine.context import ScanContext

QUERY_SOURCES = frozenset(
    {"crawl", "js", "probe", "robots", "sitemap", "api-spec", "spa", "spa-xhr", "dirs"}
)
HEADER_CANDIDATES = (
    "origin",
    "referer",
    "user-agent",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-original-url",
    "x-rewrite-url",
    "x-http-method-override",
)
MAX_QUERY = 40
MAX_FORM = 40
MAX_COOKIES = 20


def build_surface_hints(ctx: ScanContext) -> dict:
    """Aggregate parameter surfaces discovered so far for manual/active targeting."""

    query = sorted(
        {
            name
            for endpoint in ctx.endpoints
            if endpoint.source in QUERY_SOURCES
            for name in endpoint.parameters
        }
    )
    form: set[str] = set()
    for entry in ctx.artifacts.get("forms", []):
        for field in entry.get("fields", []):
            name = field.get("name")
            if isinstance(name, str) and name:
                form.add(name)
    cookies: set[str] = set()
    for page in ctx.artifacts.get("pages", []):
        for name in page.get("set_cookie_names", []):
            if isinstance(name, str) and name:
                cookies.add(name)
    return {
        "query_parameters": query[:MAX_QUERY],
        "form_parameters": sorted(form)[:MAX_FORM],
        "cookies": sorted(cookies)[:MAX_COOKIES],
        "header_candidates": list(HEADER_CANDIDATES),
    }


__all__ = ["HEADER_CANDIDATES", "build_surface_hints"]
