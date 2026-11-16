from __future__ import annotations

import asyncio
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from venomscan_engine.context import ScanContext
from venomscan_engine.crawl.crawler import is_static_asset
from venomscan_engine.models import EndpointRecord
from venomscan_engine.safety.scope import ScopeViolation

MAX_ROUTE_NAVIGATIONS = 3
SETTLE_MS = 1_200
PAGE_TIMEOUT_MS = 15_000


@dataclass
class SpaReport:
    enabled: bool = False
    routes: int = 0
    xhr: int = 0
    navigated: int = 0
    stopped: str = ""
    error: str = ""

    def as_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "routes": self.routes,
            "xhr": self.xhr,
            "navigated": self.navigated,
            "stopped": self.stopped or None,
            "error": self.error or None,
        }


def _robots_disallows(ctx: ScanContext, url: str) -> bool:
    robots = ctx.artifacts.get("robots") or {}
    path = urlsplit(url).path or "/"
    return any(
        path.startswith(prefix)
        for prefix in robots.get("disallow", [])
        if prefix and prefix != "/"
    )


def _in_scope(ctx: ScanContext, url: str) -> bool:
    try:
        ctx.scope.check(url)
    except ScopeViolation:
        return False
    return True


def _record_xhr(
    ctx: ScanContext, report: SpaReport, seen: set[tuple[str, str]], method: str, url: str,
    status: int | None,
) -> None:
    if not _in_scope(ctx, url) or len(seen) >= 60:
        return
    key = (method.upper(), url.split("#", 1)[0])
    if key in seen:
        return
    seen.add(key)
    report.xhr += 1
    parameters = list(
        dict.fromkeys(
            name for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)
        )
    )
    ctx.add_endpoint(
        EndpointRecord(
            url=url.split("#", 1)[0],
            method=method.upper(),
            source="spa-xhr",
            status_code=status,
            depth=1,
            parameters=parameters,
        )
    )


async def _collect_dom_urls(page) -> tuple[list[str], list[str]]:
    anchors = await page.evaluate(
        "() => Array.from(document.querySelectorAll('a[href]')).map(a => a.href)"
    )
    resources = await page.evaluate(
        "() => performance.getEntriesByType('resource')"
        ".filter(e => e.initiatorType === 'fetch' || e.initiatorType === 'xmlhttprequest')"
        ".map(e => e.name)"
    )
    return list(anchors or []), list(resources or [])


async def capture_spa(
    ctx: ScanContext,
    *,
    max_routes: int = 40,
    budget_seconds: float = 60.0,
) -> SpaReport:
    """Render the target once in headless Chromium to capture client-side routes and XHR.

    Every browser request is re-checked against the scan scope before it leaves the
    process; non-GET, non-HTTP and out-of-scope requests are aborted. At most a few
    same-origin routes are navigated sequentially in the same page (one page at a
    time) so the module stays inside its wall-clock budget.
    """
    report = SpaReport(enabled=True)
    if ctx.root is None:
        report.stopped = "no-root"
        return report
    budget = min(budget_seconds, max(0.0, ctx.remaining_seconds - 5))
    if budget < 8:
        report.stopped = "time-budget"
        return report

    try:
        from playwright.async_api import async_playwright
    except Exception:  # browser support is optional at runtime
        report.stopped = "playwright-missing"
        report.error = "Playwright is not installed"
        await ctx.emit(
            "crawling", "warning", "SPA capture skipped: Playwright is not installed"
        )
        return report

    seen_xhr: set[tuple[str, str]] = set()
    routes: list[str] = []
    route_seen: set[str] = set()

    def remember_routes(candidates: list[str]) -> None:
        for candidate in candidates:
            clean = candidate.split("#", 1)[0]
            if len(routes) >= max_routes:
                return
            if not clean.startswith(("http://", "https://")):
                continue
            if clean in route_seen or is_static_asset(clean):
                continue
            if not _in_scope(ctx, clean) or _robots_disallows(ctx, clean):
                continue
            route_seen.add(clean)
            routes.append(clean)

    try:
        async with async_playwright() as playwright:
            try:
                browser = await playwright.chromium.launch(headless=True)
            except Exception as exc:
                report.stopped = "browser-unavailable"
                report.error = str(exc)[:200]
                await ctx.emit(
                    "crawling",
                    "warning",
                    f"SPA capture skipped: browser unavailable ({str(exc)[:120]})",
                )
                return report
            try:
                context = await browser.new_context(
                    accept_downloads=False, java_script_enabled=True
                )
                try:
                    async def guard(route) -> None:
                        request = route.request
                        if request.method.upper() not in {"GET", "HEAD"}:
                            await route.abort()
                            return
                        if request.resource_type in {"media", "font"}:
                            await route.abort()
                            return
                        if urlsplit(request.url).scheme not in {"http", "https"}:
                            await route.abort()
                            return
                        if not _in_scope(ctx, request.url):
                            await route.abort()
                            return
                        await route.continue_()

                    await context.route("**/*", guard)

                    async def on_response(response) -> None:
                        if response.request.resource_type not in {"xhr", "fetch"}:
                            return
                        try:
                            status = response.status
                        except Exception:
                            status = None
                        _record_xhr(
                            ctx, report, seen_xhr, response.request.method,
                            response.url, status,
                        )

                    context.on("response", lambda response: asyncio.create_task(on_response(response)))
                    page = await context.new_page()
                    page.set_default_timeout(PAGE_TIMEOUT_MS)

                    async def visit(url: str) -> None:
                        await page.goto(url, wait_until="load", timeout=PAGE_TIMEOUT_MS)
                        await page.wait_for_timeout(SETTLE_MS)
                        anchors, resources = await _collect_dom_urls(page)
                        remember_routes([page.url, *anchors])
                        for resource in resources:
                            _record_xhr(ctx, report, seen_xhr, "GET", resource, None)
                        report.navigated += 1

                    await visit(ctx.target_url)
                    for route in list(routes):
                        if report.navigated > MAX_ROUTE_NAVIGATIONS:
                            report.stopped = "route-cap"
                            break
                        if ctx.remaining_seconds < 10:
                            report.stopped = "time-budget"
                            break
                        if urlsplit(route).path in {"", "/"}:
                            continue
                        try:
                            await visit(route)
                        except Exception:
                            continue
                finally:
                    await context.close()
            finally:
                await browser.close()
    except Exception as exc:  # browser failures must never sink the scan
        report.stopped = "error"
        report.error = str(exc)[:200]
        await ctx.emit("crawling", "warning", f"SPA capture failed: {str(exc)[:160]}")

    for route in routes:
        ctx.add_endpoint(EndpointRecord(url=route, method="GET", source="spa", depth=1))
    report.routes = len(routes)
    return report


__all__ = ["SpaReport", "capture_spa"]
