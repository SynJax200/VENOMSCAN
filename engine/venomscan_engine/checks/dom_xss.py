from __future__ import annotations

import asyncio
from urllib.parse import urlsplit

from venomscan_engine.checks.probes import canary, probe_points, with_value
from venomscan_engine.checks.registry import register
from venomscan_engine.context import ScanContext
from venomscan_engine.models import Finding, Severity, VerificationStatus
from venomscan_engine.safety.http import TargetUnreachable, TooManyRedirects
from venomscan_engine.safety.scope import ScopeViolation

MAX_PAGES = 2
PAGE_TIMEOUT_MS = 8_000
SETTLE_MS = 250
MARKER_PREFIX = "vs-canary-"
PREFERRED_PARAMS = ("q", "search", "query", "name", "msg", "redirect", "next", "url")


def marker_tag(token: str) -> str:
    return f"{MARKER_PREFIX}{token}"


async def detect_marker(page, tag: str) -> bool:
    """True when the browser parsed the injected markup into a real element."""
    return bool(await page.evaluate("(tag) => document.querySelector(tag) !== null", tag))


async def server_reflects(ctx: ScanContext, url: str, tag: str) -> bool:
    """Reflected XSS is a different finding; the DOM check only handles client sinks."""
    if ctx.client is None:
        return False
    try:
        response = await ctx.client.get(url)
    except (TargetUnreachable, TooManyRedirects):
        return False
    return tag in response.body


@register
class DomXssCheck:
    id = "venom.xss.dom"
    name = "DOM XSS (browser sink)"
    category = "injection"
    default_severity = Severity.MEDIUM
    profile = "active"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if ctx.root is None or ctx.remaining_seconds < 15:
            return []
        points = probe_points(ctx, MAX_PAGES, preferred=PREFERRED_PARAMS)
        if not points:
            return []

        try:
            from playwright.async_api import async_playwright
        except Exception:  # browser support is optional at runtime
            await ctx.emit(
                "analyzing",
                "warning",
                "DOM XSS skipped: Playwright is not installed",
                payload={"check_id": self.id},
            )
            return []

        findings: list[Finding] = []
        try:
            async with async_playwright() as playwright:
                try:
                    browser = await playwright.chromium.launch(headless=True)
                except Exception as exc:
                    await ctx.emit(
                        "analyzing",
                        "warning",
                        f"DOM XSS browser unavailable: {str(exc)[:160]}",
                        payload={"check_id": self.id},
                    )
                    return []
                try:
                    for point in points:
                        if ctx.remaining_seconds < 8:
                            break
                        tag = marker_tag(canary(ctx, self.id, point.parameter))
                        payload = f"<{tag}>"
                        probe_url = with_value(point, payload)
                        if await server_reflects(ctx, probe_url, tag):
                            continue
                        if await self._probe(ctx, browser, probe_url, tag):
                            findings.append(self._finding(ctx, point, probe_url, payload, tag))
                finally:
                    await browser.close()
        except Exception as exc:
            await ctx.emit(
                "analyzing",
                "warning",
                f"DOM XSS probe failed: {str(exc)[:160]}",
                payload={"check_id": self.id},
            )
        return findings

    async def _probe(self, ctx: ScanContext, browser, url: str, tag: str) -> bool:
        context = await browser.new_context(accept_downloads=False, java_script_enabled=True)
        try:
            async def guard(route) -> None:
                requested = route.request.url
                if route.request.method.upper() not in {"GET", "HEAD"}:
                    await route.abort()
                    return
                if route.request.resource_type in {"media", "font"}:
                    await route.abort()
                    return
                if urlsplit(requested).scheme not in {"http", "https"}:
                    await route.abort()
                    return
                try:
                    ctx.scope.check(requested)
                except ScopeViolation:
                    await route.abort()
                    return
                await route.continue_()

            await context.route("**/*", guard)
            page = await context.new_page()

            async def close_popup(popup) -> None:
                if popup is not page:
                    await popup.close()

            context.on("page", lambda popup: asyncio.create_task(close_popup(popup)))
            page.set_default_timeout(PAGE_TIMEOUT_MS)
            try:
                await page.goto(url, wait_until="load", timeout=PAGE_TIMEOUT_MS)
            except Exception:
                return False
            await page.wait_for_timeout(SETTLE_MS)
            return await detect_marker(page, tag)
        finally:
            await context.close()

    def _finding(
        self, ctx: ScanContext, point, probe_url: str, payload: str, tag: str
    ) -> Finding:
        return Finding(
            check_id=self.id,
            title="Client-side code writes request input into the DOM as HTML",
            category=self.category,
            severity=Severity.MEDIUM,
            confidence=8,
            verification_status=VerificationStatus.VERIFIED,
            url=point.url,
            parameter=point.parameter,
            payload=payload,
            description=(
                f"The probe replaced the {point.parameter!r} parameter of {point.url} with a "
                f"canary custom element. When a headless browser loaded that URL, the live DOM "
                f"contained <{tag}>; a script in the same position would execute in the "
                "victim's browser."
            ),
            impact=(
                "DOM XSS runs in the target origin after the page loads, so it can read "
                "session-bound data and act as the victim even when the server output is clean."
            ),
            remediation=(
                "Write untrusted values with textContent or a safe templating layer, avoid "
                "innerHTML/outerHTML sinks, sanitize any required HTML with DOMPurify and add a "
                "restrictive Content-Security-Policy."
            ),
            references=[
                "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            ],
            cwe=["CWE-79"],
            owasp=["A03:2021 Injection"],
            request_evidence={"method": "GET", "url": probe_url},
            response_evidence={
                "sink": "html-element-created",
                "marker": tag,
                "body_stored": False,
            },
        )
