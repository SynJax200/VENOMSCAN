from __future__ import annotations

import html
import re

import httpx
import pytest
from venomscan_engine.checks import all_check_ids, checks_for_profile
from venomscan_engine.checks.lfi import PathTraversalCheck
from venomscan_engine.checks.probes import canary, probe_points
from venomscan_engine.checks.sqli import SqlErrorCheck
from venomscan_engine.checks.ssti import SstiCheck, ssti_payload
from venomscan_engine.checks.xss import ReflectedXssCheck
from venomscan_engine.context import ScanContext
from venomscan_engine.events import NullSink
from venomscan_engine.models import EndpointRecord, VerificationStatus
from venomscan_engine.safety.scope import Scope

ACTIVE_CHECK_IDS = {
    "venom.xss.reflected",
    "venom.xss.dom",
    "venom.sqli.error",
    "venom.sqli.time",
    "venom.ssrf",
    "venom.xxe",
    "venom.idor",
    "venom.authz.function",
    "venom.ssti",
    "venom.lfi.path",
    "venom.api.ratelimit",
}
HTML = {"Content-Type": "text/html; charset=utf-8"}


def _context(make_bundle, url: str = "https://example.com/search?q=hello") -> ScanContext:
    ctx = ScanContext(
        scan_id="active-test",
        target_url=url,
        scope=Scope.from_target("https://example.com/"),
        profile="active",
        sink=NullSink(),
        client=None,
        max_seconds=60,
    )
    ctx.root = make_bundle(url="https://example.com/", headers=HTML)
    ctx.endpoints = [EndpointRecord(url=url, method="GET", parameters=["q"], status_code=200)]
    return ctx


def test_active_checks_only_run_in_active_profile():
    active_ids = set(all_check_ids())
    assert ACTIVE_CHECK_IDS <= active_ids
    safe = {cls.id for cls in checks_for_profile("safe")}
    assert not (ACTIVE_CHECK_IDS & safe)
    full = {cls.id for cls in checks_for_profile("active")}
    assert ACTIVE_CHECK_IDS <= full
    assert safe <= full


@pytest.mark.asyncio
async def test_xss_flags_raw_reflection(make_bundle, client_factory):
    ctx = _context(make_bundle)
    token = canary(ctx, "venom.xss.reflected", "q")
    payload = f"vs<{token}>"

    def handler(request: httpx.Request) -> httpx.Response:
        value = request.url.params.get("q", "")
        return httpx.Response(200, headers=HTML, text=f"<html><body>{value}</body></html>")

    async with client_factory(handler) as client:
        ctx.client = client
        findings = await ReflectedXssCheck().run(ctx)
    assert len(findings) == 1
    assert findings[0].payload == payload
    assert findings[0].verification_status is VerificationStatus.VERIFIED
    assert findings[0].response_evidence["reflection"] == "raw-payload"
    assert findings[0].response_evidence["variants_reflected"] == 2
    assert findings[0].response_evidence["control_reflected"] is True


@pytest.mark.asyncio
async def test_xss_single_variant_stays_suspected(make_bundle, client_factory):
    ctx = _context(make_bundle)

    def handler(request: httpx.Request) -> httpx.Response:
        value = request.url.params.get("q", "")
        rendered = value if value.startswith("vs<") else value
        if '">' in value:
            rendered = html.escape(value)
        return httpx.Response(200, headers=HTML, text=f"<html><body>{rendered}</body></html>")

    async with client_factory(handler) as client:
        ctx.client = client
        findings = await ReflectedXssCheck().run(ctx)
    assert len(findings) == 1
    assert findings[0].response_evidence["variants_reflected"] == 1
    assert findings[0].verification_status is VerificationStatus.SUSPECTED
    assert findings[0].confidence == 6


@pytest.mark.asyncio
async def test_xss_ignores_waf_block_page(make_bundle, client_factory):
    ctx = _context(make_bundle)

    def handler(request: httpx.Request) -> httpx.Response:
        value = request.url.params.get("q", "")
        return httpx.Response(
            200,
            headers=HTML,
            text=f"<html><body>Request blocked by web application firewall: {value}</body></html>",
        )

    async with client_factory(handler) as client:
        ctx.client = client
        assert await ReflectedXssCheck().run(ctx) == []


@pytest.mark.asyncio
async def test_xss_accepts_escaped_reflection(make_bundle, client_factory):
    ctx = _context(make_bundle)

    def handler(request: httpx.Request) -> httpx.Response:
        value = html.escape(request.url.params.get("q", ""))
        return httpx.Response(200, headers=HTML, text=f"<html><body>{value}</body></html>")

    async with client_factory(handler) as client:
        ctx.client = client
        assert await ReflectedXssCheck().run(ctx) == []


@pytest.mark.asyncio
async def test_xss_respects_probe_cap(make_bundle, client_factory):
    ctx = _context(make_bundle)
    ctx.endpoints = [
        EndpointRecord(url=f"https://example.com/p{i}?q=x", method="GET", parameters=["q"], status_code=200)
        for i in range(10)
    ]
    seen = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal seen
        seen += 1
        return httpx.Response(200, headers=HTML, text="<html><body>clean</body></html>")

    async with client_factory(handler) as client:
        ctx.client = client
        assert await ReflectedXssCheck().run(ctx) == []
    assert seen <= 4


@pytest.mark.asyncio
async def test_sqli_flags_database_error(make_bundle, client_factory):
    ctx = _context(make_bundle)

    def handler(request: httpx.Request) -> httpx.Response:
        if "'" in request.url.params.get("q", ""):
            return httpx.Response(
                500,
                headers=HTML,
                text="<html><body>You have an error in your SQL syntax; check the manual "
                "that corresponds to your MySQL server version</body></html>",
            )
        return httpx.Response(200, headers=HTML, text="<html><body>ok</body></html>")

    async with client_factory(handler) as client:
        ctx.client = client
        findings = await SqlErrorCheck().run(ctx)
    assert len(findings) == 1
    assert findings[0].response_evidence["error_family"] == "mysql"
    assert findings[0].response_evidence["control_clean"] is True
    assert findings[0].response_evidence["repeat_confirmed"] is True
    assert findings[0].verification_status is VerificationStatus.VERIFIED


@pytest.mark.asyncio
async def test_sqli_suppresses_generic_error_page(make_bundle, client_factory):
    ctx = _context(make_bundle)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            500,
            headers=HTML,
            text="<html><body>You have an error in your SQL syntax; check the manual "
            "that corresponds to your MySQL server version</body></html>",
        )

    async with client_factory(handler) as client:
        ctx.client = client
        assert await SqlErrorCheck().run(ctx) == []


@pytest.mark.asyncio
async def test_sqli_single_hit_stays_suspected(make_bundle, client_factory):
    ctx = _context(make_bundle)
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        value = request.url.params.get("q", "")
        if "'" in value:
            calls["n"] += 1
            if calls["n"] > 1:
                return httpx.Response(200, headers=HTML, text="<html><body>ok</body></html>")
            return httpx.Response(
                500,
                headers=HTML,
                text="<html><body>PostgreSQL ERROR: syntax error at or near</body></html>",
            )
        return httpx.Response(200, headers=HTML, text="<html><body>ok</body></html>")

    async with client_factory(handler) as client:
        ctx.client = client
        findings = await SqlErrorCheck().run(ctx)
    assert len(findings) == 1
    assert findings[0].response_evidence["repeat_confirmed"] is False
    assert findings[0].verification_status is VerificationStatus.SUSPECTED


@pytest.mark.asyncio
async def test_sqli_ignores_clean_response(make_bundle, client_factory):
    ctx = _context(make_bundle)
    async with client_factory(
        lambda request: httpx.Response(200, headers=HTML, text="<html><body>ok</body></html>")
    ) as client:
        ctx.client = client
        assert await SqlErrorCheck().run(ctx) == []


@pytest.mark.asyncio
async def test_ssti_flags_evaluated_expression(make_bundle, client_factory):
    ctx = _context(make_bundle)
    token = canary(ctx, "venom.ssti", "q")
    _, expected = ssti_payload(token)

    def handler(request: httpx.Request) -> httpx.Response:
        value = request.url.params.get("q", "")
        match = re.fullmatch(r"\{\{(\d+)\*(\d+)\}\}", value)
        rendered = str(int(match.group(1)) * int(match.group(2))) if match else value
        return httpx.Response(200, headers=HTML, text=f"<html><body>{rendered}</body></html>")

    async with client_factory(handler) as client:
        ctx.client = client
        findings = await SstiCheck().run(ctx)
    assert len(findings) == 1
    assert findings[0].response_evidence["evaluated"] == expected
    assert findings[0].response_evidence["variants_evaluated"] == 2
    assert findings[0].verification_status is VerificationStatus.VERIFIED


@pytest.mark.asyncio
async def test_ssti_single_expression_stays_suspected(make_bundle, client_factory):
    ctx = _context(make_bundle)
    token = canary(ctx, "venom.ssti", "q")
    _, expected = ssti_payload(token)

    def handler(request: httpx.Request) -> httpx.Response:
        value = request.url.params.get("q", "")
        rendered = expected if "{{" in value else value
        return httpx.Response(200, headers=HTML, text=f"<html><body>{rendered}</body></html>")

    async with client_factory(handler) as client:
        ctx.client = client
        findings = await SstiCheck().run(ctx)
    assert len(findings) == 1
    assert findings[0].response_evidence["variants_evaluated"] == 1
    assert findings[0].verification_status is VerificationStatus.SUSPECTED


@pytest.mark.asyncio
async def test_ssti_ignores_literal_expression(make_bundle, client_factory):
    ctx = _context(make_bundle)

    def handler(request: httpx.Request) -> httpx.Response:
        value = html.escape(request.url.params.get("q", ""))
        return httpx.Response(200, headers=HTML, text=f"<html><body>{value}</body></html>")

    async with client_factory(handler) as client:
        ctx.client = client
        assert await SstiCheck().run(ctx) == []


@pytest.mark.asyncio
async def test_lfi_flags_traversal_without_storing_file_body(make_bundle, client_factory):
    ctx = _context(make_bundle, "https://example.com/view?file=home.html")

    def handler(request: httpx.Request) -> httpx.Response:
        if ".." in request.url.params.get("file", ""):
            return httpx.Response(
                200,
                headers={"Content-Type": "text/plain"},
                text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
            )
        return httpx.Response(200, headers=HTML, text="<html><body>home</body></html>")

    async with client_factory(handler) as client:
        ctx.client = client
        findings = await PathTraversalCheck().run(ctx)
    assert len(findings) == 1
    assert findings[0].response_evidence["matched_file"] == "unix_passwd"
    assert findings[0].response_evidence["control_clean"] is True
    assert findings[0].response_evidence["body_stored"] is False
    assert "root:x:0:0" not in str(findings[0].model_dump())


@pytest.mark.asyncio
async def test_lfi_suppresses_when_control_also_leaks(make_bundle, client_factory):
    ctx = _context(make_bundle, "https://example.com/view?file=home.html")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "text/plain"},
            text="root:x:0:0:root:/root:/bin/bash\n",
        )

    async with client_factory(handler) as client:
        ctx.client = client
        assert await PathTraversalCheck().run(ctx) == []


@pytest.mark.asyncio
async def test_lfi_skips_unrelated_parameter_names(make_bundle, client_factory):
    ctx = _context(make_bundle, "https://example.com/search?q=hello")
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, headers=HTML, text="root:x:0:0:root:/root:/bin/bash")

    async with client_factory(handler) as client:
        ctx.client = client
        assert await PathTraversalCheck().run(ctx) == []
    assert called is False


def test_probe_points_skip_state_changing_paths(make_bundle):
    ctx = _context(make_bundle)
    ctx.endpoints = [
        EndpointRecord(url="https://example.com/logout?next=x", method="GET", status_code=200),
        EndpointRecord(url="https://example.com/search?q=x", method="POST", status_code=200),
        EndpointRecord(url="https://other.test/search?q=x", method="GET", status_code=200),
        EndpointRecord(url="https://example.com/list?page=1&token=abc", method="GET", status_code=200),
        EndpointRecord(url="https://example.com/app.js?q=x", method="GET", parameters=["q"]),
    ]
    points = probe_points(ctx, 5)
    assert [point.url for point in points] == ["https://example.com/list?page=1&token=abc"]
    assert points[0].parameter == "page"
