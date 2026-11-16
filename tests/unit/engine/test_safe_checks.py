from __future__ import annotations

import httpx
import pytest
from venomscan_engine.checks import (
    all_check_ids,
    check_catalog,
    checks_for_profile,
    register,
    validate_check,
)
from venomscan_engine.checks.auth import AuthPagesCheck
from venomscan_engine.checks.cache import CacheablePageCheck
from venomscan_engine.checks.clickjacking import ClickjackingCheck
from venomscan_engine.checks.cors import CANARY_ORIGIN, CORSMisconfigCheck
from venomscan_engine.checks.csrf import CSRFTokenCheck
from venomscan_engine.checks.disclosure import DirectoryListingCheck, VerboseErrorsCheck
from venomscan_engine.checks.files import ExposedFilesCheck
from venomscan_engine.checks.headers import SecurityHeadersCheck
from venomscan_engine.checks.methods import HTTPMethodsCheck
from venomscan_engine.checks.redirect import CANARY_URL, OpenRedirectCheck
from venomscan_engine.checks.secrets import JSSecretsCheck
from venomscan_engine.checks.session import SessionScopeCheck
from venomscan_engine.context import ScanContext
from venomscan_engine.events import NullSink
from venomscan_engine.models import Finding, Severity
from venomscan_engine.recon.tls import TLSInfo
from venomscan_engine.safety.scope import Scope
from venomscan_engine.verify.dedupe import dedupe_findings
from venomscan_engine.verify.verifier import mark_verified

SAFE_CHECK_IDS = {
    "venom.api.auth",
    "venom.api.docs",
    "venom.api.sensitive",
    "venom.auth.pages",
    "venom.cache",
    "venom.cors.misconfig",
    "venom.csrf.token",
    "venom.files.exposed",
    "venom.info.dirlist",
    "venom.info.errors",
    "venom.methods",
    "venom.redirect.open",
    "venom.secrets.js",
    "venom.session",
}


def _context(make_bundle, url: str = "https://example.com/") -> ScanContext:
    ctx = ScanContext(
        scan_id="test",
        target_url=url,
        scope=Scope.from_target(url),
        profile="safe",
        sink=NullSink(),
        client=None,
        max_seconds=60,
    )
    ctx.root = make_bundle(url=url)
    return ctx


def test_registry_discovers_all_safe_checks():
    ids = set(all_check_ids())
    assert SAFE_CHECK_IDS <= ids
    assert len(ids) == len(set(ids))
    assert {"venom.clickjacking"} <= ids
    safe = {cls.id for cls in checks_for_profile("safe")}
    assert safe == ids - {
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
    filtered = {cls.id for cls in checks_for_profile("safe", {"venom.secrets.js"})}
    assert "venom.secrets.js" not in filtered


def test_catalog_has_real_learning_copy_for_every_check():
    for entry in check_catalog():
        learning = entry["learning"]
        assert learning["what"] and learning["why"] and learning["verify"], entry["id"]
        assert "documented in the engine catalogue" not in learning["what"], entry["id"]


def test_registry_rejects_bad_contracts():
    class BadId:
        id = "not-venom"
        name = "bad"
        category = "bad"
        default_severity = Severity.LOW
        profile = "safe"

        async def run(self, ctx):
            return []

    with pytest.raises(ValueError):
        validate_check(BadId)

    class BadProfile:
        id = "venom.test.profile"
        name = "bad"
        category = "bad"
        default_severity = Severity.LOW
        profile = "turbo"

        async def run(self, ctx):
            return []

    with pytest.raises(ValueError):
        validate_check(BadProfile)

    class NotAsync:
        id = "venom.test.sync"
        name = "bad"
        category = "bad"
        default_severity = Severity.LOW
        profile = "safe"

        def run(self, ctx):
            return []

    with pytest.raises(TypeError):
        validate_check(NotAsync)

    class Duplicate:
        id = "venom.headers.missing"
        name = "duplicate"
        category = "config"
        default_severity = Severity.LOW
        profile = "passive"

        async def run(self, ctx):
            return []

    with pytest.raises(ValueError):
        register(Duplicate)


@pytest.mark.asyncio
async def test_clickjacking_flags_missing_frame_protection(make_bundle):
    ctx = _context(make_bundle)
    findings = await ClickjackingCheck().run(ctx)
    assert [f.check_id for f in findings] == ["venom.clickjacking"]


@pytest.mark.asyncio
async def test_clickjacking_accepts_xfo_or_frame_ancestors(make_bundle):
    ctx = _context(make_bundle)
    ctx.root = make_bundle(headers={"X-Frame-Options": "DENY"})
    assert await ClickjackingCheck().run(ctx) == []
    ctx.root = make_bundle(headers={"Content-Security-Policy": "frame-ancestors 'none'"})
    assert await ClickjackingCheck().run(ctx) == []


@pytest.mark.asyncio
async def test_hardening_impact_is_specific_to_the_missing_header(make_bundle):
    ctx = _context(make_bundle)
    ctx.root = make_bundle(
        headers={
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=()",
        }
    )
    [finding] = await SecurityHeadersCheck().run(ctx)
    assert finding.check_id == "venom.headers.hardening"
    assert "cross-origin-opener-policy" in finding.description
    assert "XS-Leak" in finding.impact
    assert "MIME" not in finding.impact
    assert "referrer" not in finding.impact.lower()
    assert "Cross-Origin-Opener-Policy" in finding.remediation


@pytest.mark.asyncio
async def test_edge_challenge_page_suppresses_config_findings(make_bundle):
    ctx = _context(make_bundle)
    ctx.root = make_bundle(
        status_code=403,
        headers={"X-Vercel-Challenge-Token": "opaque"},
        body="<html><title>Vercel Security Checkpoint</title></html>",
    )
    assert await ClickjackingCheck().run(ctx) == []
    assert await SecurityHeadersCheck().run(ctx) == []

    ctx.root = make_bundle(status_code=403, body="<html>Just a moment...</html>")
    assert await ClickjackingCheck().run(ctx) == []
    assert await SecurityHeadersCheck().run(ctx) == []

    ctx.root = make_bundle(status_code=429, body="<html>slow down</html>")
    assert await ClickjackingCheck().run(ctx) == []
    assert await SecurityHeadersCheck().run(ctx) == []


@pytest.mark.asyncio
async def test_plain_error_page_still_reports_config_findings(make_bundle):
    ctx = _context(make_bundle)
    ctx.root = make_bundle(status_code=404, body="<html><body>Not found</body></html>")
    assert [f.check_id for f in await ClickjackingCheck().run(ctx)] == ["venom.clickjacking"]
    ids = {f.check_id for f in await SecurityHeadersCheck().run(ctx)}
    assert {"venom.headers.csp", "venom.headers.hsts", "venom.headers.hardening"} <= ids


@pytest.mark.asyncio
async def test_cors_detects_reflected_origin(make_bundle, client_factory):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("origin") == CANARY_ORIGIN:
            return httpx.Response(
                200,
                headers={
                    "Access-Control-Allow-Origin": CANARY_ORIGIN,
                    "Access-Control-Allow-Credentials": "true",
                },
            )
        return httpx.Response(200)

    ctx = _context(make_bundle)
    async with client_factory(handler) as client:
        ctx.client = client
        findings = await CORSMisconfigCheck().run(ctx)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert findings[0].response_evidence["access_control_allow_credentials"] is True


@pytest.mark.asyncio
async def test_cors_ignores_wildcard_without_reflection(make_bundle, client_factory):
    ctx = _context(make_bundle)
    async with client_factory(lambda request: httpx.Response(
        200, headers={"Access-Control-Allow-Origin": "*"}
    )) as client:
        ctx.client = client
        assert await CORSMisconfigCheck().run(ctx) == []


@pytest.mark.asyncio
async def test_methods_flags_trace(make_bundle, client_factory):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "OPTIONS":
            return httpx.Response(200, headers={"Allow": "GET, HEAD, OPTIONS, TRACE"})
        if request.method == "TRACE":
            return httpx.Response(200, headers={"Content-Type": "message/http"})
        return httpx.Response(200)

    ctx = _context(make_bundle)
    async with client_factory(handler) as client:
        ctx.client = client
        findings = await HTTPMethodsCheck().run(ctx)
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM


@pytest.mark.asyncio
async def test_methods_accepts_standard_allow(make_bundle, client_factory):
    ctx = _context(make_bundle)
    async with client_factory(
        lambda request: httpx.Response(200, headers={"Allow": "GET, HEAD, OPTIONS"})
    ) as client:
        ctx.client = client
        assert await HTTPMethodsCheck().run(ctx) == []
    assert ctx.client.request_count == 1


@pytest.mark.asyncio
async def test_exposed_files_matches_git_and_ignores_spa_fallback(make_bundle, client_factory):
    shell = "<html><body>app shell</body></html>"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.git/HEAD":
            return httpx.Response(
                200, headers={"Content-Type": "text/plain"}, text="ref: refs/heads/main\n"
            )
        if request.url.path == "/.env":
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text=shell)
        return httpx.Response(404, headers={"Content-Type": "text/html"}, text=shell)

    ctx = _context(make_bundle)
    ctx.root = make_bundle(body=shell)
    async with client_factory(handler) as client:
        ctx.client = client
        findings = await ExposedFilesCheck().run(ctx)
    assert [f.parameter for f in findings] == ["/.git/HEAD"]
    assert findings[0].severity is Severity.HIGH
    assert "body" not in findings[0].response_evidence or (
        findings[0].response_evidence["body"] == "«redacted: potential secrets»"
    )


@pytest.mark.asyncio
async def test_secrets_masks_matched_value(make_bundle):
    ctx = _context(make_bundle)
    ctx.artifacts["scripts"] = [
        {"url": "https://example.com/app.js", "inline": False, "body": 'k="AKIAABCDEFGHIJKLMNOP"'}
    ]
    findings = await JSSecretsCheck().run(ctx)
    assert len(findings) == 1
    masked = findings[0].response_evidence["masked_value"]
    assert "AKIAABCDEFGHIJKLMNOP" not in masked
    assert masked.startswith("AKIA")


@pytest.mark.asyncio
async def test_secrets_ignores_placeholders(make_bundle):
    ctx = _context(make_bundle)
    ctx.artifacts["scripts"] = [
        {
            "url": "https://example.com/app.js",
            "inline": False,
            "body": 'const token = "your-example-token-value-here";',
        }
    ]
    assert await JSSecretsCheck().run(ctx) == []


def _form(action: str, method: str, fields: list[dict], page: str = "https://example.com/account"):
    return {"page": page, "action": action, "method": method, "fields": fields}


@pytest.mark.asyncio
async def test_csrf_flags_post_without_token(make_bundle):
    ctx = _context(make_bundle)
    ctx.artifacts["forms"] = [
        _form(
            "https://example.com/account/update",
            "POST",
            [{"name": "email", "type": "email", "autocomplete": ""}],
        )
    ]
    findings = await CSRFTokenCheck().run(ctx)
    assert [f.check_id for f in findings] == ["venom.csrf.token"]
    assert findings[0].verification_status.value == "suspected"


@pytest.mark.asyncio
async def test_csrf_accepts_token_or_password_forms(make_bundle):
    ctx = _context(make_bundle)
    ctx.artifacts["forms"] = [
        _form(
            "https://example.com/account/update",
            "POST",
            [
                {"name": "email", "type": "email", "autocomplete": ""},
                {"name": "csrf_token", "type": "hidden", "autocomplete": ""},
            ],
        ),
        _form(
            "https://example.com/login",
            "POST",
            [{"name": "password", "type": "password", "autocomplete": "current-password"}],
        ),
    ]
    assert await CSRFTokenCheck().run(ctx) == []


@pytest.mark.asyncio
async def test_auth_flags_get_password_and_weak_autocomplete(make_bundle):
    ctx = _context(make_bundle)
    ctx.artifacts["forms"] = [
        _form(
            "https://example.com/login",
            "GET",
            [{"name": "password", "type": "password", "autocomplete": ""}],
        ),
        _form(
            "https://example.com/signin",
            "POST",
            [{"name": "password", "type": "password", "autocomplete": "on"}],
        ),
    ]
    findings = await AuthPagesCheck().run(ctx)
    titles = [f.title for f in findings]
    assert any("submitted with GET" in title for title in titles)
    assert any("autocomplete" in title for title in titles)


@pytest.mark.asyncio
async def test_auth_accepts_safe_login_form(make_bundle):
    ctx = _context(make_bundle)
    ctx.artifacts["forms"] = [
        _form(
            "https://example.com/login",
            "POST",
            [
                {"name": "password", "type": "password", "autocomplete": "current-password"},
                {"name": "csrf_token", "type": "hidden", "autocomplete": ""},
            ],
        )
    ]
    assert await AuthPagesCheck().run(ctx) == []


@pytest.mark.asyncio
async def test_session_flags_parent_domain_cookie(make_bundle):
    ctx = _context(make_bundle, "https://app.example.com/")
    ctx.root = make_bundle(
        url="https://app.example.com/",
        set_cookies=["sid=1; Domain=.example.com; Path=/; Secure; HttpOnly; SameSite=Lax"],
    )
    findings = await SessionScopeCheck().run(ctx)
    assert [f.parameter for f in findings] == ["sid"]


@pytest.mark.asyncio
async def test_session_accepts_host_only_cookie(make_bundle):
    ctx = _context(make_bundle, "https://example.com/")
    ctx.root = make_bundle(set_cookies=["sid=1; Path=/; Secure; HttpOnly; SameSite=Lax"])
    assert await SessionScopeCheck().run(ctx) == []


@pytest.mark.asyncio
async def test_cache_flags_cookie_page_without_no_store(make_bundle):
    ctx = _context(make_bundle)
    ctx.artifacts["pages"] = [
        {
            "url": "https://example.com/account",
            "status_code": 200,
            "cache_control": "",
            "pragma": "",
            "set_cookie": True,
            "body": "",
        }
    ]
    findings = await CacheablePageCheck().run(ctx)
    assert len(findings) == 1
    ctx.artifacts["pages"][0]["cache_control"] = "no-store"
    assert await CacheablePageCheck().run(ctx) == []


@pytest.mark.asyncio
async def test_disclosure_checks(make_bundle):
    ctx = _context(make_bundle)
    ctx.artifacts["pages"] = [
        {
            "url": "https://example.com/error",
            "status_code": 500,
            "body": "Traceback (most recent call last):\n  File x",
        },
        {
            "url": "https://example.com/files/",
            "status_code": 200,
            "body": "<html><head><title>Index of /files</title></head></html>",
        },
    ]
    errors = await VerboseErrorsCheck().run(ctx)
    listing = await DirectoryListingCheck().run(ctx)
    assert [f.check_id for f in errors] == ["venom.info.errors"]
    assert [f.check_id for f in listing] == ["venom.info.dirlist"]


@pytest.mark.asyncio
async def test_disclosure_clean_pages(make_bundle):
    ctx = _context(make_bundle)
    ctx.artifacts["pages"] = [
        {"url": "https://example.com/", "status_code": 200, "body": "<html>ok</html>"}
    ]
    assert await VerboseErrorsCheck().run(ctx) == []
    assert await DirectoryListingCheck().run(ctx) == []


@pytest.mark.asyncio
async def test_open_redirect_canary(make_bundle, client_factory):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": CANARY_URL})

    ctx = _context(make_bundle)
    ctx.endpoints = [
        type(
            "Endpoint",
            (),
            {
                "url": "https://example.com/go?next=/home",
                "method": "GET",
                "parameters": ["next"],
                "state": "live",
            },
        )()
    ]
    async with client_factory(handler) as client:
        ctx.client = client
        findings = await OpenRedirectCheck().run(ctx)
    assert len(findings) == 1
    assert findings[0].parameter == "next"
    mark_verified(findings)
    assert findings[0].verification_status.value == "verified"
    assert ctx.client.request_count == 1


@pytest.mark.asyncio
async def test_open_redirect_ignores_relative_location(make_bundle, client_factory):
    ctx = _context(make_bundle)
    ctx.endpoints = [
        type(
            "Endpoint",
            (),
            {
                "url": "https://example.com/go?next=/home",
                "method": "GET",
                "parameters": ["next"],
                "state": "live",
            },
        )()
    ]
    async with client_factory(
        lambda request: httpx.Response(302, headers={"Location": "/home"})
    ) as client:
        ctx.client = client
        assert await OpenRedirectCheck().run(ctx) == []


def test_cross_scan_dedupe_collapses_repeat_hits(make_bundle):
    first = Finding(
        check_id="venom.headers.csp",
        title="t",
        category="config",
        severity=Severity.LOW,
        confidence=8,
        url="https://example.com/",
        description="d",
        impact="i",
        remediation="r",
    )
    second = first.model_copy(update={"confidence": 9})
    merged = dedupe_findings([first, second])
    assert len(merged) == 1
    assert merged[0].confidence == 9


@pytest.mark.asyncio
async def test_clean_fixture_produces_no_findings(make_bundle, client_factory):
    root_headers = {
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
        "Cross-Origin-Opener-Policy": "same-origin",
        "X-Frame-Options": "DENY",
        "Server": "uvicorn",
        "Cache-Control": "no-store",
    }
    ctx = _context(make_bundle)
    ctx.root = make_bundle(
        headers=root_headers,
        set_cookies=["session_id=abc; Secure; HttpOnly; SameSite=Lax; Path=/"],
        body="<html><body>clean</body></html>",
    )
    ctx.artifacts["tls"] = TLSInfo(
        protocol="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384", days_to_expiry=200, verified=True
    )
    ctx.artifacts["forms"] = [
        _form(
            "https://example.com/login",
            "POST",
            [
                {"name": "password", "type": "password", "autocomplete": "current-password"},
                {"name": "csrf_token", "type": "hidden", "autocomplete": ""},
            ],
        )
    ]
    ctx.artifacts["scripts"] = [
        {"url": "https://example.com/app.js", "inline": False, "body": "console.log('ok')"}
    ]
    ctx.artifacts["pages"] = [
        {
            "url": "https://example.com/",
            "status_code": 200,
            "cache_control": "no-store",
            "pragma": "",
            "set_cookie": False,
            "content_type": "text/html",
            "body": "<html><body>clean</body></html>",
        }
    ]
    ctx.endpoints = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "OPTIONS":
            return httpx.Response(200, headers={"Allow": "GET, HEAD, OPTIONS"})
        return httpx.Response(404, headers={"Content-Type": "text/html"}, text="not found")

    async with client_factory(handler) as client:
        ctx.client = client
        for check_cls in checks_for_profile("safe"):
            produced = await check_cls().run(ctx)
            assert produced == [], f"{check_cls.id} produced {[f.title for f in produced]}"
