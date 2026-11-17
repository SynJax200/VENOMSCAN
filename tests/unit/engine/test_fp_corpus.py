"""False-positive regression corpus.

Each case replays a *clean* response and asserts the check family stays silent. The
corpus is declarative: a new check family must add a clean control here, and the
coverage test fails if a deterministic prefix has no case. Promotion rules for
exploit checks are pinned in the second half: proof present -> verified, proof
missing or a dirty control -> downgraded, never silently trusted.
"""

from __future__ import annotations

import base64
import json
import time

import httpx
import pytest
from venomscan_engine.checks import all_check_ids
from venomscan_engine.checks.api_security import (
    ApiAuthConfigCheck,
    ApiDocsExposedCheck,
    ApiSensitiveDataCheck,
    ApiUnauthenticatedCheck,
    GraphqlCheck,
    JwtCheck,
)
from venomscan_engine.checks.auth import AuthPagesCheck
from venomscan_engine.checks.cache import CacheablePageCheck
from venomscan_engine.checks.clickjacking import ClickjackingCheck
from venomscan_engine.checks.cookies import CookieFlagsCheck
from venomscan_engine.checks.cors import CORSMisconfigCheck
from venomscan_engine.checks.csrf import CSRFTokenCheck
from venomscan_engine.checks.disclosure import DirectoryListingCheck, VerboseErrorsCheck
from venomscan_engine.checks.files import ExposedFilesCheck
from venomscan_engine.checks.headers import SecurityHeadersCheck
from venomscan_engine.checks.methods import HTTPMethodsCheck
from venomscan_engine.checks.redirect import OpenRedirectCheck
from venomscan_engine.checks.secrets import JSSecretsCheck
from venomscan_engine.checks.server import ServerExposureCheck
from venomscan_engine.checks.session import SessionScopeCheck
from venomscan_engine.checks.tls_check import TLSCheck
from venomscan_engine.context import ScanContext
from venomscan_engine.events import NullSink
from venomscan_engine.models import EndpointRecord, Finding, Severity, VerificationStatus
from venomscan_engine.recon.tls import TLSInfo
from venomscan_engine.safety.scope import Scope
from venomscan_engine.verify.verifier import (
    DETERMINISTIC_CHECK_PREFIXES,
    REQUIRED_RESPONSE_EVIDENCE,
    mark_verified,
)

SECURE_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}

DOCUMENT = {
    "url": "https://example.com/openapi.json",
    "title": "Example API",
    "version": "1.0",
    "spec_version": "3.1.0",
    "paths": 4,
    "operations": 6,
    "servers": ["https://api.example.com"],
    "security_schemes": ["bearerAuth:http/bearer"],
    "global_security": True,
    "declared_auth": True,
}


def _ctx(make_bundle, url: str = "https://example.com/", profile: str = "safe") -> ScanContext:
    ctx = ScanContext(
        scan_id="fp-corpus",
        target_url=url,
        scope=Scope.from_target(url),
        profile=profile,
        sink=NullSink(),
        client=None,
        max_seconds=60,
    )
    ctx.root = make_bundle(url=url)
    return ctx


def _spec(ctx: ScanContext, **overrides) -> None:
    document = dict(DOCUMENT)
    document.update(overrides)
    ctx.artifacts["openapi"] = {"documents": [document], "endpoint_count": document["operations"]}


def _endpoint(url: str, parameters: list[str] | None = None) -> EndpointRecord:
    return EndpointRecord(
        url=url,
        method="GET",
        source="crawl",
        status_code=200,
        parameters=parameters or [],
    )


def _form(action: str, method: str, fields: list[dict]) -> dict:
    return {
        "page": "https://example.com/account",
        "action": action,
        "method": method,
        "fields": fields,
    }


async def _clean_headers(ctx, make_bundle):
    ctx.root = make_bundle(headers=SECURE_HEADERS)


async def _clean_cookies(ctx, make_bundle):
    ctx.root = make_bundle(set_cookies=["sid=1; Path=/; Secure; HttpOnly; SameSite=Lax"])


async def _clean_tls(ctx, make_bundle):
    ctx.artifacts["tls"] = TLSInfo(
        protocol="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384", days_to_expiry=200, verified=True
    )


async def _clean_server(ctx, make_bundle):
    ctx.root = make_bundle(headers={"Server": "cloudflare"})


async def _clean_errors(ctx, make_bundle):
    ctx.artifacts["pages"] = [
        {"url": "https://example.com/", "status_code": 200, "body": "<html>ok</html>"}
    ]


async def _clean_listing(ctx, make_bundle):
    ctx.artifacts["pages"] = [
        {"url": "https://example.com/files/", "status_code": 200, "body": "<html>Library</html>"}
    ]


async def _clean_clickjacking(ctx, make_bundle):
    ctx.root = make_bundle(headers={"X-Frame-Options": "DENY"})


def _spa_fallback(request: httpx.Request) -> httpx.Response:
    shell = "<html><body>app shell</body></html>"
    return httpx.Response(404, headers={"Content-Type": "text/html"}, text=shell)


async def _clean_files(ctx, make_bundle):
    ctx.root = make_bundle(body="<html><body>app shell</body></html>")
    return _spa_fallback


async def _clean_methods(ctx, make_bundle):
    return lambda request: httpx.Response(200, headers={"Allow": "GET, HEAD, OPTIONS"})


async def _clean_cors(ctx, make_bundle):
    return lambda request: httpx.Response(200, headers={"Access-Control-Allow-Origin": "*"})


async def _clean_cache(ctx, make_bundle):
    ctx.artifacts["pages"] = [
        {
            "url": "https://example.com/account",
            "status_code": 200,
            "cache_control": "no-store",
            "pragma": "",
            "set_cookie": True,
            "body": "",
        }
    ]


async def _clean_session(ctx, make_bundle):
    ctx.root = make_bundle(set_cookies=["sid=1; Path=/; Secure; HttpOnly; SameSite=Lax"])


async def _clean_redirect(ctx, make_bundle):
    ctx.endpoints = [_endpoint("https://example.com/go?next=/home", ["next"])]
    return lambda request: httpx.Response(302, headers={"Location": "/home"})


async def _clean_csrf(ctx, make_bundle):
    ctx.artifacts["forms"] = [
        _form(
            "https://example.com/account/update",
            "POST",
            [{"name": "csrf_token", "type": "hidden", "autocomplete": ""}],
        )
    ]


async def _clean_auth(ctx, make_bundle):
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


async def _clean_secrets(ctx, make_bundle):
    ctx.artifacts["scripts"] = [
        {"url": "https://example.com/app.js", "inline": False, "body": 'const t = "your-example-token";'}
    ]


async def _clean_api_docs(ctx, make_bundle):
    _spec(ctx, paths=0)


async def _clean_api_auth(ctx, make_bundle):
    _spec(ctx)


async def _clean_api_sensitive(ctx, make_bundle):
    ctx.artifacts["api_samples"] = [
        {
            "url": "https://example.com/api/ping",
            "content_type": "application/json",
            "body": '{"status": "ok", "items": [1, 2, 3]}',
        }
    ]


def _segment(value: dict) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


async def _clean_jwt(ctx, make_bundle):
    token = ".".join(
        [
            _segment({"alg": "HS256"}),
            _segment({"sub": "1", "exp": int(time.time()) + 3600}),
            "signature",
        ]
    )
    ctx.artifacts["api_samples"] = [
        {
            "url": "https://example.com/api/session",
            "content_type": "application/json",
            "body": f'{{"access_token": "{token}"}}',
        }
    ]


async def _clean_graphql(ctx, make_bundle):
    ctx.endpoints = [_endpoint("https://example.com/graphql")]

    def handler(request: httpx.Request) -> httpx.Response:
        query = request.url.params.get("query", "")
        if "__schema" in query:
            return httpx.Response(200, json={"errors": [{"message": "introspection disabled"}]})
        if "__typename" in query:
            return httpx.Response(200, json={"data": {"__typename": "Query"}})
        return httpx.Response(200, json={"status": "ok"})

    return handler


async def _clean_api_unauth(ctx, make_bundle):
    _spec(ctx, declared_auth=True, protected_gets=[{"path": "/items", "method": "GET"}])

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/items":
            return httpx.Response(401, json={"error": "unauthorized"})
        return httpx.Response(200, headers={"Content-Type": "text/html"}, text="<html>login</html>")

    return handler


CLEAN_CASES: dict[str, tuple[object, object]] = {
    "headers": (SecurityHeadersCheck, _clean_headers),
    "cookies": (CookieFlagsCheck, _clean_cookies),
    "tls": (TLSCheck, _clean_tls),
    "transport": (ServerExposureCheck, _clean_server),
    "verbose-errors": (VerboseErrorsCheck, _clean_errors),
    "directory-listing": (DirectoryListingCheck, _clean_listing),
    "clickjacking": (ClickjackingCheck, _clean_clickjacking),
    "exposed-files": (ExposedFilesCheck, _clean_files),
    "methods": (HTTPMethodsCheck, _clean_methods),
    "cors": (CORSMisconfigCheck, _clean_cors),
    "cache": (CacheablePageCheck, _clean_cache),
    "session-scope": (SessionScopeCheck, _clean_session),
    "open-redirect": (OpenRedirectCheck, _clean_redirect),
    "csrf": (CSRFTokenCheck, _clean_csrf),
    "auth-pages": (AuthPagesCheck, _clean_auth),
    "js-secrets": (JSSecretsCheck, _clean_secrets),
    "api-docs": (ApiDocsExposedCheck, _clean_api_docs),
    "api-auth": (ApiAuthConfigCheck, _clean_api_auth),
    "api-sensitive": (ApiSensitiveDataCheck, _clean_api_sensitive),
    "jwt": (JwtCheck, _clean_jwt),
    "graphql": (GraphqlCheck, _clean_graphql),
    "api-unauth": (ApiUnauthenticatedCheck, _clean_api_unauth),
}

REQUIRED_FAMILIES = (
    "venom.headers.",
    "venom.cookies.",
    "venom.tls.",
    "venom.transport.",
    "venom.info.",
    "venom.clickjacking",
    "venom.files.",
    "venom.methods",
    "venom.cors.",
    "venom.cache.",
    "venom.session.",
    "venom.redirect.",
    "venom.csrf.",
    "venom.auth.",
    "venom.secrets.",
    "venom.api.",
)


@pytest.mark.asyncio
@pytest.mark.parametrize("case_id", sorted(CLEAN_CASES))
async def test_clean_control_stays_silent(case_id, make_bundle, client_factory):
    check_class, setup = CLEAN_CASES[case_id]
    ctx = _ctx(make_bundle)
    handler = await setup(ctx, make_bundle)
    handler = handler or (lambda request: httpx.Response(200))
    async with client_factory(handler) as client:
        ctx.client = client
        findings = await check_class().run(ctx)
    assert findings == [], f"{case_id} raised findings on a clean control: {findings}"


# ServerExposureCheck reports under venom.transport.plaintext even though its class
# id is venom.info.server, so the transport family is pinned to that case explicitly.
FAMILY_ALIASES = {"venom.transport.": "venom.info.server"}


def _case_ids() -> set[str]:
    return {check_class.id for check_class, _ in CLEAN_CASES.values()}


def test_corpus_covers_every_deterministic_prefix():
    covered = _case_ids()
    missing = []
    for prefix in REQUIRED_FAMILIES:
        base = prefix.rstrip(".")
        if FAMILY_ALIASES.get(prefix) in covered:
            continue
        if not any(check_id == base or check_id.startswith(base + ".") for check_id in covered):
            missing.append(prefix)
    assert not missing, f"add a clean control for: {missing}"
    assert set(DETERMINISTIC_CHECK_PREFIXES) <= set(REQUIRED_FAMILIES)


# --- promotion decision rules -------------------------------------------------


def _exploit_finding(check_id: str, response_evidence: dict) -> Finding:
    return Finding(
        check_id=check_id,
        title="exploit claim",
        category="injection",
        severity=Severity.HIGH,
        confidence=9,
        verification_status=VerificationStatus.VERIFIED,
        url="https://example.com/item?id=1",
        description="d",
        impact="i",
        remediation="r",
        request_evidence={"method": "GET", "url": "https://example.com/item?id=1'"},
        response_evidence=response_evidence,
    )


@pytest.mark.parametrize(
    ("check_id", "required"),
    sorted(REQUIRED_RESPONSE_EVIDENCE.items()),
)
def test_promotion_requires_the_full_proof_contract(check_id, required):
    complete = {key: True for key in required}
    finding = _exploit_finding(check_id, complete)
    mark_verified([finding])
    assert finding.verification_status is VerificationStatus.VERIFIED

    for key in required:
        broken = dict(complete)
        broken.pop(key)
        downgraded = _exploit_finding(check_id, dict(broken))
        mark_verified([downgraded])
        assert downgraded.verification_status is VerificationStatus.SUSPECTED, (check_id, key)
        assert downgraded.confidence == 5
        assert downgraded.response_evidence["verification_note"] == "evidence contract incomplete"


def test_dirty_injection_control_blocks_promotion():
    finding = _exploit_finding(
        "venom.sqli.error",
        {"error_family": "sqlite", "control_clean": False},
    )
    mark_verified([finding])
    assert finding.verification_status is VerificationStatus.SUSPECTED


@pytest.mark.parametrize("check_id", sorted(REQUIRED_RESPONSE_EVIDENCE))
def test_proof_contract_targets_real_checks(check_id):
    assert check_id in set(all_check_ids())


@pytest.mark.parametrize(
    ("check_id", "observed"),
    [
        ("venom.headers.csp", {"url": "https://example.com/", "headers": {}}),
        ("venom.cookies.flags", {"url": "https://example.com/", "set_cookie": "«redacted»"}),
        ("venom.tls.weak", {"tls": {"protocol": "TLSv1.1"}}),
        ("venom.info.server", {"url": "https://example.com/", "status_code": 200}),
    ],
)
def test_deterministic_families_promote_with_observed_evidence(check_id, observed):
    finding = _exploit_finding(check_id, observed)
    finding.verification_status = VerificationStatus.SUSPECTED
    mark_verified([finding])
    assert finding.verification_status is VerificationStatus.VERIFIED


def test_deterministic_family_without_observed_evidence_is_not_promoted():
    finding = _exploit_finding("venom.headers.csp", {})
    finding.verification_status = VerificationStatus.SUSPECTED
    mark_verified([finding])
    assert finding.verification_status is VerificationStatus.SUSPECTED
