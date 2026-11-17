from __future__ import annotations

import pytest
from venomscan_engine.checks.cookies import CookieFlagsCheck
from venomscan_engine.checks.headers import SecurityHeadersCheck
from venomscan_engine.checks.server import ServerExposureCheck
from venomscan_engine.checks.tls_check import TLSCheck
from venomscan_engine.context import ScanContext
from venomscan_engine.events import NullSink
from venomscan_engine.models import Finding, Severity, VerificationStatus
from venomscan_engine.recon.tech import detect_technologies
from venomscan_engine.recon.tls import TLSInfo
from venomscan_engine.safety.scope import Scope
from venomscan_engine.verify.verifier import mark_verified


def _context(make_bundle) -> ScanContext:
    ctx = ScanContext(
        scan_id="test",
        target_url="https://example.com/",
        scope=Scope.from_target("https://example.com"),
        profile="passive",
        sink=NullSink(),
        client=None,  # checks only read artifacts in the passive phase
        max_seconds=60,
    )
    ctx.root = make_bundle()
    return ctx


@pytest.mark.asyncio
async def test_headers_check_reports_csp_hsts_and_hardening(make_bundle):
    ctx = _context(make_bundle)
    findings = await SecurityHeadersCheck().run(ctx)
    ids = {f.check_id for f in findings}
    assert ids == {"venom.headers.csp", "venom.headers.hsts", "venom.headers.hardening"}
    csp = next(f for f in findings if f.check_id == "venom.headers.csp")
    assert csp.severity.value == "medium"
    assert csp.verification_status is VerificationStatus.SUSPECTED


@pytest.mark.asyncio
async def test_headers_check_respects_existing_frame_ancestors(make_bundle):
    ctx = _context(make_bundle)
    ctx.root = make_bundle(
        headers={"Content-Security-Policy": "frame-ancestors 'self'", "X-Frame-Options": "DENY"}
    )
    findings = await SecurityHeadersCheck().run(ctx)
    assert not any(f.check_id == "venom.headers.csp" for f in findings)
    hardening = next(f for f in findings if f.check_id == "venom.headers.hardening")
    assert "x-frame-options" not in hardening.description


@pytest.mark.asyncio
async def test_cookies_check_flags_session_cookie(make_bundle):
    ctx = _context(make_bundle)
    ctx.root = make_bundle(
        set_cookies=["session_id=abc; Path=/", "theme=dark; Secure; HttpOnly; SameSite=Lax"]
    )
    findings = await CookieFlagsCheck().run(ctx)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.parameter == "session_id"
    assert finding.severity.value == "medium"
    assert "Secure" in finding.title
    assert "HttpOnly" in finding.title


@pytest.mark.asyncio
async def test_server_check_flags_plaintext_and_versions(make_bundle):
    ctx = _context(make_bundle)
    ctx.root = make_bundle(
        url="http://example.com/",
        headers={"Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.1"},
    )
    findings = await ServerExposureCheck().run(ctx)
    ids = {f.check_id for f in findings}
    assert ids == {"venom.transport.plaintext", "venom.info.version"}
    plaintext = next(f for f in findings if f.check_id == "venom.transport.plaintext")
    assert plaintext.severity.value == "high"


@pytest.mark.asyncio
async def test_server_check_ignores_bare_server_token(make_bundle):
    ctx = _context(make_bundle)
    ctx.root = make_bundle(headers={"Server": "cloudflare"})
    findings = await ServerExposureCheck().run(ctx)
    assert findings == []


@pytest.mark.asyncio
async def test_tls_check_reports_expired_and_deprecated(make_bundle):
    ctx = _context(make_bundle)
    ctx.artifacts["tls"] = TLSInfo(
        protocol="TLSv1.1",
        cipher="ECDHE-RSA-AES128-SHA",
        days_to_expiry=-3,
        verified=False,
        error="certificate has expired",
    )
    findings = await TLSCheck().run(ctx)
    ids = {f.check_id for f in findings}
    assert "venom.tls.expired" in ids
    assert "venom.tls.protocol" in ids
    assert "venom.tls.untrusted" not in ids


@pytest.mark.asyncio
async def test_tls_check_clean_certificate(make_bundle):
    ctx = _context(make_bundle)
    ctx.artifacts["tls"] = TLSInfo(
        protocol="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384", days_to_expiry=200, verified=True
    )
    assert await TLSCheck().run(ctx) == []


def test_technology_detection(make_bundle):
    bundle = make_bundle(
        headers={"Server": "nginx", "X-Powered-By": "Express"},
        body='<script src="/_next/static/chunk.js"></script>',
        set_cookies=["PHPSESSID=1"],
    )
    names = {tech.name for tech in detect_technologies(bundle)}
    assert {"Nginx", "Express", "PHP", "Next.js"} <= names


def test_technology_detection_asgi_server(make_bundle):
    bundle = make_bundle(headers={"Server": "uvicorn"})
    (tech,) = detect_technologies(bundle)
    assert tech.name == "Uvicorn"
    assert tech.category == "app-server"
    assert tech.version is None


def test_verifier_marks_deterministic_findings(make_bundle):
    ctx = _context(make_bundle)
    ctx.add_finding(
        Finding(
            check_id="venom.headers.csp",
            title="t",
            category="config",
            severity=Severity.MEDIUM,
            confidence=9,
            url="https://example.com/",
            description="d",
            impact="i",
            remediation="r",
            request_evidence={"method": "GET", "url": "https://example.com/"},
            response_evidence={
                "url": "https://example.com/",
                "status_code": 200,
                "headers": {"server": "demo"},
            },
        )
    )
    ctx.add_finding(ctx.findings[0].model_copy(update={"check_id": "venom.xss.reflected"}))
    mark_verified(ctx.findings)
    assert ctx.findings[0].verification_status is VerificationStatus.VERIFIED
    assert ctx.findings[1].verification_status is VerificationStatus.SUSPECTED
