from __future__ import annotations

import time

import httpx
import pytest
from venomscan_engine.checks import all_check_ids, checks_for_profile, sqli_time
from venomscan_engine.checks.sqli_time import TimeBasedSqliCheck
from venomscan_engine.context import ScanContext
from venomscan_engine.events import NullSink
from venomscan_engine.models import EndpointRecord, Severity, VerificationStatus
from venomscan_engine.safety.scope import Scope

URL = "https://example.com/item?id=7"


def _context(make_bundle) -> ScanContext:
    ctx = ScanContext(
        scan_id="sqli-time-test",
        target_url=URL,
        scope=Scope.from_target("https://example.com/"),
        profile="active",
        sink=NullSink(),
        client=None,
        max_seconds=60,
    )
    ctx.root = make_bundle(url="https://example.com/")
    ctx.endpoints = [EndpointRecord(url=URL, method="GET", parameters=["id"], status_code=200)]
    return ctx


def _handler(fast_seconds: float, sleep_markers: set[str]):
    def handler(request: httpx.Request) -> httpx.Response:
        value = request.url.params.get("id", "")
        if any(marker in value for marker in sleep_markers):
            time.sleep(0.3)
        else:
            time.sleep(fast_seconds)
        return httpx.Response(200, text="ok")

    return handler


def test_time_check_is_registered_as_active_only():
    assert "venom.sqli.time" in all_check_ids()
    assert "venom.sqli.time" not in {cls.id for cls in checks_for_profile("safe")}
    assert "venom.sqli.time" in {cls.id for cls in checks_for_profile("active")}


@pytest.mark.asyncio
async def test_repeated_delay_confirms_blind_sqli(make_bundle, client_factory, monkeypatch):
    monkeypatch.setattr(sqli_time, "DELAY_MS", 200)
    ctx = _context(make_bundle)

    async with client_factory(_handler(0.0, {"SLEEP", "pg_sleep", "WAITFOR"})) as client:
        ctx.client = client
        findings = await TimeBasedSqliCheck().run(ctx)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.check_id == "venom.sqli.time"
    assert finding.severity is Severity.HIGH
    assert finding.verification_status is VerificationStatus.SUSPECTED
    assert finding.parameter == "id"
    assert finding.response_evidence["delayed_attempts"] >= 2
    assert finding.response_evidence["baseline_ms"] < finding.response_evidence["threshold_ms"]
    assert finding.request_evidence["url"].startswith("https://example.com/item?")
    assert "SLEEP" in finding.payload or "pg_sleep" in finding.payload


@pytest.mark.asyncio
async def test_fast_responses_produce_no_finding(make_bundle, client_factory, monkeypatch):
    monkeypatch.setattr(sqli_time, "DELAY_MS", 200)
    ctx = _context(make_bundle)

    async with client_factory(_handler(0.0, set())) as client:
        ctx.client = client
        assert await TimeBasedSqliCheck().run(ctx) == []


@pytest.mark.asyncio
async def test_single_delay_is_not_enough(make_bundle, client_factory, monkeypatch):
    monkeypatch.setattr(sqli_time, "DELAY_MS", 200)
    attempts = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        value = request.url.params.get("id", "")
        if any(marker in value for marker in ("SLEEP", "pg_sleep", "WAITFOR")):
            attempts["count"] += 1
            if attempts["count"] == 1:
                time.sleep(0.3)
        return httpx.Response(200, text="ok")

    ctx = _context(make_bundle)
    async with client_factory(handler) as client:
        ctx.client = client
        # One delayed run out of three is noise, not evidence.
        assert await TimeBasedSqliCheck().run(ctx) == []


@pytest.mark.asyncio
async def test_check_skips_when_scan_time_is_short(make_bundle, client_factory):
    ctx = _context(make_bundle)
    ctx.max_seconds = 1

    async with client_factory(_handler(0.0, set())) as client:
        ctx.client = client
        assert await TimeBasedSqliCheck().run(ctx) == []
