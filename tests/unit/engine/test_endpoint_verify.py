from __future__ import annotations

import time
from urllib.parse import urlsplit

import pytest
from venomscan_engine.crawl.endpoint_verify import is_verifiable, verify_endpoints
from venomscan_engine.models import EndpointRecord
from venomscan_engine.safety.http import BudgetExceeded, ResponseBundle


class _Client:
    def __init__(
        self,
        routes: dict[str, tuple[int, str, dict]] | None = None,
        wildcard: tuple[int, str, dict] | None = None,
    ) -> None:
        self.routes = routes or {}
        self.wildcard = wildcard or (404, "missing", {})
        self.requested: list[str] = []

    async def get(self, url: str) -> ResponseBundle:
        self.requested.append(url)
        status, body, headers = self.routes.get(urlsplit(url).path, self.wildcard)
        return ResponseBundle(
            url=url,
            status_code=status,
            headers=headers,
            body=body,
            elapsed_ms=1,
            size=len(body),
        )


class _BudgetClient:
    async def get(self, url: str) -> ResponseBundle:
        raise BudgetExceeded("budget gone")


class _Ctx:
    def __init__(self, client, endpoints: list[EndpointRecord], *, artifacts=None) -> None:
        self.client = client
        self.endpoints = endpoints
        self.artifacts = artifacts or {}
        self.max_seconds = 60
        self.started = time.monotonic()
        self.target_url = "https://example.com/"
        self.events: list[tuple] = []

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, self.max_seconds - (time.monotonic() - self.started))

    @property
    def root(self) -> ResponseBundle:
        return ResponseBundle(
            url=self.target_url, status_code=200, headers={}, body="", elapsed_ms=0, size=0
        )

    async def emit(self, *args, **kwargs) -> None:
        self.events.append((args, kwargs))


def _endpoint(url: str, *, source: str = "js", method: str = "GET") -> EndpointRecord:
    return EndpointRecord(url=url, method=method, source=source)


def test_verifiable_endpoint_rules():
    assert is_verifiable("https://example.com/api/orders", "GET", None, "js")
    assert not is_verifiable("https://example.com/api/orders", "POST", None, "js")
    assert not is_verifiable("https://example.com/api/orders", "GET", 200, "js")
    assert not is_verifiable("https://example.com/api/orders?id=1", "GET", None, "js")
    assert not is_verifiable("https://example.com/app.js", "GET", None, "js")
    assert not is_verifiable("https://example.com/login", "GET", None, "crawl")


@pytest.mark.asyncio
async def test_verification_promotes_js_routes_and_attaches_metadata():
    endpoints = [
        _endpoint("https://example.com/api/orders"),
        _endpoint("https://example.com/app.js"),
        _endpoint("https://example.com/login", source="crawl"),
        _endpoint("https://example.com/api/checkout", method="POST"),
    ]
    client = _Client(
        {"/api/orders": (200, '{"orders":[]}', {"content-type": "application/json"})}
    )
    ctx = _Ctx(client, endpoints)

    report = await verify_endpoints(ctx, max_probes=5)

    assert report.candidates == 1
    assert report.probed == 1
    assert report.verified == 1
    orders = endpoints[0]
    assert orders.status_code == 200
    assert orders.content_type == "application/json"
    assert orders.state == "live"
    assert endpoints[2].status_code is None
    assert not any(event[0][1] == "endpoint_verify_started" for event in ctx.events)


@pytest.mark.asyncio
async def test_soft_404_does_not_promote_endpoints():
    endpoints = [_endpoint("https://example.com/api/orders")]
    client = _Client(wildcard=(200, "<html>custom not found</html>", {"content-type": "text/html"}))
    ctx = _Ctx(client, endpoints)

    report = await verify_endpoints(ctx, max_probes=3)

    assert report.soft_404 is True
    assert report.not_found == 1
    assert report.verified == 0
    assert endpoints[0].status_code is None


@pytest.mark.asyncio
async def test_robots_and_missing_routes_are_not_promoted():
    endpoints = [
        _endpoint("https://example.com/private/panel"),
        _endpoint("https://example.com/api/orders"),
    ]
    client = _Client({"/api/orders": (404, "missing", {})})
    ctx = _Ctx(client, endpoints, artifacts={"robots": {"disallow": ["/private"]}})

    report = await verify_endpoints(ctx, max_probes=5)

    assert report.skipped == 1
    assert report.not_found == 1
    assert report.verified == 0
    assert endpoints[0].status_code is None
    assert endpoints[1].status_code is None


@pytest.mark.asyncio
async def test_budget_exhaustion_stops_without_promoting():
    endpoints = [_endpoint("https://example.com/api/orders")]
    ctx = _Ctx(_BudgetClient(), endpoints)

    report = await verify_endpoints(ctx, max_probes=3)

    assert report.stopped == "request-budget"
    assert report.verified == 0
    assert endpoints[0].status_code is None


@pytest.mark.asyncio
async def test_probe_cap_is_respected():
    endpoints = [_endpoint(f"https://example.com/api/item/{index}") for index in range(5)]
    client = _Client(
        {
            f"/api/item/{index}": (
                200,
                f'{{"item":{index}}}',
                {"content-type": "application/json"},
            )
            for index in range(5)
        }
    )
    ctx = _Ctx(client, endpoints)

    report = await verify_endpoints(ctx, max_probes=2)

    assert report.probed == 2
    assert report.verified == 2
    assert report.stopped == "probe-cap"
    assert len(client.requested) == 3
