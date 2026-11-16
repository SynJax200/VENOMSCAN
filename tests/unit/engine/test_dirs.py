from __future__ import annotations

import time
from urllib.parse import urlsplit

import pytest
from venomscan_engine.crawl.dirs import DirReport, discover_paths
from venomscan_engine.crawl.hints import build_surface_hints
from venomscan_engine.models import EndpointRecord
from venomscan_engine.safety.http import BudgetExceeded, ResponseBundle


class _Client:
    def __init__(self, routes: dict[str, tuple[int, str, dict]], wildcard: tuple[int, str]) -> None:
        self.routes = routes
        self.wildcard = wildcard
        self.requested: list[str] = []

    async def get(self, url: str) -> ResponseBundle:
        self.requested.append(url)
        status, body, headers = self.routes.get(urlsplit(url).path, (*self.wildcard, {}))
        return ResponseBundle(
            url=url,
            status_code=status,
            headers=headers,
            body=body,
            elapsed_ms=1,
            size=len(body),
        )


class _BrokenClient:
    async def get(self, url: str) -> ResponseBundle:
        raise BudgetExceeded("budget gone")


class _Ctx:
    def __init__(self, client, *, artifacts: dict | None = None, seconds: float = 60.0) -> None:
        self.client = client
        self.artifacts = artifacts or {}
        self.endpoints: list[EndpointRecord] = []
        self.max_seconds = seconds
        self.started = time.monotonic()
        self.target_url = "https://example.com/"
        self.profile = "safe"

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, self.max_seconds - (time.monotonic() - self.started))

    @property
    def root(self) -> ResponseBundle:
        return ResponseBundle(
            url=self.target_url, status_code=200, headers={}, body="", elapsed_ms=0, size=0
        )

    def add_endpoint(self, endpoint: EndpointRecord) -> None:
        self.endpoints.append(endpoint)

    async def emit(self, *args, **kwargs) -> None:
        return None


@pytest.mark.asyncio
async def test_discover_paths_filters_soft_404_and_robots():
    client = _Client(
        {
            "/admin": (200, "<html><h1>Admin console</h1></html>", {"content-type": "text/html"}),
            "/.env": (200, "SECRET_KEY=abc", {"content-type": "text/plain"}),
            "/login": (302, "", {"location": "/auth/signin"}),
        },
        wildcard=(200, "<html><h1>Page not found</h1></html>"),
    )
    ctx = _Ctx(client, artifacts={"robots": {"disallow": ["/private"]}})

    report = await discover_paths(ctx, max_probes=20, budget_seconds=10)

    assert report.probed > 0
    assert "/admin" in report.paths
    assert "/.env" in report.paths
    assert "/login" in report.paths
    assert "/private" not in report.paths
    assert report.soft_404 is True
    assert all(not url.endswith("/private") for url in client.requested)
    assert {endpoint.source for endpoint in ctx.endpoints} == {"dirs"}
    assert "discovered" in report.summary()
    assert report.as_dict()["found"] == report.found


@pytest.mark.asyncio
async def test_discover_paths_respects_probe_cap_and_budget_errors():
    client = _Client({}, wildcard=(404, "missing"))
    ctx = _Ctx(client)
    report = await discover_paths(ctx, max_probes=3, budget_seconds=10)
    assert report.probed == 3
    assert isinstance(report, DirReport)

    stopped = await discover_paths(_Ctx(_BrokenClient()), max_probes=3, budget_seconds=10)
    assert stopped.stopped == "request-budget"


@pytest.mark.asyncio
async def test_discover_paths_skips_when_budget_too_small():
    report = await discover_paths(_Ctx(_Client({}, (404, "x")), seconds=2), max_probes=5)
    assert report.stopped == "time-budget"
    assert report.probed == 0


def test_build_surface_hints_aggregates_parameters():
    ctx = _Ctx(_Client({}, (200, "")))
    ctx.endpoints = [
        EndpointRecord(url="https://example.com/search?q=a&page=2", source="crawl", parameters=["q", "page"]),
        EndpointRecord(url="https://example.com/api/items?id=1", source="js", parameters=["id"]),
    ]
    ctx.artifacts = {
        "forms": [{"fields": [{"name": "username"}, {"name": "password"}]}],
        "pages": [{"set_cookie_names": ["session_id", "csrf_token"]}],
    }

    hints = build_surface_hints(ctx)

    assert hints["query_parameters"] == ["id", "page", "q"]
    assert hints["form_parameters"] == ["password", "username"]
    assert hints["cookies"] == ["csrf_token", "session_id"]
    assert "x-forwarded-for" in hints["header_candidates"]
