from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest
from venomscan_engine.safety.http import ResponseBundle, SafeHttpClient
from venomscan_engine.safety.scope import Scope


@pytest.fixture
def public_resolver() -> Callable:
    async def resolver(host: str, port: int) -> list[str]:
        return ["93.184.216.34"]

    return resolver


@pytest.fixture
def make_bundle() -> Callable[..., ResponseBundle]:
    def factory(
        url: str = "https://example.com/",
        status_code: int = 200,
        headers: dict[str, str] | None = None,
        body: str = "<html><body>hello</body></html>",
        set_cookies: list[str] | None = None,
    ) -> ResponseBundle:
        return ResponseBundle(
            url=url,
            status_code=status_code,
            headers={k.lower(): v for k, v in (headers or {}).items()},
            body=body,
            elapsed_ms=5,
            size=len(body),
            set_cookies=set_cookies or [],
        )

    return factory


@pytest.fixture
def client_factory(public_resolver: Callable) -> Callable[..., SafeHttpClient]:
    def factory(
        handler: Callable[[httpx.Request], httpx.Response],
        target: str = "https://example.com",
        **kwargs,
    ) -> SafeHttpClient:
        kwargs.setdefault("max_requests", 20)
        kwargs.setdefault("max_seconds", 30)
        kwargs.setdefault("rps", 100)
        return SafeHttpClient(
            Scope.from_target(target),
            transport=httpx.MockTransport(handler),
            resolver=public_resolver,
            **kwargs,
        )

    return factory
