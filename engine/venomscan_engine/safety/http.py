from __future__ import annotations

import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpcore
import httpx

from venomscan_engine.control import ScanCancelled
from venomscan_engine.safety.ratelimit import TokenBucket
from venomscan_engine.safety.redact import redact_headers, redact_text
from venomscan_engine.safety.scope import Scope, ScopeViolation
from venomscan_engine.safety.ssrf import SSRFBlocked, assert_host_allowed


class _PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Dial the address that passed SSRF validation instead of re-resolving it.

    Without pinning a hostile DNS record could return a public address to the
    SSRF pre-check and a private one to the TCP connect that follows (TOCTOU).
    """

    def __init__(self, pins: dict[str, str]) -> None:
        self._pins = pins
        self._inner = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,  # noqa: ASYNC109 - required by the httpcore interface
        local_address: str | None = None,
        socket_options: list | None = None,
    ) -> httpcore.AsyncNetworkStream:
        return await self._inner.connect_tcp(
            self._pins.get(host.strip("[]").lower(), host),
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,  # noqa: ASYNC109 - required by the httpcore interface
        socket_options: list | None = None,
    ) -> httpcore.AsyncNetworkStream:
        return await self._inner.connect_unix_socket(
            path, timeout=timeout, socket_options=socket_options
        )

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class TargetUnreachable(RuntimeError):
    pass


class BudgetExceeded(RuntimeError):
    pass


class TooManyRedirects(RuntimeError):
    pass


def validate_proxy_url(value: str | None) -> str | None:
    """Only plain HTTP(S) proxies are accepted; credentials belong in the URL or env."""
    if not value:
        return None
    value = value.strip()
    parts = urlsplit(value)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("upstream proxy must be an http(s):// URL")
    return value


@dataclass
class ResponseBundle:
    url: str
    status_code: int
    headers: dict[str, str]
    body: str
    elapsed_ms: int
    size: int
    redirect_chain: list[str] = field(default_factory=list)
    set_cookies: list[str] = field(default_factory=list)

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())

    def evidence(self) -> dict:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "headers": redact_headers(self.headers),
            "body_excerpt": redact_text(self.body),
            "elapsed_ms": self.elapsed_ms,
            "size": self.size,
            "redirect_chain": self.redirect_chain,
        }


class SafeHttpClient:
    """The single outbound chokepoint for target traffic.

    Enforces scope allowlists, SSRF rules (incl. cloud metadata), rate limits,
    redirect re-validation and per-scan request/time budgets.
    """

    def __init__(
        self,
        scope: Scope,
        *,
        max_requests: int = 120,
        rps: float = 4.0,
        max_seconds: float = 90.0,
        timeout: float = 10.0,
        allow_private: bool = False,
        transport: httpx.AsyncBaseTransport | None = None,
        proxy_url: str | None = None,
        resolver=None,
        cancel_check=None,
        user_agent: str = "VENOMSCAN/0.1 (authorized security assessment)",
    ) -> None:
        self.scope = scope
        self.max_requests = max_requests
        self.max_seconds = max_seconds
        self.timeout = timeout
        self.allow_private = allow_private
        self._transport = transport
        self._proxy_url = validate_proxy_url(proxy_url)
        self._resolver = resolver
        self._cancel_check = cancel_check
        self._user_agent = user_agent
        self._bucket = TokenBucket(rate=rps, burst=min(max(rps, 1.0), 8.0))
        self._client: httpx.AsyncClient | None = None
        self._requests = 0
        self._started = time.monotonic()
        self._pins: dict[str, str] = {}

    def _pinned_transport(self) -> httpx.AsyncBaseTransport:
        transport = httpx.AsyncHTTPTransport()
        # httpx exposes no network_backend hook, but its transport routes every
        # connection through self._pool, so a pinned httpcore pool is enough.
        transport._pool = httpcore.AsyncConnectionPool(
            ssl_context=httpx.create_ssl_context(),
            max_connections=100,
            max_keepalive_connections=20,
            keepalive_expiry=5.0,
            network_backend=_PinnedNetworkBackend(self._pins),
        )
        return transport

    async def __aenter__(self) -> SafeHttpClient:
        self._client = httpx.AsyncClient(
            follow_redirects=False,
            timeout=httpx.Timeout(self.timeout, connect=min(self.timeout, 5.0)),
            headers={"User-Agent": self._user_agent, "Accept": "*/*"},
            transport=None if self._proxy_url else (self._transport or self._pinned_transport()),
            proxy=self._proxy_url,
            # Ignore ambient HTTP(S)_PROXY/NO_PROXY: outbound traffic must only follow
            # the validated scope, and malformed NO_PROXY entries break URL parsing.
            trust_env=False,
        )
        return self

    async def __aexit__(self, *exc_info) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    @property
    def request_count(self) -> int:
        return self._requests

    @property
    def elapsed_seconds(self) -> float:
        return time.monotonic() - self._started

    def _check_budget(self) -> None:
        if self._requests >= self.max_requests:
            raise BudgetExceeded(f"request budget exhausted ({self.max_requests})")
        if self.elapsed_seconds >= self.max_seconds:
            raise BudgetExceeded(f"time budget exhausted ({self.max_seconds:.0f}s)")

    def _check_cancel(self) -> None:
        if self._cancel_check is not None and self._cancel_check():
            raise ScanCancelled("scan cancelled by operator")

    async def _validate(self, url: str) -> None:
        self.scope.check(url)
        parts = urlsplit(url)
        port = parts.port or (443 if parts.scheme == "https" else 80)
        kwargs = {"allow_private": self.allow_private}
        if self._resolver is not None:
            kwargs["resolver"] = self._resolver
        host = (parts.hostname or "").strip("[]").lower()
        addresses = await assert_host_allowed(host, port, **kwargs)
        self._pins[host] = addresses[0]

    async def get(self, url: str, *, headers: dict[str, str] | None = None) -> ResponseBundle:
        return await self.request("GET", url, headers=headers)

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json: dict | None = None,
        data: dict | None = None,
        content: str | bytes | None = None,
        max_redirects: int = 5,
        follow_redirects: bool = True,
    ) -> ResponseBundle:
        if self._client is None:
            raise RuntimeError("SafeHttpClient must be used as an async context manager")

        started = time.monotonic()
        chain: list[str] = []
        current_method = method.upper()

        for _ in range(max_redirects + 1):
            self._check_cancel()
            self._check_budget()
            try:
                await self._validate(url)
            except ScopeViolation:
                raise
            except SSRFBlocked:
                raise
            await self._bucket.acquire()
            try:
                response = await self._client.request(
                    current_method,
                    url,
                    headers=headers,
                    json=json,
                    data=data,
                    content=content,
                )
            except httpx.HTTPError as exc:
                raise TargetUnreachable(f"{current_method} {url} failed: {exc}") from exc
            self._requests += 1

            location = response.headers.get("location")
            if response.is_redirect and location:
                nxt = urljoin(url, location)
                chain.append(url)
                if not follow_redirects:
                    return self._bundle(response, started, chain)
                if response.status_code == 303 or (
                    response.status_code in (301, 302) and current_method != "HEAD"
                ):
                    current_method, json, data, content = "GET", None, None, None
                url = nxt
                continue

            return self._bundle(response, started, chain)

        raise TooManyRedirects(f"more than {max_redirects} redirects from {method} {url}")

    @staticmethod
    def _bundle(response: httpx.Response, started: float, chain: list[str]) -> ResponseBundle:
        try:
            body = response.text
        except Exception:
            body = response.content.decode("utf-8", "replace")
        return ResponseBundle(
            url=str(response.url),
            status_code=response.status_code,
            headers={k.lower(): v for k, v in response.headers.items()},
            body=body[:200_000],
            elapsed_ms=int((time.monotonic() - started) * 1000),
            size=len(response.content),
            redirect_chain=list(chain),
            set_cookies=response.headers.get_list("set-cookie"),
        )
