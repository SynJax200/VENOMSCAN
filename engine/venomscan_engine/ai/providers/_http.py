from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit

import httpx

from venomscan_engine.ai.provider import LLMError

RETRY_STATUS = {408, 429, 500, 502, 503, 504}
MAX_RETRY_AFTER = 2.0

_sleep = asyncio.sleep


def _retry_after(response: httpx.Response) -> float | None:
    value = response.headers.get("retry-after")
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None


def _pin_public_destination(url: str) -> tuple[str, dict[str, str], str | None]:
    """Resolve once, reject non-public addresses, and connect to the resolved IP.

    Pinning the connection closes the DNS-rebinding window between validation and
    use. The original hostname is preserved in Host/SNI so TLS still validates it.
    """
    parsed = urlsplit(url)
    host = parsed.hostname
    if not host:
        raise LLMError("provider URL has no host")
    scheme = parsed.scheme or "https"
    port = parsed.port or (443 if scheme == "https" else 80)
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if not literal.is_global:
            raise LLMError("provider destination is not public")
        return url, {}, None
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise LLMError("provider destination could not be resolved") from exc
    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for info in infos:
        try:
            address = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if address.is_global:
            addresses.append(address)
    if not addresses:
        raise LLMError("provider destination is not public")
    chosen = addresses[0]
    netloc = f"[{chosen}]:{port}" if chosen.version == 6 else f"{chosen}:{port}"
    pinned = urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, ""))
    host_header = host if port == (443 if scheme == "https" else 80) else f"{host}:{port}"
    return pinned, {"Host": host_header}, host


async def post_json(
    url: str,
    *,
    headers: dict[str, str],
    body: dict,
    timeout_seconds: float,
    transport,
    retries: int = 1,
    backoff: float = 0.4,
    pin_public: bool = False,
) -> httpx.Response:
    """POST JSON with bounded retries on transient failures.

    Retries cover transport errors, 408/429 and 5xx responses. Retry-After is
    honoured up to two seconds so a scan request never hangs on a throttled provider.
    """
    attempts = max(1, int(retries) + 1)
    last_error = "provider unavailable"
    request_url = url
    request_headers = dict(headers)
    extensions = None
    if pin_public and transport is None:
        request_url, pinned_headers, sni_hostname = _pin_public_destination(url)
        request_headers.update(pinned_headers)
        if sni_hostname:
            extensions = {"sni_hostname": sni_hostname}
    async with httpx.AsyncClient(
        timeout=timeout_seconds,
        transport=transport,
        trust_env=False,
        follow_redirects=False,
    ) as client:
        for attempt in range(1, attempts + 1):
            try:
                response = await client.post(
                    request_url,
                    headers=request_headers,
                    json=body,
                    extensions=extensions,
                )
            except httpx.TransportError as exc:
                last_error = f"provider unreachable: {exc.__class__.__name__}"
                if attempt < attempts:
                    await _sleep(backoff * attempt)
                    continue
                raise LLMError(last_error) from exc
            if response.status_code in RETRY_STATUS and attempt < attempts:
                delay = _retry_after(response)
                await _sleep(min(delay if delay is not None else backoff * attempt, MAX_RETRY_AFTER))
                continue
            if 300 <= response.status_code < 400:
                raise LLMError("provider redirected; redirects are not allowed")
            if response.status_code >= 400:
                raise LLMError(f"provider returned HTTP {response.status_code}")
            return response
    raise LLMError(last_error)
