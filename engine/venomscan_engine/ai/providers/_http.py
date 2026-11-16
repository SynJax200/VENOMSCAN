from __future__ import annotations

import asyncio

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


async def post_json(
    url: str,
    *,
    headers: dict[str, str],
    body: dict,
    timeout_seconds: float,
    transport,
    retries: int = 1,
    backoff: float = 0.4,
) -> httpx.Response:
    """POST JSON with bounded retries on transient failures.

    Retries cover transport errors, 408/429 and 5xx responses. Retry-After is
    honoured up to two seconds so a scan request never hangs on a throttled provider.
    """
    attempts = max(1, int(retries) + 1)
    last_error = "provider unavailable"
    async with httpx.AsyncClient(
        timeout=timeout_seconds, transport=transport, trust_env=False
    ) as client:
        for attempt in range(1, attempts + 1):
            try:
                response = await client.post(url, headers=headers, json=body)
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
            if response.status_code >= 400:
                raise LLMError(f"provider returned HTTP {response.status_code}")
            return response
    raise LLMError(last_error)
