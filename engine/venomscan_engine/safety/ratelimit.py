from __future__ import annotations

import asyncio
import time


class TokenBucket:
    """Async token bucket, per (scan, host) in production use."""

    def __init__(self, rate: float, burst: float | None = None) -> None:
        self.rate = max(rate, 0.1)
        self.capacity = burst if burst is not None else max(rate, 1.0)
        self._tokens = self.capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._updated
                self._updated = now
                self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                wait = (tokens - self._tokens) / self.rate
                await asyncio.sleep(min(wait, 2.0))
