from __future__ import annotations

import hashlib
import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol


@dataclass
class _Window:
    count: int
    expires_at: float


class LoginThrottle(Protocol):
    """Failed-login throttle shared by the auth router (memory or Redis backed)."""

    def retry_after(self, email: str, ip: str) -> int: ...

    def record_failure(self, email: str, ip: str) -> int: ...

    def record_success(self, email: str) -> None: ...

    def reset(self) -> None: ...


class MemoryLoginGuard:
    """Per-process throttle and account lockout.

    Correct for a single API process. Use `RedisLoginGuard` when more than one
    API worker serves logins, otherwise each worker keeps its own counters.
    """

    def __init__(
        self,
        *,
        max_attempts: int = 5,
        ip_max_attempts: int = 20,
        window_seconds: int = 300,
        lockout_seconds: int = 900,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.max_attempts = max(1, max_attempts)
        self.ip_max_attempts = max(self.max_attempts, ip_max_attempts)
        self.window_seconds = max(1, window_seconds)
        self.lockout_seconds = max(1, lockout_seconds)
        self._clock = clock
        self._lock = threading.Lock()
        self._windows: dict[str, _Window] = {}
        self._locked: dict[str, float] = {}

    # ---------------------------------------------------------------- internals

    def _prune(self, now: float) -> None:
        for key in [key for key, window in self._windows.items() if window.expires_at <= now]:
            del self._windows[key]
        for key in [key for key, until in self._locked.items() if until <= now]:
            del self._locked[key]

    def _window(self, key: str, now: float) -> _Window:
        window = self._windows.get(key)
        if window is None or window.expires_at <= now:
            window = _Window(count=0, expires_at=now + self.window_seconds)
            self._windows[key] = window
        return window

    def _retry_after(self, email: str, ip: str, now: float) -> int:
        locked_until = self._locked.get(email)
        if locked_until and locked_until > now:
            return max(1, math.ceil(locked_until - now))
        account = self._windows.get(f"acct:{email}")
        if account and account.expires_at > now and account.count >= self.max_attempts:
            return max(1, math.ceil(account.expires_at - now))
        client = self._windows.get(f"ip:{ip}")
        if client and client.expires_at > now and client.count >= self.ip_max_attempts:
            return max(1, math.ceil(client.expires_at - now))
        return 0

    # ------------------------------------------------------------------- public

    def retry_after(self, email: str, ip: str) -> int:
        now = self._clock()
        with self._lock:
            self._prune(now)
            return self._retry_after(email, ip, now)

    def record_failure(self, email: str, ip: str) -> int:
        """Count a failed attempt; returns lockout seconds when the account locks."""

        now = self._clock()
        with self._lock:
            self._prune(now)
            account = self._window(f"acct:{email}", now)
            account.count += 1
            client = self._window(f"ip:{ip}", now)
            client.count += 1
            if account.count >= self.max_attempts:
                self._windows.pop(f"acct:{email}", None)
                self._locked[email] = now + self.lockout_seconds
                return self.lockout_seconds
            return 0

    def record_success(self, email: str) -> None:
        with self._lock:
            self._windows.pop(f"acct:{email}", None)
            self._locked.pop(email, None)

    def reset(self) -> None:
        with self._lock:
            self._windows.clear()
            self._locked.clear()


class RedisLoginGuard:
    """Throttle shared through Redis so every API worker sees the same counters.

    Keys hold a salted hash of the email (no PII in Redis). If Redis is
    unreachable the guard falls back to its own in-process state, so a cache
    outage degrades to per-worker enforcement instead of failing sign-in.
    """

    def __init__(
        self,
        client: Any,
        *,
        max_attempts: int = 5,
        ip_max_attempts: int = 20,
        window_seconds: int = 300,
        lockout_seconds: int = 900,
        namespace: str = "venomscan:login",
    ) -> None:
        self._client = client
        self.namespace = namespace
        self.max_attempts = max(1, max_attempts)
        self.ip_max_attempts = max(self.max_attempts, ip_max_attempts)
        self.window_seconds = max(1, window_seconds)
        self.lockout_seconds = max(1, lockout_seconds)
        self._fallback = MemoryLoginGuard(
            max_attempts=self.max_attempts,
            ip_max_attempts=self.ip_max_attempts,
            window_seconds=self.window_seconds,
            lockout_seconds=self.lockout_seconds,
        )

    # ---------------------------------------------------------------- internals

    def _key(self, kind: str, value: str) -> str:
        digest = hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()[:32]
        return f"{self.namespace}:{kind}:{digest}"

    def _ttl(self, key: str) -> int:
        ttl = self._client.ttl(key)
        return int(ttl) if isinstance(ttl, (int, float)) and ttl > 0 else 0

    # ------------------------------------------------------------------- public

    def retry_after(self, email: str, ip: str) -> int:
        try:
            lock_ttl = self._ttl(self._key("lock", email))
            if lock_ttl:
                return lock_ttl
            account = self._client.get(self._key("acct", email))
            if account is not None and int(account) >= self.max_attempts:
                return self._ttl(self._key("acct", email)) or 1
            client = self._client.get(self._key("ip", ip))
            if client is not None and int(client) >= self.ip_max_attempts:
                return self._ttl(self._key("ip", ip)) or 1
            return 0
        except Exception:
            return self._fallback.retry_after(email, ip)

    def record_failure(self, email: str, ip: str) -> int:
        try:
            account_key = self._key("acct", email)
            account = int(self._client.incr(account_key))
            if account == 1:
                self._client.expire(account_key, self.window_seconds)
            ip_key = self._key("ip", ip)
            client = int(self._client.incr(ip_key))
            if client == 1:
                self._client.expire(ip_key, self.window_seconds)
            if account >= self.max_attempts:
                self._client.set(self._key("lock", email), "1", ex=self.lockout_seconds)
                self._client.delete(account_key)
                return self.lockout_seconds
            return 0
        except Exception:
            return self._fallback.record_failure(email, ip)

    def record_success(self, email: str) -> None:
        try:
            self._client.delete(self._key("acct", email), self._key("lock", email))
        except Exception:
            self._fallback.record_success(email)

    def reset(self) -> None:
        try:
            pattern = f"{self.namespace}:*"
            keys = list(self._client.scan_iter(match=pattern, count=500))
            if keys:
                self._client.delete(*keys)
        except Exception:
            pass
        self._fallback.reset()


def build_login_guard(
    *,
    backend: str = "memory",
    redis_url: str = "",
    max_attempts: int = 5,
    ip_max_attempts: int = 20,
    window_seconds: int = 300,
    lockout_seconds: int = 900,
) -> LoginThrottle:
    """Redis gives every API worker the same counters; memory is single-process."""

    if backend.lower() == "redis" and redis_url:
        import redis

        client = redis.Redis.from_url(
            redis_url,
            socket_connect_timeout=1.0,
            socket_timeout=1.0,
            decode_responses=True,
        )
        return RedisLoginGuard(
            client,
            max_attempts=max_attempts,
            ip_max_attempts=ip_max_attempts,
            window_seconds=window_seconds,
            lockout_seconds=lockout_seconds,
        )
    return MemoryLoginGuard(
        max_attempts=max_attempts,
        ip_max_attempts=ip_max_attempts,
        window_seconds=window_seconds,
        lockout_seconds=lockout_seconds,
    )


__all__ = ["LoginThrottle", "MemoryLoginGuard", "RedisLoginGuard", "build_login_guard"]
