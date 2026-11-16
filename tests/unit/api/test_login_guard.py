from __future__ import annotations

from venomscan_api.services.login_guard import (
    MemoryLoginGuard,
    RedisLoginGuard,
    build_login_guard,
)


def test_guard_locks_account_after_threshold():
    now = [1000.0]
    guard = MemoryLoginGuard(
        max_attempts=3, window_seconds=60, lockout_seconds=120, clock=lambda: now[0]
    )

    assert guard.record_failure("user@example.com", "203.0.113.7") == 0
    assert guard.record_failure("user@example.com", "203.0.113.7") == 0
    assert guard.record_failure("user@example.com", "203.0.113.7") == 120
    assert guard.retry_after("user@example.com", "203.0.113.7") == 120

    now[0] += 121
    assert guard.retry_after("user@example.com", "203.0.113.7") == 0


def test_guard_throttles_ip_across_accounts():
    guard = MemoryLoginGuard(
        max_attempts=2, ip_max_attempts=2, window_seconds=30, lockout_seconds=60
    )

    guard.record_failure("first@example.com", "198.51.100.9")
    guard.record_failure("second@example.com", "198.51.100.9")

    assert guard.retry_after("third@example.com", "198.51.100.9") > 0
    assert guard.retry_after("third@example.com", "198.51.100.10") == 0


def test_guard_success_clears_account_failures():
    guard = MemoryLoginGuard(max_attempts=4, window_seconds=60, lockout_seconds=60)

    guard.record_failure("user@example.com", "203.0.113.7")
    guard.record_failure("user@example.com", "203.0.113.7")
    guard.record_success("user@example.com")

    assert guard.retry_after("user@example.com", "203.0.113.7") == 0
    for _ in range(3):
        assert guard.record_failure("user@example.com", "203.0.113.7") == 0


class _FakeRedis:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.expires: dict[str, int] = {}

    def incr(self, key: str) -> int:
        value = int(self.values.get(key, 0)) + 1
        self.values[key] = str(value)
        return value

    def expire(self, key: str, seconds: int) -> bool:
        self.expires[key] = seconds
        return True

    def get(self, key: str) -> str | None:
        return self.values.get(key)

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        self.values[key] = value
        if ex:
            self.expires[key] = ex

    def delete(self, *keys: str) -> int:
        removed = 0
        for key in keys:
            if self.values.pop(key, None) is not None:
                removed += 1
            self.expires.pop(key, None)
        return removed

    def ttl(self, key: str) -> int:
        return self.expires.get(key, -2)

    def scan_iter(self, match: str | None = None, count: int | None = None):
        prefix = (match or "").rstrip("*")
        return [key for key in self.values if key.startswith(prefix)]


class _BrokenRedis:
    def __getattr__(self, name):
        raise RuntimeError("redis unavailable")


def test_redis_guard_shares_lockout_and_hashes_emails():
    client = _FakeRedis()
    guard = RedisLoginGuard(
        client, max_attempts=3, window_seconds=60, lockout_seconds=120
    )

    assert guard.record_failure("user@example.com", "203.0.113.7") == 0
    assert guard.record_failure("user@example.com", "203.0.113.7") == 0
    assert guard.record_failure("user@example.com", "203.0.113.7") == 120
    assert guard.retry_after("user@example.com", "203.0.113.7") == 120
    assert not any("user@example.com" in key for key in client.values)


def test_redis_guard_throttles_ip_without_locking_other_accounts():
    client = _FakeRedis()
    guard = RedisLoginGuard(
        client, max_attempts=2, ip_max_attempts=2, window_seconds=30, lockout_seconds=60
    )

    guard.record_failure("first@example.com", "198.51.100.9")
    guard.record_failure("second@example.com", "198.51.100.9")

    assert guard.retry_after("third@example.com", "198.51.100.9") > 0
    assert guard.retry_after("third@example.com", "198.51.100.10") == 0
    assert guard.retry_after("first@example.com", "198.51.100.9") > 0


def test_redis_guard_success_clears_account_state():
    client = _FakeRedis()
    guard = RedisLoginGuard(
        client, max_attempts=3, window_seconds=60, lockout_seconds=60
    )

    guard.record_failure("user@example.com", "203.0.113.7")
    guard.record_failure("user@example.com", "203.0.113.7")
    guard.record_success("user@example.com")

    assert guard.retry_after("user@example.com", "203.0.113.7") == 0
    for _ in range(2):
        assert guard.record_failure("user@example.com", "203.0.113.7") == 0


def test_redis_guard_falls_back_to_process_state_when_redis_fails():
    guard = RedisLoginGuard(
        _BrokenRedis(), max_attempts=2, window_seconds=30, lockout_seconds=45
    )

    assert guard.record_failure("user@example.com", "203.0.113.7") == 0
    assert guard.record_failure("user@example.com", "203.0.113.7") == 45
    assert guard.retry_after("user@example.com", "203.0.113.7") > 0


def test_build_login_guard_selects_backend():
    assert isinstance(build_login_guard(backend="memory"), MemoryLoginGuard)
    assert isinstance(build_login_guard(backend="redis", redis_url=""), MemoryLoginGuard)
    guard = build_login_guard(
        backend="redis", redis_url="redis://127.0.0.1:1/0", max_attempts=2
    )
    assert isinstance(guard, RedisLoginGuard)
