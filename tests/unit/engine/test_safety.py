from __future__ import annotations

import ipaddress

import pytest
from venomscan_engine.safety.scope import Scope, ScopeViolation
from venomscan_engine.safety.ssrf import SSRFBlocked, assert_host_allowed, is_blocked


def test_scope_allows_exact_host_only():
    scope = Scope.from_target("https://app.example.com/login")
    scope.check("https://app.example.com/other?x=1")
    with pytest.raises(ScopeViolation):
        scope.check("https://api.example.com/")
    with pytest.raises(ScopeViolation):
        scope.check("https://evil.test/")


def test_scope_subdomains_opt_in():
    scope = Scope.from_target("https://example.com", include_subdomains=True)
    scope.check("https://api.example.com/")
    with pytest.raises(ScopeViolation):
        scope.check("https://example.com.evil.test/")


def test_scope_rejects_other_schemes():
    scope = Scope.from_target("https://example.com")
    with pytest.raises(ScopeViolation):
        scope.check("ftp://example.com/")


def test_scope_requires_hostname():
    with pytest.raises(ValueError):
        Scope.from_target("not-a-url")


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.5",
        "172.16.4.4",
        "192.168.1.1",
        "169.254.1.1",
        "100.64.0.1",
        "::1",
        "fd00::1",
    ],
)
def test_private_and_metadata_addresses_blocked(address):
    assert is_blocked(ipaddress.ip_address(address), allow_private=False) is not None


def test_public_address_allowed():
    assert is_blocked(ipaddress.ip_address("93.184.216.34"), allow_private=False) is None


def test_metadata_endpoint_blocked_even_when_private_allowed():
    reason = is_blocked(ipaddress.ip_address("169.254.169.254"), allow_private=True)
    assert reason == "cloud metadata endpoint"


@pytest.mark.asyncio
async def test_resolution_to_private_address_is_blocked(public_resolver):
    async def private_resolver(host: str, port: int) -> list[str]:
        return ["10.0.0.9"]

    with pytest.raises(SSRFBlocked):
        await assert_host_allowed(
            "internal.example.com", 443, allow_private=False, resolver=private_resolver
        )


@pytest.mark.asyncio
async def test_localhost_hostname_never_allowed(public_resolver):
    with pytest.raises(SSRFBlocked):
        await assert_host_allowed("localhost", 80, allow_private=True, resolver=public_resolver)


@pytest.mark.asyncio
async def test_public_resolution_returns_addresses(public_resolver):
    addresses = await assert_host_allowed(
        "example.com", 443, allow_private=False, resolver=public_resolver
    )
    assert addresses == ["93.184.216.34"]
