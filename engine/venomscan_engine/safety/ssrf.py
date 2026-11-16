from __future__ import annotations

import asyncio
import ipaddress
import socket

BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata",
    "metadata.google.internal",
    "instance-data",
}

_METADATA_IPS = {ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("fd00:ec2::254")}


class SSRFBlocked(RuntimeError):
    pass


def _normalize(addr: ipaddress.IPv4Address | ipaddress.IPv6Address):
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return addr.ipv4_mapped
    return addr


def is_blocked(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address, *, allow_private: bool
) -> str | None:
    """Return a reason string when the address must not be contacted."""
    addr = _normalize(addr)
    if addr in _METADATA_IPS:
        return "cloud metadata endpoint"
    if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
        return "reserved or multicast address"
    if allow_private:
        return None
    cgnat = ipaddress.ip_network("100.64.0.0/10")
    if addr.version == 4 and addr in cgnat:
        return "carrier-grade NAT range"
    if addr.is_loopback:
        return "loopback address"
    if addr.is_link_local:
        return "link-local address"
    if addr.is_private:
        return "private network address"
    return None


async def resolve_host(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({info[4][0] for info in infos})


async def assert_host_allowed(
    host: str,
    port: int,
    *,
    allow_private: bool,
    resolver=resolve_host,
) -> list[str]:
    clean = host.strip("[]").lower()
    if clean in BLOCKED_HOSTNAMES or clean.endswith(".localhost"):
        raise SSRFBlocked(f"hostname {host!r} is never allowed")

    try:
        literal = ipaddress.ip_address(clean)
        addresses = [str(literal)]
    except ValueError:
        try:
            addresses = await resolver(clean, port)
        except (socket.gaierror, OSError) as exc:
            raise SSRFBlocked(f"cannot resolve {host!r}") from exc

    if not addresses:
        raise SSRFBlocked(f"{host!r} did not resolve to any address")

    for raw in addresses:
        reason = is_blocked(ipaddress.ip_address(raw), allow_private=allow_private)
        if reason:
            raise SSRFBlocked(f"{host} resolves to {raw} ({reason})")
    return addresses
