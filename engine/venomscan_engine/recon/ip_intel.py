from __future__ import annotations

import asyncio
import ipaddress
import time
from dataclasses import dataclass, field
from typing import Any

MAX_ADDRESSES = 12
MAX_PTR = 4
MAX_ASN_LOOKUPS = 4
MAX_NEIGHBOURS = 16

_HOSTING_MARKERS: tuple[tuple[str, str], ...] = (
    ("cloudfront.net", "Amazon CloudFront"),
    ("amazonaws.com", "Amazon AWS"),
    ("akamai", "Akamai"),
    ("akamai.net", "Akamai"),
    ("cloudflare", "Cloudflare"),
    ("fastly", "Fastly"),
    ("1e100.net", "Google"),
    ("googleusercontent", "Google Cloud"),
    ("azure", "Microsoft Azure"),
    ("digitalocean", "DigitalOcean"),
    ("linode", "Linode"),
    ("hetzner", "Hetzner"),
    ("ovh.net", "OVH"),
)

# AS names are free text, so these markers are matched case-insensitively.
_ASN_HOSTING_MARKERS: tuple[tuple[str, str], ...] = (
    ("amazon", "Amazon AWS"),
    ("google", "Google"),
    ("microsoft", "Microsoft Azure"),
    ("cloudflare", "Cloudflare"),
    ("fastly", "Fastly"),
    ("akamai", "Akamai"),
    ("digitalocean", "DigitalOcean"),
    ("linode", "Linode"),
    ("hetzner", "Hetzner"),
    ("ovh", "OVH"),
)


@dataclass
class IPAddressInfo:
    address: str
    version: int
    scope: str
    ptr: str | None = None
    asn: str | None = None
    as_name: str | None = None
    prefix: str | None = None
    country: str | None = None


@dataclass
class IPIntel:
    host: str
    addresses: list[IPAddressInfo] = field(default_factory=list)
    hosting: list[str] = field(default_factory=list)
    error: str | None = None

    def summary(self) -> str:
        if not self.addresses:
            return self.error or "No IP addresses resolved"
        scopes = sorted({item.scope for item in self.addresses})
        text = f"{len(self.addresses)} address(es): {', '.join(scopes)}"
        prefixes = sorted({item.prefix for item in self.addresses if item.prefix})
        if prefixes:
            text += f" · {', '.join(prefixes[:3])}"
        if self.hosting:
            text += f" · {', '.join(self.hosting)}"
        return text

    def as_dict(self) -> dict:
        return {
            "host": self.host,
            "addresses": [
                {
                    "address": item.address,
                    "version": item.version,
                    "scope": item.scope,
                    "ptr": item.ptr,
                    "asn": item.asn,
                    "as_name": item.as_name,
                    "prefix": item.prefix,
                    "country": item.country,
                }
                for item in self.addresses
            ],
            "hosting": self.hosting,
            "error": self.error,
        }


@dataclass
class NeighbourReport:
    prefix: str
    queried: int = 0
    hosts: list[dict] = field(default_factory=list)
    error: str | None = None

    def summary(self) -> str:
        if self.error:
            return f"Reverse-DNS neighbourhood skipped: {self.error}"
        return f"{len(self.hosts)} named neighbour(s) in {self.prefix} ({self.queried} PTR queries)"

    def as_dict(self) -> dict:
        return {
            "prefix": self.prefix,
            "queried": self.queried,
            "hosts": self.hosts,
            "count": len(self.hosts),
            "error": self.error,
        }


def classify_address(address: str) -> tuple[int, str] | None:
    try:
        parsed = ipaddress.ip_address(address.strip().rstrip("."))
    except ValueError:
        return None
    if parsed.is_loopback:
        scope = "loopback"
    elif parsed.is_link_local:
        scope = "link-local"
    elif parsed.is_multicast:
        scope = "multicast"
    elif parsed.is_private:
        scope = "private"
    elif parsed.is_reserved:
        scope = "reserved"
    elif parsed.is_unspecified:
        scope = "unspecified"
    else:
        scope = "public"
    return parsed.version, scope


def _hosting_from_ptr(ptr: str) -> str | None:
    lowered = ptr.lower()
    for marker, label in _HOSTING_MARKERS:
        if marker in lowered:
            return label
    return None


def _hosting_from_asn(as_name: str) -> str | None:
    lowered = as_name.lower()
    for marker, label in _ASN_HOSTING_MARKERS:
        if marker in lowered:
            return label
    return None


def _reverse_lookup(resolver: Any, address: str, timeout: float) -> str | None:
    import dns.exception
    import dns.reversename

    try:
        name = dns.reversename.from_address(address)
        answers = resolver.resolve(name.to_text(), "PTR", lifetime=timeout)
        for answer in answers:
            value = answer.to_text().strip().rstrip(".")
            if value:
                return value
    except (dns.exception.DNSException, ValueError, OSError):
        return None
    return None


def _origin_name(address: str) -> str | None:
    import ipaddress

    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    if parsed.version == 4:
        return ".".join(reversed(str(parsed).split("."))) + ".origin.asn.cymru.com"
    nibbles = ".".join(reversed(parsed.exploded.replace(":", "")))
    return f"{nibbles}.origin6.asn.cymru.com"


def _txt_value(answer: Any) -> str:
    chunks = getattr(answer, "strings", None)
    if chunks:
        return "".join(chunk.decode("utf-8", "replace") if isinstance(chunk, bytes) else chunk for chunk in chunks)
    return answer.to_text().strip().strip('"')


def _asn_lookup(resolver: Any, address: str, timeout: float) -> dict[str, str] | None:
    """Team Cymru DNS: origin AS, BGP prefix and registry country (no API key)."""

    import dns.exception

    origin = _origin_name(address)
    if origin is None:
        return None
    try:
        answers = resolver.resolve(origin, "TXT", lifetime=timeout)
        text = next((_txt_value(answer) for answer in answers if _txt_value(answer)), "")
    except (dns.exception.DNSException, ValueError, OSError):
        return None
    fields = [field.strip() for field in text.split("|")]
    if len(fields) < 2 or not fields[0] or not fields[0].isdigit():
        return None
    result = {
        "asn": fields[0],
        "prefix": fields[1] if len(fields) > 1 else "",
        "country": fields[2] if len(fields) > 2 else "",
    }
    try:
        answers = resolver.resolve(f"AS{fields[0]}.asn.cymru.com", "TXT", lifetime=timeout)
        text = next((_txt_value(answer) for answer in answers if _txt_value(answer)), "")
    except (dns.exception.DNSException, ValueError, OSError):
        return result
    parts = [field.strip() for field in text.split("|")]
    if len(parts) >= 5 and parts[4]:
        result["as_name"] = parts[4]
    return result


def collect_ip_intel(
    host: str,
    records: dict[str, list[str]] | None = None,
    *,
    resolver: Any | None = None,
    timeout: float = 2.0,
) -> IPIntel:
    """Classify resolved addresses and optionally resolve PTR names."""

    report = IPIntel(host=host)
    candidates: list[str] = []
    if classify_address(host) is not None:
        candidates.append(host)
    for rtype in ("A", "AAAA"):
        candidates.extend(records.get(rtype, []) if records else [])

    seen: set[str] = set()
    for candidate in candidates:
        if len(report.addresses) >= MAX_ADDRESSES:
            break
        parsed = classify_address(candidate)
        if parsed is None or candidate in seen:
            continue
        seen.add(candidate)
        report.addresses.append(
            IPAddressInfo(address=candidate, version=parsed[0], scope=parsed[1])
        )

    if resolver is not None and report.addresses:
        deadline = time.monotonic() + max(timeout * 2, 1.0)
        for item in report.addresses[:MAX_PTR]:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            ptr = _reverse_lookup(resolver, item.address, min(timeout, remaining))
            if ptr is None:
                continue
            item.ptr = ptr
            label = _hosting_from_ptr(ptr)
            if label is not None and label not in report.hosting:
                report.hosting.append(label)

        public = [item for item in report.addresses if item.scope == "public"]
        for item in public[:MAX_ASN_LOOKUPS]:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            data = _asn_lookup(resolver, item.address, min(timeout, remaining))
            if data is None:
                continue
            item.asn = f"AS{data['asn']}"
            item.prefix = data.get("prefix") or None
            item.country = data.get("country") or None
            item.as_name = data.get("as_name") or None
            if item.as_name:
                label = _hosting_from_asn(item.as_name)
                if label is not None and label not in report.hosting:
                    report.hosting.append(label)

    return report


def _neighbour_candidates(address: str, limit: int) -> list[str]:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return []
    if parsed.version != 4:
        return []
    octets = str(parsed).split(".")
    base = ".".join(octets[:3])
    last = int(octets[3])
    candidates: list[str] = []
    for offset in range(1, 255):
        host = (last + offset) % 256
        if host in (0, 255):
            continue
        candidates.append(f"{base}.{host}")
        if len(candidates) >= limit:
            break
    return candidates


def sweep_neighbours(
    addresses: list[str],
    resolver: Any,
    *,
    limit: int = MAX_NEIGHBOURS,
    timeout: float = 1.0,
) -> NeighbourReport:
    """Reverse-resolve a bounded slice of the target's own /24 (DNS only, no fetches)."""

    seed: str | None = None
    for address in addresses:
        parsed = classify_address(address)
        if parsed is not None and parsed[0] == 4 and parsed[1] == "public":
            seed = address
            break
    if seed is None:
        return NeighbourReport(prefix="", error="no public IPv4 address")

    report = NeighbourReport(prefix=seed.rsplit(".", 1)[0] + ".0/24")
    deadline = time.monotonic() + min(max(timeout * limit, 2.0), 8.0)
    for candidate in _neighbour_candidates(seed, limit):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        report.queried += 1
        ptr = _reverse_lookup(resolver, candidate, min(timeout, remaining))
        if ptr is not None:
            report.hosts.append({"address": candidate, "ptr": ptr})
    return report


async def lookup_neighbours(
    addresses: list[str],
    *,
    resolver: Any | None = None,
    limit: int = MAX_NEIGHBOURS,
    timeout: float = 1.0,  # noqa: ASYNC109 - thread offload needs the timeout value
) -> NeighbourReport:
    """Run the reverse-DNS neighbourhood sweep in a worker thread; never raises."""

    def _run() -> NeighbourReport:
        active = resolver
        if active is None:
            import dns.resolver

            active = dns.resolver.Resolver()
        return sweep_neighbours(addresses, active, limit=limit, timeout=timeout)

    try:
        return await asyncio.to_thread(_run)
    except Exception as exc:  # neighbourhood data is enrichment only
        return NeighbourReport(prefix="", error=f"{type(exc).__name__}: {str(exc)[:120]}")


async def lookup_ip_intel(
    host: str,
    records: dict[str, list[str]] | None = None,
    *,
    resolver: Any | None = None,
    timeout: float = 2.0,  # noqa: ASYNC109 - thread offload needs the timeout value
) -> IPIntel:
    """Run IP intelligence in a worker thread; failures never raise."""

    def _run() -> IPIntel:
        active = resolver
        if active is None:
            import dns.resolver

            active = dns.resolver.Resolver()
            try:
                active.lifetime = timeout
                active.timeout = min(timeout, 2.0)
            except AttributeError:
                pass
        return collect_ip_intel(host, records, resolver=active, timeout=timeout)

    try:
        return await asyncio.to_thread(_run)
    except Exception as exc:  # resolver failures must not sink the scan
        return IPIntel(host=host, error=f"{type(exc).__name__}: {str(exc)[:160]}")


__all__ = [
    "IPAddressInfo",
    "IPIntel",
    "NeighbourReport",
    "classify_address",
    "collect_ip_intel",
    "lookup_ip_intel",
    "lookup_neighbours",
    "sweep_neighbours",
]
