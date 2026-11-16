from __future__ import annotations

import pytest
from venomscan_engine.recon.ip_intel import (
    _origin_name,
    classify_address,
    collect_ip_intel,
    lookup_ip_intel,
    sweep_neighbours,
)


class _Answer:
    def __init__(self, text: str) -> None:
        self.text = text

    def to_text(self) -> str:
        return self.text


class _Resolver:
    def __init__(self, mapping: dict[str, list[_Answer]]) -> None:
        self.mapping = mapping
        self.lifetime = 2
        self.timeout = 2

    def resolve(self, host: str, rtype: str, lifetime: float | None = None):
        return self.mapping.get(rtype, [])


class _HostResolver:
    def __init__(self, mapping: dict[tuple[str, str], list[_Answer]]) -> None:
        self.mapping = mapping
        self.lifetime = 2
        self.timeout = 2

    def resolve(self, host: str, rtype: str, lifetime: float | None = None):
        return self.mapping.get((host, rtype), [])


def test_classify_address_scopes():
    assert classify_address("93.184.216.34") == (4, "public")
    assert classify_address("10.1.2.3") == (4, "private")
    assert classify_address("127.0.0.1") == (4, "loopback")
    assert classify_address("169.254.169.254") == (4, "link-local")
    assert classify_address("2606:2800:220:1:248:1893:25c8:1946") == (6, "public")
    assert classify_address("not-an-ip") is None


def test_collect_ip_intel_marks_hosting_from_ptr():
    report = collect_ip_intel(
        "shop.example.com",
        {"A": ["93.184.216.34", "10.0.0.5"], "AAAA": ["2606:2800::1"]},
        resolver=_Resolver({"PTR": [_Answer("ec2-93-184-216-34.compute-1.amazonaws.com.")]}),
    )
    assert len(report.addresses) == 3
    scopes = {item.address: item.scope for item in report.addresses}
    assert scopes["10.0.0.5"] == "private"
    assert scopes["93.184.216.34"] == "public"
    assert report.addresses[0].ptr == "ec2-93-184-216-34.compute-1.amazonaws.com"
    assert report.hosting == ["Amazon AWS"]
    assert "public" in report.summary()


def test_collect_ip_intel_handles_ip_literal_without_records():
    report = collect_ip_intel("127.0.0.1")
    assert [item.address for item in report.addresses] == ["127.0.0.1"]
    assert report.addresses[0].scope == "loopback"


def test_origin_name_builds_cymru_queries():
    assert _origin_name("93.184.216.34") == "34.216.184.93.origin.asn.cymru.com"
    assert _origin_name("2606:2800::1").endswith(".origin6.asn.cymru.com")
    assert _origin_name("not-an-ip") is None


def test_collect_ip_intel_enriches_public_addresses_with_asn():
    resolver = _HostResolver(
        {
            ("34.216.184.93.origin.asn.cymru.com", "TXT"): [
                _Answer("16509 | 93.184.216.0/24 | US | arin | 2008-06-30")
            ],
            ("AS16509.asn.cymru.com", "TXT"): [
                _Answer("16509 | US | arin | 2000-03-30 | AMAZON-02 - Amazon.com, Inc., US")
            ],
        }
    )
    report = collect_ip_intel(
        "shop.example.com",
        {"A": ["93.184.216.34", "10.0.0.5"]},
        resolver=resolver,
    )

    public = report.addresses[0]
    assert public.asn == "AS16509"
    assert public.prefix == "93.184.216.0/24"
    assert public.country == "US"
    assert public.as_name and "Amazon" in public.as_name
    assert "Amazon AWS" in report.hosting
    assert "93.184.216.0/24" in report.summary()
    assert report.addresses[1].asn is None
    assert report.as_dict()["addresses"][0]["country"] == "US"


@pytest.mark.asyncio
async def test_lookup_ip_intel_never_raises_on_resolver_failure():
    class _Broken:
        lifetime = 1
        timeout = 1

        def resolve(self, *args, **kwargs):
            raise OSError("resolver down")

    report = await lookup_ip_intel("example.com", {"A": ["93.184.216.34"]}, resolver=_Broken())
    assert report.addresses[0].address == "93.184.216.34"
    assert report.addresses[0].ptr is None


def test_sweep_neighbours_limits_ptr_queries():
    resolver = _HostResolver(
        {
            ("35.216.184.93.in-addr.arpa.", "PTR"): [_Answer("mail.example.net.")],
            ("36.216.184.93.in-addr.arpa.", "PTR"): [_Answer("vpn.example.net.")],
        }
    )
    report = sweep_neighbours(["93.184.216.34"], resolver, limit=4, timeout=0.5)

    assert report.prefix == "93.184.216.0/24"
    assert report.queried == 4
    assert report.hosts == [
        {"address": "93.184.216.35", "ptr": "mail.example.net"},
        {"address": "93.184.216.36", "ptr": "vpn.example.net"},
    ]
    assert "2 named neighbour(s)" in report.summary()


def test_sweep_neighbours_requires_public_ipv4():
    report = sweep_neighbours(["10.0.0.5", "2606:2800::1"], _HostResolver({}))
    assert report.hosts == []
    assert report.error == "no public IPv4 address"
