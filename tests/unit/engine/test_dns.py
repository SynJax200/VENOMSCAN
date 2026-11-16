from __future__ import annotations

import dns.exception
import dns.resolver
import pytest
from venomscan_engine.recon.dns import lookup_dns, parse_dmarc_policy


class _Answer:
    def __init__(self, text: str) -> None:
        self.text = text

    def to_text(self) -> str:
        return self.text


class _TxtAnswer:
    def __init__(self, *chunks: bytes) -> None:
        self.strings = list(chunks)


class _Resolver:
    def __init__(self, mapping: dict[str, list[object]]) -> None:
        self.mapping = mapping
        self.lifetime = 5
        self.timeout = 5

    def resolve(self, host: str, rtype: str, lifetime: float | None = None):
        if rtype in self.mapping:
            return self.mapping[rtype]
        raise dns.resolver.NoAnswer()


class _HostResolver:
    def __init__(self, mapping: dict[tuple[str, str], list[object]]) -> None:
        self.mapping = mapping
        self.lifetime = 5
        self.timeout = 5

    def resolve(self, host: str, rtype: str, lifetime: float | None = None):
        if (host, rtype) in self.mapping:
            return self.mapping[(host, rtype)]
        raise dns.resolver.NoAnswer()


class _FailingResolver:
    def resolve(self, host: str, rtype: str, lifetime: float | None = None):
        raise dns.exception.DNSException("resolver offline")


@pytest.mark.asyncio
async def test_lookup_dns_collects_records():
    resolver = _Resolver(
        {
            "A": [_Answer("93.184.216.34")],
            "AAAA": [_Answer("2606:2800:220:1:248:1893:25c8:1946")],
            "TXT": [_TxtAnswer(b"v=spf1 ", b"-all")],
            "MX": [_Answer("10 mail.example.com.")],
            "SOA": [_Answer("ns1.example.com. hostmaster.example.com. 2024010101 7200 3600 1209600 3600")],
        }
    )
    report = await lookup_dns("example.com", resolver=resolver, timeout=1.0)

    assert report.records["A"] == ["93.184.216.34"]
    assert report.records["AAAA"] == ["2606:2800:220:1:248:1893:25c8:1946"]
    assert report.records["TXT"] == ["v=spf1 -all"]
    assert report.records["MX"] == ["10 mail.example.com."]
    assert report.records["SOA"] == [
        "ns1.example.com. hostmaster.example.com. 2024010101 7200 3600 1209600 3600"
    ]
    assert "CNAME" not in report.records
    assert "A×1" in report.summary()
    assert report.error is None


@pytest.mark.asyncio
async def test_lookup_dns_extracts_spf_and_dmarc():
    resolver = _HostResolver(
        {
            ("shop.example.com", "TXT"): [
                _TxtAnswer(b"v=spf1 include:_spf.example.com ", b"-all"),
                _TxtAnswer(b"google-site-verification=abc"),
            ],
            ("_dmarc.example.com", "TXT"): [
                _TxtAnswer(b"v=DMARC1; p=reject; rua=mailto:dmarc@example.com")
            ],
        }
    )
    report = await lookup_dns("shop.example.com", resolver=resolver, timeout=1.0)

    assert report.records["SPF"] == ["v=spf1 include:_spf.example.com -all"]
    assert report.records["DMARC"] == ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]
    assert report.mail["spf"] == "v=spf1 include:_spf.example.com -all"
    assert report.mail["dmarc"]["policy"] == "reject"
    assert report.mail["dmarc"]["report_uris"] == ["mailto:dmarc@example.com"]


def test_parse_dmarc_policy_reads_subdomain_and_alignment_tags():
    policy = parse_dmarc_policy(
        "v=DMARC1; p=quarantine; sp=reject; pct=50; adkim=s; aspf=r; "
        "rua=mailto:a@example.com,mailto:b@example.com; ruf=mailto:f@example.com"
    )

    assert policy["policy"] == "quarantine"
    assert policy["subdomain_policy"] == "reject"
    assert policy["percentage"] == "50"
    assert policy["dkim_alignment"] == "s"
    assert policy["spf_alignment"] == "r"
    assert policy["report_uris"] == ["mailto:a@example.com", "mailto:b@example.com"]
    assert policy["forensic_uris"] == ["mailto:f@example.com"]


@pytest.mark.asyncio
async def test_lookup_dns_probes_dkim_selectors():
    resolver = _HostResolver(
        {
            ("example.com", "TXT"): [_TxtAnswer(b"v=spf1 -all")],
            ("_dmarc.example.com", "TXT"): [_TxtAnswer(b"v=DMARC1; p=none")],
            ("default._domainkey.example.com", "TXT"): [_TxtAnswer(b"v=DKIM1; p=")],
            ("google._domainkey.example.com", "TXT"): [
                _TxtAnswer(b"v=DKIM1; k=rsa; t=y; p=", b"MIIBIjANBgkq")
            ],
        }
    )
    report = await lookup_dns("example.com", resolver=resolver, timeout=1.0)

    dkim = {entry["selector"]: entry for entry in report.mail["dkim"]}
    assert set(dkim) == {"default", "google"}
    assert dkim["default"]["revoked"] is True
    assert dkim["google"]["revoked"] is False
    assert dkim["google"]["key_type"] == "rsa"
    assert dkim["google"]["flags"] == "y"
    assert "default → rsa (revoked: empty p= tag)" in report.records["DKIM"]


@pytest.mark.asyncio
async def test_lookup_dns_probes_provider_specific_dkim_selectors():
    resolver = _HostResolver(
        {
            ("example.com", "TXT"): [_TxtAnswer(b"v=spf1 -all")],
            ("_dmarc.example.com", "TXT"): [_TxtAnswer(b"v=DMARC1; p=none")],
            ("amazonses._domainkey.example.com", "TXT"): [
                _TxtAnswer(b"v=DKIM1; k=rsa; p=", b"MIIBIjANBgkq")
            ],
        }
    )
    report = await lookup_dns("example.com", resolver=resolver, timeout=1.0)
    dkim = {entry["selector"]: entry for entry in report.mail["dkim"]}
    assert "amazonses" in dkim


@pytest.mark.asyncio
async def test_lookup_dns_prefers_apex_dmarc_when_subdomain_has_none():
    resolver = _HostResolver(
        {
            ("www.example.com", "TXT"): [_TxtAnswer(b"v=spf1 -all")],
            ("_dmarc.example.com", "TXT"): [_TxtAnswer(b"v=DMARC1; p=none")],
        }
    )
    report = await lookup_dns("www.example.com", resolver=resolver, timeout=1.0)

    assert report.records["DMARC"] == ["v=DMARC1; p=none"]


@pytest.mark.asyncio
async def test_lookup_dns_falls_back_to_apex_spf_for_subdomain_host():
    resolver = _HostResolver(
        {
            ("www.example.com", "TXT"): [_TxtAnswer(b"google-site-verification=abc")],
            ("example.com", "TXT"): [_TxtAnswer(b"v=spf1 include:mail.example.com -all")],
            ("_dmarc.example.com", "TXT"): [_TxtAnswer(b"v=DMARC1; p=quarantine; sp=reject")],
        }
    )
    report = await lookup_dns("www.example.com", resolver=resolver, timeout=1.0)

    assert report.mail["spf"] == "v=spf1 include:mail.example.com -all"
    assert report.mail["spf_domain"] == "example.com"
    assert report.mail["dmarc"]["subdomain_policy"] == "reject"


@pytest.mark.asyncio
async def test_lookup_dns_collects_srv_and_ptr():
    resolver = _HostResolver(
        {
            ("example.com", "A"): [_Answer("93.184.216.34")],
            ("_sip._tcp.example.com", "SRV"): [_Answer("10 60 5060 sip.example.com.")],
            ("34.216.184.93.in-addr.arpa.", "PTR"): [_Answer("edge.example.net.")],
        }
    )
    report = await lookup_dns("example.com", resolver=resolver, timeout=1.0)

    assert report.records["SRV"] == ["_sip._tcp → 10 60 5060 sip.example.com."]
    assert report.records["PTR"] == ["93.184.216.34 → edge.example.net"]


@pytest.mark.asyncio
async def test_lookup_dns_swallows_resolver_failure():
    report = await lookup_dns("example.com", resolver=_FailingResolver(), timeout=0.5)
    assert report.records == {}
    assert report.error and "resolver offline" in report.error
