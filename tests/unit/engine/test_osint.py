from __future__ import annotations

import httpx
import pytest
from venomscan_engine.recon.osint import (
    _parse_whois_text,
    discover_historical_urls,
    discover_subdomains,
    lookup_whois,
    registrable_domain,
)


def test_registrable_domain_normalises_hosts():
    assert registrable_domain("API.Example.COM.") == "example.com"
    assert registrable_domain("shop.example.co.uk") == "example.co.uk"
    assert registrable_domain("127.0.0.1") is None
    assert registrable_domain("localhost") is None
    assert registrable_domain("intranet.internal") is None


def _ct_payload(request: httpx.Request) -> httpx.Response:
    if request.url.host == "crt.sh":
        assert request.url.params["q"] == "%.example.com"
        return httpx.Response(
            200,
            json=[
                {"name_value": "api.example.com\n*.example.com"},
                {"common_name": "www.example.com"},
                {"name_value": "evil.test"},
                {"name_value": "example.com"},
            ],
        )
    if request.url.host == "api.certspotter.com":
        assert request.url.params["domain"] == "example.com"
        return httpx.Response(200, json=[{"dns_names": ["api.example.com", "*.example.com"]}])
    assert request.url.host == "api.hackertarget.com"
    assert request.url.params["q"] == "example.com"
    return httpx.Response(
        200,
        text=(
            "vpn.example.com,203.0.113.10\n"
            "api.example.com,203.0.113.11\n"
            "example.com,203.0.113.12\n"
        ),
    )


@pytest.mark.asyncio
async def test_discover_subdomains_merges_ct_and_passive_dns():
    report = await discover_subdomains(
        "example.com", transport=httpx.MockTransport(_ct_payload), timeout=3
    )
    assert report.error is None
    assert report.names == ["api.example.com", "vpn.example.com", "www.example.com"]
    assert report.wildcard is True
    assert report.source == "crt.sh+certspotter+hostsearch"
    assert report.sources == {
        "crt.sh": "2 name(s)",
        "certspotter": "1 name(s)",
        "hostsearch": "2 name(s)",
    }
    assert report.as_dict()["count"] == 3


@pytest.mark.asyncio
async def test_discover_subdomains_queries_otx_only_with_a_key():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "crt.sh":
            return httpx.Response(200, json=[])
        if request.url.host == "api.certspotter.com":
            return httpx.Response(200, json=[])
        if request.url.host == "api.hackertarget.com":
            return httpx.Response(200, text="")
        assert request.url.host == "otx.alienvault.com"
        assert request.headers["X-OTX-API-KEY"] == "otx-key"
        return httpx.Response(200, json={"passive_dns": [{"hostname": "gw.example.com"}]})

    without = await discover_subdomains(
        "example.com", transport=httpx.MockTransport(handler), timeout=3
    )
    assert "otx" not in without.sources

    with_key = await discover_subdomains(
        "example.com",
        transport=httpx.MockTransport(handler),
        timeout=3,
        otx_api_key="otx-key",
    )
    assert with_key.names == ["gw.example.com"]
    assert with_key.sources["otx"] == "1 name(s)"


@pytest.mark.asyncio
async def test_discover_subdomains_survives_one_failing_source():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "crt.sh":
            return httpx.Response(200, json=[{"name_value": "api.example.com"}])
        return httpx.Response(503)

    report = await discover_subdomains(
        "example.com", transport=httpx.MockTransport(handler), timeout=3
    )
    assert report.names == ["api.example.com"]
    assert report.error == "certspotter: HTTP 503; hostsearch: HTTP 503"
    assert "partial" in report.summary()


@pytest.mark.asyncio
async def test_discover_subdomains_can_skip_optional_sources():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "crt.sh"
        return httpx.Response(200, json=[{"name_value": "api.example.com"}])

    report = await discover_subdomains(
        "example.com",
        transport=httpx.MockTransport(handler),
        timeout=3,
        include_certspotter=False,
        include_otx=False,
        include_hostsearch=False,
    )
    assert report.names == ["api.example.com"]
    assert report.source == "crt.sh"


@pytest.mark.asyncio
async def test_discover_subdomains_reports_http_error():
    transport = httpx.MockTransport(lambda request: httpx.Response(502))
    report = await discover_subdomains("example.com", transport=transport, timeout=3)
    assert report.names == []
    assert report.error == "HTTP 502"


def _history_handler(request: httpx.Request) -> httpx.Response:
    if request.url.host == "web.archive.org":
        assert request.url.params["url"] == "example.com/*"
        return httpx.Response(
            200,
            json=[
                ["original", "timestamp", "statuscode", "mimetype"],
                ["https://example.com/api/users?id=1", "20240101120000", "200", "application/json"],
                ["http://www.example.com/login", "20230505090000", "200", "text/html"],
                ["https://evil.test/steal", "20230101", "200", "text/html"],
                ["https://example.com:8443/out-of-scope-port", "20230101", "200", "text/html"],
                ["https://example.com/app.js", "20220101", "200", "application/javascript"],
            ],
        )
    assert request.url.host == "urlscan.io"
    assert request.url.params["q"] == "domain:example.com"
    return httpx.Response(
        200,
        json={
            "results": [
                {
                    "page": {"url": "https://example.com/api/users?id=1", "status": "200"},
                    "task": {"time": "2025-02-03T10:00:00Z"},
                },
                {
                    "page": {"url": "https://example.com/dashboard", "status": "200"},
                    "task": {"time": "2024-06-01T10:00:00Z"},
                },
                {
                    "page": {"url": "https://evil.test/page", "status": "200"},
                    "task": {"time": "2024-06-01T10:00:00Z"},
                },
            ]
        },
    )


@pytest.mark.asyncio
async def test_discover_historical_urls_merges_sources_and_filters_scope():
    report = await discover_historical_urls(
        "example.com", transport=httpx.MockTransport(_history_handler), timeout=3
    )
    assert report.error is None
    assert [item["url"] for item in report.urls] == [
        "https://example.com/api/users?id=1",
        "https://example.com/dashboard",
        "http://www.example.com/login",
        "https://example.com/app.js",
    ]
    kinds = {item["url"]: item["kind"] for item in report.urls}
    assert kinds["https://example.com/api/users?id=1"] == "api"
    assert kinds["http://www.example.com/login"] == "page"
    assert kinds["https://example.com/app.js"] == "asset"
    assert report.urls[0]["last_seen"] == "2024-01-01"
    assert report.sources == {"wayback": "3 URL(s)", "urlscan": "2 URL(s)"}
    assert report.as_dict()["count"] == 4
    assert report.summary() == "4 archived URL(s) (urlscan+wayback), 1 API-like"


@pytest.mark.asyncio
async def test_discover_historical_urls_survives_one_failing_source():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "web.archive.org":
            return httpx.Response(504)
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "page": {"url": "https://example.com/dashboard", "status": "200"},
                        "task": {"time": "2024-06-01T10:00:00Z"},
                    }
                ]
            },
        )

    report = await discover_historical_urls(
        "example.com", transport=httpx.MockTransport(handler), timeout=3
    )
    assert [item["url"] for item in report.urls] == ["https://example.com/dashboard"]
    assert report.error == "wayback: HTTP 504"
    assert "partial" in report.summary()


@pytest.mark.asyncio
async def test_discover_historical_urls_reports_http_error():
    transport = httpx.MockTransport(lambda request: httpx.Response(429))
    report = await discover_historical_urls("example.com", transport=transport, timeout=3)
    assert report.urls == []
    assert report.error == "HTTP 429"


_RDAP_DOCUMENT = {
    "ldhName": "EXAMPLE.COM",
    "status": ["client transfer prohibited", "active"],
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2026-08-14T07:01:34Z"},
    ],
    "entities": [
        {
            "roles": ["registrar"],
            "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar, Inc."]]],
        }
    ],
    "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}, {"ldhName": "B.IANA-SERVERS.NET"}],
}


def _rdap_handler(request: httpx.Request) -> httpx.Response:
    if request.url.host == "data.iana.org":
        return httpx.Response(
            200,
            json={"services": [[["com", "net"], ["https://rdap.registry.example/v1/"]]]},
        )
    assert request.url.host == "rdap.registry.example"
    assert request.url.path == "/v1/domain/example.com"
    return httpx.Response(200, json=_RDAP_DOCUMENT)


@pytest.mark.asyncio
async def test_lookup_whois_parses_rdap_registration():
    report = await lookup_whois(
        "example.com", transport=httpx.MockTransport(_rdap_handler), timeout=3
    )
    assert report.error is None
    assert report.registrar == "Example Registrar, Inc."
    assert report.created == "1995-08-14T04:00:00Z"
    assert report.expires == "2027-08-13T04:00:00Z"
    assert report.nameservers == ["a.iana-servers.net", "b.iana-servers.net"]
    assert report.statuses == ["client transfer prohibited", "active"]
    assert "Example Registrar" in report.summary()


async def _offline_whois(server: str, query: str, timeout: float) -> str:  # noqa: ASYNC109
    raise OSError("port 43 blocked")


@pytest.mark.asyncio
async def test_lookup_whois_errors_when_suffix_is_not_in_bootstrap():
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, json={"services": [[["com"], ["https://rdap.example/"]]]})
    )
    report = await lookup_whois(
        "example.co.uk", transport=transport, timeout=3, whois_query=_offline_whois
    )
    assert report.error == "no RDAP service for this suffix"
    assert report.registrar is None


_WHOIS_IANA_TEXT = "domain: COM\norganisation: IANA\nwhois: whois.verisign-grs.com\n"
_WHOIS_REGISTRY_TEXT = """Domain Name: EXAMPLE.COM
Registrar WHOIS Server: whois.registrar.example
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2027-08-13T04:00:00Z
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
>>> Last update of whois database: 2026-11-15T00:00:00Z <<<
"""
_WHOIS_REGISTRAR_TEXT = "Registrar: Example Registrar, Inc.\n"


@pytest.mark.asyncio
async def test_lookup_whois_falls_back_to_port43():
    async def query(server: str, name: str, timeout: float) -> str:  # noqa: ASYNC109
        if server == "whois.iana.org":
            return _WHOIS_IANA_TEXT
        if server == "whois.verisign-grs.com":
            return _WHOIS_REGISTRY_TEXT
        if server == "whois.registrar.example":
            return _WHOIS_REGISTRAR_TEXT
        raise OSError(f"unexpected server {server}")

    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"services": []}))
    report = await lookup_whois(
        "example.com", transport=transport, timeout=3, whois_query=query
    )

    assert report.error is None
    assert report.source == "WHOIS"
    assert report.registrar == "Example Registrar, Inc."
    assert report.created and report.created.startswith("1995-08-14")
    assert report.expires and report.expires.startswith("2027-08-13")
    assert report.statuses == ["clientTransferProhibited"]
    assert report.nameservers == ["a.iana-servers.net", "b.iana-servers.net"]
    assert "Example Registrar" in report.summary()


def test_parse_whois_text_keeps_first_value_and_skips_noise():
    text = (
        "% comment line\n"
        "registrar: First Registrar\n"
        "Registrar: Second Registrar\n"
        "Domain Status: active https://icann.org/epp#active\n"
        "Domain Status: active\n"
        "name server: NS1.EXAMPLE.COM.\n"
        "Registrar WHOIS Server: whois.registrar.example\n"
    )
    report = _parse_whois_text("example.com", text)

    assert report.registrar == "First Registrar"
    assert report.statuses == ["active"]
    assert report.nameservers == ["ns1.example.com"]
