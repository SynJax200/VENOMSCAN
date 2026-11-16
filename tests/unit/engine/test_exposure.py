from __future__ import annotations

import httpx
import pytest
from venomscan_engine.recon.exposure import lookup_exposure


def _internetdb_handler(request: httpx.Request) -> httpx.Response:
    assert request.url.host == "internetdb.shodan.io"
    assert request.url.path == "/93.184.216.34"
    return httpx.Response(
        200,
        json={
            "ports": [443, 80],
            "hostnames": ["example.com"],
            "tags": ["cloud"],
            "vulns": ["CVE-2021-1234", "CVE-2022-5678"],
        },
    )


@pytest.mark.asyncio
async def test_lookup_exposure_uses_keyless_internetdb():
    report = await lookup_exposure(
        "93.184.216.34",
        transport=httpx.MockTransport(_internetdb_handler),
        timeout=2,
    )
    assert report is not None
    assert report.source == "Shodan InternetDB"
    assert report.ports == [80, 443]
    assert report.hostnames == ["example.com"]
    assert report.vulns == ["CVE-2021-1234", "CVE-2022-5678"]
    assert report.error is None


@pytest.mark.asyncio
async def test_lookup_exposure_internetdb_empty_host_is_not_an_error():
    transport = httpx.MockTransport(lambda request: httpx.Response(404))
    report = await lookup_exposure("93.184.216.34", transport=transport, timeout=2)
    assert report is not None
    assert report.ports == []
    assert report.error is None


def _shodan_handler(request: httpx.Request) -> httpx.Response:
    assert request.url.host == "api.shodan.io"
    assert request.url.path == "/shodan/host/93.184.216.34"
    assert request.url.params["key"] == "test-key"
    return httpx.Response(
        200,
        json={
            "ports": [443, 80, 443],
            "hostnames": ["example.com", "www.example.com"],
            "org": "Example Org",
            "isp": "Example ISP",
            "os": "Linux",
            "country_code": "US",
            "tags": ["cloud"],
            "vulns": {"CVE-2021-1234": {"cvss": 7.5}, "CVE-2022-5678": {}},
        },
    )


@pytest.mark.asyncio
async def test_lookup_exposure_parses_shodan_host():
    report = await lookup_exposure(
        "93.184.216.34",
        shodan_key="test-key",
        transport=httpx.MockTransport(_shodan_handler),
        timeout=2,
    )
    assert report is not None
    assert report.source == "Shodan"
    assert report.ports == [80, 443]
    assert report.hostnames == ["example.com", "www.example.com"]
    assert report.organisation == "Example Org"
    assert report.operating_system == "Linux"
    assert report.vulns == ["CVE-2021-1234", "CVE-2022-5678"]
    assert "2 known CVE(s)" in report.summary()


@pytest.mark.asyncio
async def test_lookup_exposure_reports_rejected_credentials():
    transport = httpx.MockTransport(lambda request: httpx.Response(401))
    report = await lookup_exposure(
        "93.184.216.34", shodan_key="wrong", transport=transport, timeout=2
    )
    assert report is not None
    assert report.error == "credentials rejected"


@pytest.mark.asyncio
async def test_lookup_exposure_parses_censys_host():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "search.censys.io"
        assert request.headers["Authorization"].startswith("Basic ")
        return httpx.Response(
            200,
            json={
                "result": {
                    "services": [{"port": 443}, {"port": 22}],
                    "names": ["example.com"],
                    "autonomous_system": {"name": "EXAMPLE-AS"},
                    "operating_system": "Linux",
                    "location": {"country": "US"},
                }
            },
        )

    report = await lookup_exposure(
        "93.184.216.34",
        censys_id="id",
        censys_secret="secret",
        transport=httpx.MockTransport(handler),
        timeout=2,
    )
    assert report is not None
    assert report.source == "Censys"
    assert report.ports == [22, 443]
    assert report.organisation == "EXAMPLE-AS"
    assert report.country == "US"
