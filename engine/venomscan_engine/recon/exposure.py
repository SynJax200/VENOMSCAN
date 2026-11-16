from __future__ import annotations

from dataclasses import dataclass, field

import httpx

SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{address}"
SHODAN_INTERNETDB_URL = "https://internetdb.shodan.io/{address}"
CENSYS_HOST_URL = "https://search.censys.io/api/v2/hosts/{address}"
MAX_PORTS = 20
MAX_HOSTNAMES = 10
MAX_VULNS = 25


@dataclass
class ExposureReport:
    address: str
    source: str
    ports: list[int] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    organisation: str | None = None
    isp: str | None = None
    operating_system: str | None = None
    country: str | None = None
    tags: list[str] = field(default_factory=list)
    vulns: list[str] = field(default_factory=list)
    error: str | None = None

    def summary(self) -> str:
        if self.error:
            return f"{self.source} lookup failed: {self.error}"
        parts = [f"{self.source}"]
        if self.ports:
            parts.append(f"{len(self.ports)} open port(s)")
        if self.vulns:
            parts.append(f"{len(self.vulns)} known CVE(s)")
        if self.organisation:
            parts.append(str(self.organisation))
        return " · ".join(parts)

    def as_dict(self) -> dict:
        return {
            "address": self.address,
            "source": self.source,
            "ports": self.ports,
            "hostnames": self.hostnames,
            "organisation": self.organisation,
            "isp": self.isp,
            "operating_system": self.operating_system,
            "country": self.country,
            "tags": self.tags,
            "vulns": self.vulns,
            "error": self.error,
        }


_SOURCE_LABELS = {
    "shodan": "Shodan",
    "censys": "Censys",
    "internetdb": "Shodan InternetDB",
}


def _source_label(source: str) -> str:
    return _SOURCE_LABELS.get(source, source.title())


def _strings(value: object, limit: int) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, (str, int))][:limit]


def _parse_shodan(address: str, payload: object) -> ExposureReport:
    report = ExposureReport(address=address, source="Shodan")
    if not isinstance(payload, dict):
        report.error = "unexpected Shodan payload"
        return report
    report.ports = sorted(
        {int(port) for port in payload.get("ports") or [] if isinstance(port, int)}
    )[:MAX_PORTS]
    report.hostnames = _strings(payload.get("hostnames"), MAX_HOSTNAMES)
    report.organisation = payload.get("org") if isinstance(payload.get("org"), str) else None
    report.isp = payload.get("isp") if isinstance(payload.get("isp"), str) else None
    operating_system = payload.get("os")
    report.operating_system = operating_system if isinstance(operating_system, str) else None
    report.country = payload.get("country_code") if isinstance(payload.get("country_code"), str) else None
    report.tags = _strings(payload.get("tags"), 10)
    vulns = payload.get("vulns")
    if isinstance(vulns, dict):
        report.vulns = [str(cve) for cve in vulns][:MAX_VULNS]
    return report


def _parse_internetdb(address: str, payload: object) -> ExposureReport:
    """Shodan InternetDB: keyless ports/hostnames/tags/vulns for a single address."""
    report = ExposureReport(address=address, source="Shodan InternetDB")
    if not isinstance(payload, dict):
        report.error = "unexpected InternetDB payload"
        return report
    report.ports = sorted(
        {int(port) for port in payload.get("ports") or [] if isinstance(port, int)}
    )[:MAX_PORTS]
    report.hostnames = _strings(payload.get("hostnames"), MAX_HOSTNAMES)
    report.tags = _strings(payload.get("tags"), 10)
    report.vulns = _strings(payload.get("vulns"), MAX_VULNS)
    return report


def _parse_censys(address: str, payload: object) -> ExposureReport:
    report = ExposureReport(address=address, source="Censys")
    if not isinstance(payload, dict):
        report.error = "unexpected Censys payload"
        return report
    result = payload.get("result")
    if not isinstance(result, dict):
        report.error = str(payload.get("error") or "empty Censys result")[:160]
        return report
    services = result.get("services")
    if isinstance(services, list):
        ports = {
            int(service["port"])
            for service in services
            if isinstance(service, dict) and isinstance(service.get("port"), int)
        }
        report.ports = sorted(ports)[:MAX_PORTS]
    report.hostnames = _strings(result.get("names"), MAX_HOSTNAMES)
    system = result.get("autonomous_system")
    if isinstance(system, dict) and isinstance(system.get("name"), str):
        report.organisation = system["name"]
    operating_system = result.get("operating_system")
    if isinstance(operating_system, str):
        report.operating_system = operating_system
    location = result.get("location")
    if isinstance(location, dict) and isinstance(location.get("country"), str):
        report.country = location["country"]
    return report


async def lookup_exposure(
    address: str,
    *,
    shodan_key: str = "",
    censys_id: str = "",
    censys_secret: str = "",
    transport: httpx.AsyncBaseTransport | None = None,
    timeout: float = 8.0,  # noqa: ASYNC109 - forwarded to httpx.Timeout
) -> ExposureReport | None:
    """Read-only internet-exposure lookup; falls back to keyless Shodan InternetDB."""

    source = ""
    url = ""
    headers: dict[str, str] = {}
    auth: tuple[str, str] | None = None
    params: dict[str, str] = {}
    if shodan_key:
        source = "shodan"
        url = SHODAN_HOST_URL.format(address=address)
        params = {"key": shodan_key, "minify": "false"}
    elif censys_id and censys_secret:
        source = "censys"
        url = CENSYS_HOST_URL.format(address=address)
        auth = (censys_id, censys_secret)
        headers = {"Accept": "application/json"}
    else:
        source = "internetdb"
        url = SHODAN_INTERNETDB_URL.format(address=address)

    try:
        async with httpx.AsyncClient(
            transport=transport,
            timeout=httpx.Timeout(timeout, connect=min(timeout, 4.0)),
            follow_redirects=False,
            trust_env=False,
            headers={"User-Agent": "VENOMSCAN-osint/0.1 (authorized security assessment)", **headers},
            auth=auth,
        ) as client:
            response = await client.get(url, params=params)
    except httpx.HTTPError as exc:
        # Never surface str(exc): provider URLs carry API credentials.
        report = ExposureReport(address=address, source=_source_label(source))
        report.error = type(exc).__name__
        return report

    if response.status_code == 401:
        report = ExposureReport(address=address, source=_source_label(source))
        report.error = "credentials rejected"
        return report
    if response.status_code == 404:
        return ExposureReport(address=address, source=_source_label(source))
    if response.status_code != 200:
        report = ExposureReport(address=address, source=_source_label(source))
        report.error = f"HTTP {response.status_code}"
        return report
    try:
        payload = response.json()
    except ValueError:
        report = ExposureReport(address=address, source=_source_label(source))
        report.error = "invalid JSON"
        return report
    if source == "shodan":
        return _parse_shodan(address, payload)
    if source == "internetdb":
        return _parse_internetdb(address, payload)
    return _parse_censys(address, payload)


__all__ = ["ExposureReport", "lookup_exposure"]
