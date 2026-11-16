from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx

OSINT_UA = "VENOMSCAN-osint/0.1 (authorized security assessment)"
CRTSH_URL = (
    "https://crt.sh/?q=%25.{domain}&output=json&exclude=expired&deduplicate=Y"
)
CERTSPOTTER_URL = (
    "https://api.certspotter.com/v1/issuances"
    "?domain={domain}&include_subdomains=true&expand=dns_names"
)
WAYBACK_CDX_URL = (
    "https://web.archive.org/cdx/search/cdx"
    "?url={domain}/*&output=json&fl=original,timestamp,statuscode,mimetype"
    "&collapse=urlkey&filter=statuscode:200&limit=500"
)
URLSCAN_SEARCH_URL = "https://urlscan.io/api/v1/search/?q=domain:{domain}&size=200"
OTX_PASSIVE_DNS_URL = (
    "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
)
HOSTSEARCH_URL = "https://api.hackertarget.com/hostsearch/?q={domain}"
IANA_RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
IANA_WHOIS = "whois.iana.org"
WHOIS_PORT = 43
MAX_BODY_BYTES = 2_000_000
MAX_WHOIS_BYTES = 262_144
MAX_SUBDOMAINS = 50
MAX_NAMESERVERS = 8
MAX_STATUSES = 6
MAX_HISTORY_URLS = 120

_HISTORY_ASSET_EXTENSIONS = frozenset(
    {
        ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
        ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map", ".mp4", ".pdf", ".zip",
    }
)

_HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")

_RESERVED_SUFFIXES = frozenset(
    {"local", "localhost", "test", "example", "invalid", "internal", "lan", "home", "arpa"}
)
_MULTI_PART_SUFFIXES = frozenset(
    {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "com.au",
        "net.au",
        "co.jp",
        "co.in",
        "com.br",
        "co.za",
        "com.sg",
        "co.nz",
        "co.kr",
        "com.mx",
        "com.tr",
    }
)


@dataclass
class SubdomainReport:
    domain: str
    names: list[str] = field(default_factory=list)
    wildcard: bool = False
    source: str = "crt.sh"
    sources: dict[str, str] = field(default_factory=dict)
    error: str | None = None

    def summary(self) -> str:
        if self.error and not self.names:
            return f"Subdomain lookup failed: {self.error}"
        if not self.names:
            return "No subdomains in certificate transparency"
        via = "+".join(sorted(self.sources)) or self.source
        text = f"{len(self.names)} subdomain(s) in certificate transparency ({via})"
        if self.error:
            text += f" · partial: {self.error}"
        return text

    def as_dict(self) -> dict:
        return {
            "domain": self.domain,
            "names": self.names,
            "count": len(self.names),
            "wildcard": self.wildcard,
            "source": self.source,
            "sources": self.sources,
            "error": self.error,
        }


@dataclass
class HistoricalReport:
    domain: str
    urls: list[dict] = field(default_factory=list)
    source: str = "wayback"
    sources: dict[str, str] = field(default_factory=dict)
    error: str | None = None

    def summary(self) -> str:
        if self.error and not self.urls:
            return f"Historical URL lookup failed: {self.error}"
        if not self.urls:
            return "No archived URLs found"
        apis = sum(1 for item in self.urls if item.get("kind") == "api")
        via = "+".join(sorted(self.sources)) or self.source
        text = f"{len(self.urls)} archived URL(s) ({via}), {apis} API-like"
        if self.error:
            text += f" · partial: {self.error}"
        return text

    def as_dict(self) -> dict:
        return {
            "domain": self.domain,
            "urls": self.urls,
            "count": len(self.urls),
            "source": self.source,
            "sources": self.sources,
            "error": self.error,
        }


@dataclass
class WhoisReport:
    domain: str
    registrar: str | None = None
    statuses: list[str] = field(default_factory=list)
    created: str | None = None
    updated: str | None = None
    expires: str | None = None
    nameservers: list[str] = field(default_factory=list)
    source: str = "RDAP"
    error: str | None = None

    def summary(self) -> str:
        if self.error:
            return f"WHOIS lookup failed: {self.error}"
        parts = [self.registrar or "registrar unknown"]
        if self.created:
            parts.append(f"created {self.created[:10]}")
        if self.expires:
            parts.append(f"expires {self.expires[:10]}")
        return " · ".join(parts)

    def as_dict(self) -> dict:
        return {
            "domain": self.domain,
            "registrar": self.registrar,
            "statuses": self.statuses,
            "created": self.created,
            "updated": self.updated,
            "expires": self.expires,
            "nameservers": self.nameservers,
            "source": self.source,
            "error": self.error,
        }


def _is_safe_https(url: str) -> bool:
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.username or parts.password:
        return False
    if parts.port not in (None, 443):
        return False
    return bool(parts.hostname) and not is_ip_address(parts.hostname)


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip())
    except ValueError:
        return False
    return True


def registrable_domain(host: str) -> str | None:
    """Return the registrable domain, or None for IP literals and reserved names."""

    candidate = host.strip().lower().rstrip(".")
    if not candidate or is_ip_address(candidate):
        return None
    labels = candidate.split(".")
    if len(labels) < 2:
        return None
    if any(not label or not all(ch.isalnum() or ch == "-" for ch in label) for label in labels):
        return None
    if labels[-1] in _RESERVED_SUFFIXES:
        return None
    suffix = ".".join(labels[-2:])
    if suffix in _MULTI_PART_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return suffix


async def _get_body(
    url: str,
    *,
    transport: httpx.AsyncBaseTransport | None,
    timeout: float,  # noqa: ASYNC109 - forwarded to httpx.Timeout, not asyncio
    accept: str = "application/json",
    extra_headers: dict[str, str] | None = None,
) -> tuple[str | None, str | None]:
    # crt.sh routinely needs >4 s just to accept the connection, so the connect
    # budget is generous; the read budget still respects the scan deadline.
    try:
        async with httpx.AsyncClient(
            transport=transport,
            timeout=httpx.Timeout(timeout, connect=min(timeout, 10.0)),
            follow_redirects=False,
            trust_env=False,
            headers={
                "User-Agent": OSINT_UA,
                "Accept": accept,
                **(extra_headers or {}),
            },
        ) as client:
            response = await client.get(url)
    except httpx.HTTPError as exc:
        return None, f"{type(exc).__name__}: {str(exc)[:160] or 'request failed'}"
    if response.status_code != 200:
        return None, f"HTTP {response.status_code}"
    if len(response.content) > MAX_BODY_BYTES:
        return None, "response too large"
    return response.text, None


async def _get_json(
    url: str,
    *,
    transport: httpx.AsyncBaseTransport | None,
    timeout: float,  # noqa: ASYNC109 - forwarded to httpx.Timeout, not asyncio
    extra_headers: dict[str, str] | None = None,
) -> tuple[object | None, str | None]:
    body, error = await _get_body(
        url,
        transport=transport,
        timeout=timeout,
        extra_headers=extra_headers,
    )
    if error is not None:
        return None, error
    try:
        return json.loads(body or ""), None
    except ValueError as exc:
        return None, f"invalid JSON: {str(exc)[:120]}"


def _ct_names(entries: object, domain: str) -> tuple[set[str], bool]:
    found: set[str] = set()
    wildcard = False
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        for key in ("name_value", "common_name"):
            value = entry.get(key)
            if not isinstance(value, str):
                continue
            for raw in value.splitlines():
                name = raw.strip().lower()
                if not name:
                    continue
                if name.startswith("*."):
                    wildcard = True
                    name = name[2:]
                name = name.rstrip(".")
                if name.endswith("." + domain):
                    found.add(name)
    return found, wildcard


def _certspotter_names(payload: object, domain: str) -> tuple[set[str], bool]:
    found: set[str] = set()
    wildcard = False
    for entry in payload if isinstance(payload, list) else []:
        if not isinstance(entry, dict):
            continue
        names = entry.get("dns_names")
        if not isinstance(names, list):
            continue
        for raw in names:
            if not isinstance(raw, str):
                continue
            name = raw.strip().lower()
            if name.startswith("*."):
                wildcard = True
                name = name[2:]
            name = name.rstrip(".")
            if name.endswith("." + domain):
                found.add(name)
    return found, wildcard


def _otx_names(payload: object, domain: str) -> tuple[set[str], bool]:
    """AlienVault OTX passive DNS: historical hostnames observed resolving under the domain."""
    found: set[str] = set()
    wildcard = False
    entries = payload.get("passive_dns") if isinstance(payload, dict) else None
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        hostname = entry.get("hostname")
        if not isinstance(hostname, str):
            continue
        name = hostname.strip().lower()
        if name.startswith("*."):
            wildcard = True
            name = name[2:]
        name = name.rstrip(".")
        if name.endswith("." + domain):
            found.add(name)
    return found, wildcard


def _hostsearch_names(payload: object, domain: str) -> tuple[set[str], bool]:
    """HackerTarget host search: CSV lines of `host,address` from passive DNS."""
    found: set[str] = set()
    wildcard = False
    for line in str(payload).splitlines():
        host = line.split(",", 1)[0].strip().lower().rstrip(".")
        if not host or " " in host or "." not in host:
            continue
        name = host[2:] if host.startswith("*.") else host
        wildcard = wildcard or host.startswith("*.")
        if name.endswith("." + domain):
            found.add(name)
    return found, wildcard


_SUBDOMAIN_PARSERS = {
    "crt.sh": _ct_names,
    "certspotter": _certspotter_names,
    "otx": _otx_names,
    "hostsearch": _hostsearch_names,
}


async def discover_subdomains(
    domain: str,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    timeout: float = 15.0,  # noqa: ASYNC109 - forwarded to httpx.Timeout
    include_certspotter: bool = True,
    include_otx: bool = True,
    include_hostsearch: bool = True,
    otx_api_key: str = "",
) -> SubdomainReport:
    """Passive subdomain discovery from CT, HackerTarget passive DNS and (keyed) OTX."""

    report = SubdomainReport(domain=domain)
    requests: list[tuple[str, str]] = [
        ("crt.sh", CRTSH_URL.format(domain=domain)),
    ]
    if include_certspotter:
        requests.append(("certspotter", CERTSPOTTER_URL.format(domain=domain)))
    # OTX rejects anonymous use with HTTP 429, so it is only queried with a key.
    if include_otx and otx_api_key:
        requests.append(("otx", OTX_PASSIVE_DNS_URL.format(domain=domain)))
    results = await asyncio.gather(
        *(
            _get_json(
                url,
                transport=transport,
                timeout=timeout,
                extra_headers={"X-OTX-API-KEY": otx_api_key} if name == "otx" else None,
            )
            for name, url in requests
        )
    )

    found: set[str] = set()
    wildcard = False
    errors: dict[str, str] = {}
    for (name, _), (payload, error) in zip(requests, results, strict=True):
        if error is not None:
            errors[name] = error
            continue
        names, wild = _SUBDOMAIN_PARSERS[name](payload, domain)
        found |= names
        wildcard = wildcard or wild
        report.sources[name] = f"{len(names)} name(s)"

    if include_hostsearch:
        text, error = await _get_body(
            HOSTSEARCH_URL.format(domain=domain),
            transport=transport,
            timeout=timeout,
            accept="text/plain",
        )
        if error is not None:
            errors["hostsearch"] = error
        else:
            names, wild = _hostsearch_names(text, domain)
            found |= names
            wildcard = wildcard or wild
            report.sources["hostsearch"] = f"{len(names)} name(s)"

    source_count = len(requests) + (1 if include_hostsearch else 0)
    if len(errors) == source_count:
        report.error = errors.get("crt.sh") or next(iter(errors.values()))
        return report
    if errors:
        report.error = "; ".join(f"{name}: {err}" for name, err in errors.items())

    found.discard(domain)
    report.names = sorted(found)[:MAX_SUBDOMAINS]
    report.wildcard = wildcard
    report.source = "+".join(name for name, _ in requests if name in report.sources)
    if "hostsearch" in report.sources:
        report.source = "+".join(filter(None, [report.source, "hostsearch"]))
    return report


def _history_url(original: str, domain: str) -> str | None:
    parts = urlsplit(original.strip())
    if parts.scheme not in ("http", "https") or parts.username or parts.password:
        return None
    host = (parts.hostname or "").lower()
    if not host or not (host == domain or host.endswith("." + domain)):
        return None
    if parts.port not in (None, 80, 443):
        return None
    path = parts.path or "/"
    query = f"?{parts.query}" if parts.query else ""
    return f"{parts.scheme}://{host}{path}{query}"


def _history_kind(url: str, mimetype: str) -> str:
    lower = url.lower()
    path = urlsplit(lower).path
    suffix = path[path.rfind(".") :] if "." in path.rsplit("/", 1)[-1] else ""
    if suffix in _HISTORY_ASSET_EXTENSIONS:
        return "asset"
    if "/api" in path or path.endswith((".json", ".graphql")) or "json" in mimetype:
        return "api"
    return "page"


def _history_timestamp(value: object) -> str | None:
    text = str(value or "")
    if len(text) >= 8 and text[:8].isdigit():
        return f"{text[:4]}-{text[4:6]}-{text[6:8]}"
    return text or None


def _history_recency(value: object) -> int:
    digits = str(value or "").replace("-", "")[:8]
    return int(digits) if digits.isdigit() else 0


def _history_entry(
    url: str, domain: str, *, last_seen: str | None, status: str | None, mimetype: str = ""
) -> dict | None:
    scoped = _history_url(url, domain)
    if scoped is None:
        return None
    return {
        "url": scoped,
        "last_seen": last_seen,
        "status": status,
        "kind": _history_kind(scoped, mimetype),
    }


def _wayback_entries(payload: object, domain: str) -> list[dict]:
    entries: list[dict] = []
    for row in payload if isinstance(payload, list) else []:
        if not isinstance(row, list) or len(row) < 2:
            continue
        entry = _history_entry(
            str(row[0]),
            domain,
            last_seen=_history_timestamp(row[1]),
            status=str(row[2]) if len(row) > 2 else None,
            mimetype=str(row[3]) if len(row) > 3 else "",
        )
        if entry is not None:
            entries.append(entry)
    return entries


def _urlscan_entries(payload: object, domain: str) -> list[dict]:
    entries: list[dict] = []
    results = payload.get("results") if isinstance(payload, dict) else None
    for result in results if isinstance(results, list) else []:
        if not isinstance(result, dict):
            continue
        page = result.get("page")
        task = result.get("task")
        if not isinstance(page, dict) or not isinstance(page.get("url"), str):
            continue
        time_value = task.get("time") if isinstance(task, dict) else None
        entry = _history_entry(
            page["url"],
            domain,
            last_seen=str(time_value)[:10] if time_value else None,
            status=str(page.get("status")) if page.get("status") else None,
            mimetype=str(page.get("mimeType") or ""),
        )
        if entry is not None:
            entries.append(entry)
    return entries


async def discover_historical_urls(
    domain: str,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    timeout: float = 12.0,  # noqa: ASYNC109 - forwarded to httpx.Timeout
) -> HistoricalReport:
    """List archived/first-seen URLs from Wayback CDX and urlscan.io without fetching them."""

    report = HistoricalReport(domain=domain)
    requests = [
        ("wayback", WAYBACK_CDX_URL.format(domain=domain)),
        ("urlscan", URLSCAN_SEARCH_URL.format(domain=domain)),
    ]
    results = await asyncio.gather(
        *(_get_json(url, transport=transport, timeout=timeout) for _, url in requests)
    )
    errors: dict[str, str] = {}
    collected: dict[str, dict] = {}
    for (name, _), (payload, error) in zip(requests, results, strict=True):
        if error is not None:
            errors[name] = error
            continue
        parser = _wayback_entries if name == "wayback" else _urlscan_entries
        entries = parser(payload, domain)
        report.sources[name] = f"{len(entries)} URL(s)"
        for entry in entries:
            collected.setdefault(entry["url"], entry)

    if len(errors) == len(requests):
        report.error = errors.get("wayback") or next(iter(errors.values()))
        return report
    if errors:
        report.error = "; ".join(f"{name}: {err}" for name, err in errors.items())

    report.urls = sorted(
        collected.values(),
        key=lambda item: (
            {"api": 0, "page": 1, "asset": 2}.get(str(item.get("kind")), 3),
            -_history_recency(item.get("last_seen")),
        ),
    )[:MAX_HISTORY_URLS]
    report.source = "+".join(name for name, _ in requests if name in report.sources)
    return report


def _pick_rdap_base(domain: str, bootstrap: object) -> str | None:
    if not isinstance(bootstrap, dict):
        return None
    services = bootstrap.get("services")
    if not isinstance(services, list):
        return None
    best_tld = ""
    best_url: str | None = None
    for service in services:
        if not isinstance(service, list) or len(service) != 2:
            continue
        tlds, urls = service
        if not isinstance(tlds, list) or not isinstance(urls, list):
            continue
        for tld in tlds:
            if not isinstance(tld, str):
                continue
            lowered = tld.lower()
            if domain == lowered or domain.endswith("." + lowered):
                if len(lowered) <= len(best_tld):
                    continue
                for url in urls:
                    if isinstance(url, str) and _is_safe_https(url):
                        best_tld = lowered
                        best_url = url
                        break
    return best_url


def _parse_rdap(domain: str, payload: object) -> WhoisReport:
    report = WhoisReport(domain=domain)
    if not isinstance(payload, dict):
        report.error = "unexpected RDAP payload"
        return report

    events = payload.get("events")
    if isinstance(events, list):
        dates: dict[str, str] = {}
        for event in events:
            if not isinstance(event, dict):
                continue
            action = str(event.get("eventAction") or "").lower()
            date = event.get("eventDate")
            if action and isinstance(date, str):
                dates[action] = date
        report.created = dates.get("registration")
        report.expires = dates.get("expiration")
        report.updated = dates.get("last changed") or dates.get("last update of rdap database")

    statuses = payload.get("status")
    if isinstance(statuses, list):
        report.statuses = [str(item) for item in statuses if isinstance(item, str)][:MAX_STATUSES]

    entities = payload.get("entities")
    if isinstance(entities, list):
        for entity in entities:
            if not isinstance(entity, dict):
                continue
            roles = entity.get("roles")
            if not isinstance(roles, list) or "registrar" not in roles:
                continue
            vcard = entity.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
                for item in vcard[1]:
                    if (
                        isinstance(item, list)
                        and len(item) >= 4
                        and item[0] == "fn"
                        and isinstance(item[3], str)
                    ):
                        report.registrar = item[3]
                        break
            if report.registrar:
                break

    nameservers = payload.get("nameservers")
    if isinstance(nameservers, list):
        for server in nameservers:
            if isinstance(server, dict) and isinstance(server.get("ldhName"), str):
                report.nameservers.append(server["ldhName"].rstrip(".").lower())
        report.nameservers = report.nameservers[:MAX_NAMESERVERS]
    return report


_REFERRAL_KEYS = frozenset({"whois", "referralserver", "registrarwhoisserver", "whoisserver"})
_REGISTRAR_KEYS = frozenset({"registrar", "sponsoring registrar"})
_CREATED_KEYS = frozenset(
    {
        "creation date",
        "created",
        "created on",
        "registered",
        "registered on",
        "registration date",
        "registration time",
        "domain registration date",
    }
)
_UPDATED_KEYS = frozenset(
    {"updated date", "update date", "last updated on", "last modified", "last-modified", "changed"}
)
_EXPIRES_KEYS = frozenset(
    {
        "registry expiry date",
        "expiration date",
        "expiration time",
        "expiry date",
        "expiry",
        "paid-till",
        "registrar registration expiration date",
    }
)
_STATUS_KEYS = frozenset({"domain status", "status", "state"})
_NAMESERVER_KEYS = frozenset({"name server", "name servers", "nserver", "nameserver"})
_SKIP_KEYS = frozenset(
    {
        "registrar whois server",
        "registrar url",
        "registrar abuse contact email",
        "registrar abuse contact phone",
        "whois server",
        "referralserver",
    }
)

WhoisQuery = Callable[[str, str, float], Awaitable[str]]


def _has_registration(report: WhoisReport) -> bool:
    return bool(
        report.registrar
        or report.created
        or report.expires
        or report.statuses
        or report.nameservers
    )


def _whois_server(value: str) -> str | None:
    candidate = value.strip()
    if "://" in candidate:
        candidate = candidate.split("://", 1)[1]
    candidate = candidate.split("/", 1)[0].strip().lower()
    if not candidate:
        return None
    host = candidate.split()[0].strip(".")
    if len(host) > 253 or not _HOSTNAME_RE.match(host) or "." not in host:
        return None
    if is_ip_address(host):
        return None
    return host


def _whois_referrals(text: str) -> list[str]:
    servers: list[str] = []
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            continue
        if key.strip().lower().replace(" ", "") not in _REFERRAL_KEYS:
            continue
        server = _whois_server(value)
        if server and server not in servers:
            servers.append(server)
    return servers


def _parse_whois_text(domain: str, text: str) -> WhoisReport:
    report = WhoisReport(domain=domain, source="WHOIS")
    statuses: list[str] = []
    nameservers: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("%", "#", ">>>")):
            continue
        key, sep, value = stripped.partition(":")
        if not sep:
            continue
        key = " ".join(key.strip().lower().split())
        value = value.strip()
        if not key or not value or key in _SKIP_KEYS:
            continue
        if key in _REGISTRAR_KEYS and report.registrar is None:
            report.registrar = value
        elif key in _CREATED_KEYS and report.created is None:
            report.created = value
        elif key in _UPDATED_KEYS and report.updated is None:
            report.updated = value
        elif key in _EXPIRES_KEYS and report.expires is None:
            report.expires = value
        elif key in _STATUS_KEYS:
            status = value.split()[0].strip(",")
            if status and status not in statuses:
                statuses.append(status)
        elif key in _NAMESERVER_KEYS:
            server = value.split()[0].rstrip(".").lower()
            if server and server not in nameservers:
                nameservers.append(server)
    report.statuses = statuses[:MAX_STATUSES]
    report.nameservers = nameservers[:MAX_NAMESERVERS]
    if not _has_registration(report):
        report.error = "empty WHOIS response"
    return report


async def _whois_socket_query(
    server: str,
    query: str,
    timeout: float,  # noqa: ASYNC109 - forwarded to asyncio.wait_for
) -> str:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(server, WHOIS_PORT), timeout=timeout
    )
    try:
        writer.write((query + "\r\n").encode("ascii", "ignore"))
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        buffer = bytearray()
        while len(buffer) < MAX_WHOIS_BYTES:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            if not chunk:
                break
            buffer.extend(chunk)
        return buffer.decode("utf-8", "replace")
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
        except (TimeoutError, OSError):
            pass


async def _whois_port43(
    domain: str,
    *,
    timeout: float,  # noqa: ASYNC109 - forwarded to the bounded socket query
    query_fn: WhoisQuery | None = None,
) -> WhoisReport:
    """Bounded port-43 WHOIS fallback used only when RDAP has no usable data."""

    report = WhoisReport(domain=domain, source="WHOIS")
    ask = query_fn or _whois_socket_query
    deadline = time.monotonic() + max(timeout, 1.0)

    def remaining(cap: float) -> float:
        return max(0.5, min(cap, deadline - time.monotonic()))

    tld = domain.rsplit(".", 1)[-1]
    try:
        iana_text = await ask(IANA_WHOIS, tld, remaining(3.0))
    except (TimeoutError, OSError, ValueError):
        report.error = "WHOIS service unreachable"
        return report
    servers = _whois_referrals(iana_text)
    if not servers:
        report.error = f"no WHOIS service for .{tld}"
        return report
    try:
        text = await ask(servers[0], domain, remaining(timeout))
    except (TimeoutError, OSError, ValueError):
        report.error = "WHOIS query failed"
        return report

    report = _parse_whois_text(domain, text)
    registrar_servers = [server for server in _whois_referrals(text) if server != servers[0]]
    if report.registrar is None and registrar_servers:
        try:
            extra = await ask(registrar_servers[0], domain, remaining(timeout))
        except (TimeoutError, OSError, ValueError):
            extra = ""
        detail = _parse_whois_text(domain, extra)
        report.registrar = detail.registrar
        report.created = report.created or detail.created
        report.updated = report.updated or detail.updated
        report.expires = report.expires or detail.expires
        report.statuses = report.statuses or detail.statuses
        report.nameservers = report.nameservers or detail.nameservers

    report.error = None if _has_registration(report) else "empty WHOIS response"
    return report


async def lookup_whois(
    domain: str,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    timeout: float = 8.0,  # noqa: ASYNC109 - forwarded to httpx.Timeout
    whois_query: WhoisQuery | None = None,
) -> WhoisReport:
    """Registration metadata via IANA RDAP, falling back to bounded port-43 WHOIS."""

    report = WhoisReport(domain=domain)
    bootstrap, error = await _get_json(
        IANA_RDAP_BOOTSTRAP, transport=transport, timeout=min(timeout, 6.0)
    )
    if error is not None:
        report.error = f"bootstrap: {error}"
    else:
        base = _pick_rdap_base(domain, bootstrap)
        if base is None:
            report.error = "no RDAP service for this suffix"
        else:
            payload, error = await _get_json(
                f"{base.rstrip('/')}/domain/{domain}", transport=transport, timeout=timeout
            )
            if error is not None:
                report.error = error
            else:
                parsed = _parse_rdap(domain, payload)
                if parsed.error is None and _has_registration(parsed):
                    return parsed
                report = parsed
                report.error = report.error or "empty RDAP response"

    fallback = await _whois_port43(
        domain, timeout=min(timeout, 6.0), query_fn=whois_query
    )
    if fallback.error is None and _has_registration(fallback):
        return fallback
    if not report.error:
        report.error = fallback.error or "no registration data"
    return report


__all__ = [
    "HistoricalReport",
    "SubdomainReport",
    "WhoisReport",
    "discover_historical_urls",
    "discover_subdomains",
    "is_ip_address",
    "lookup_whois",
    "registrable_domain",
]
