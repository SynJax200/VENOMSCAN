from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

RECORD_TYPES = ("A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA")
MAX_VALUES = 10
MAX_PTR = 3
# Service prefixes are probed explicitly because SRV records never live on the apex.
SRV_SERVICES = (
    "_sip._tcp",
    "_sip._udp",
    "_xmpp-client._tcp",
    "_xmpp-server._tcp",
    "_autodiscover._tcp",
    "_submission._tcp",
)
# DKIM selectors cannot be enumerated from DNS, so common provider defaults are probed.
DKIM_SELECTORS = (
    "default",
    "google",
    "selector1",
    "selector2",
    "s1",
    "s2",
    "k1",
    "k2",
    "mail",
    "dkim",
    "mandrill",
    "amazonses",
    "sendgrid",
    "mailchimp",
    "zoho",
    "smtp",
    "sig1",
    "mx",
    "s3",
    "hubspot",
)
MAX_DKIM = 4


@dataclass
class DNSReport:
    host: str
    records: dict[str, list[str]] = field(default_factory=dict)
    mail: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def summary(self) -> str:
        if not self.records:
            return "No DNS records returned"
        labels = ", ".join(f"{rtype}×{len(values)}" for rtype, values in self.records.items())
        return labels


def _normalize(text: str) -> str:
    return " ".join(text.split())


def _tag_values(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        key, sep, value = part.partition("=")
        key = key.strip().lower()
        if sep and key and key not in tags:
            tags[key] = value.strip()
    return tags


def _uri_list(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()][:4]


def parse_dmarc_policy(record: str) -> dict[str, Any]:
    """Split a DMARC TXT record into the tags a reviewer or LLM can reason about."""

    tags = _tag_values(record)
    return {
        "raw": _normalize(record),
        "policy": tags.get("p"),
        "subdomain_policy": tags.get("sp"),
        "percentage": tags.get("pct"),
        "dkim_alignment": tags.get("adkim") or "r",
        "spf_alignment": tags.get("aspf") or "r",
        "report_uris": _uri_list(tags.get("rua")),
        "forensic_uris": _uri_list(tags.get("ruf")),
    }


def _dkim_entry(selector: str, record: str) -> dict[str, Any]:
    tags = _tag_values(record)
    key = tags.get("p", "")
    return {
        "selector": selector,
        "key_type": tags.get("k") or "rsa",
        "flags": tags.get("t") or "",
        "service": tags.get("s") or "",
        "key_length": len(key),
        "revoked": not bool(key),
        "record": _normalize(record),
    }


def _dkim_label(entry: dict[str, Any]) -> str:
    label = f"{entry['selector']} → {entry['key_type']}"
    if entry["revoked"]:
        return f"{label} (revoked: empty p= tag)"
    if entry["flags"]:
        label += f" [{entry['flags']}]"
    return f"{label}, key {entry['key_length']} chars"


def _resolver_query(resolver: Any, host: str, rtype: str, timeout: float) -> list[str]:
    answers = resolver.resolve(host, rtype, lifetime=timeout)
    values: list[str] = []
    for answer in answers:
        if rtype == "TXT":
            chunks = getattr(answer, "strings", None)
            if chunks:
                values.append("".join(chunk.decode("utf-8", "replace") for chunk in chunks))
            else:
                values.append(str(answer).strip('"'))
        else:
            values.append(_normalize(answer.to_text()))
    return values[:MAX_VALUES]


def _optional_query(
    resolver: Any, host: str, rtype: str, timeout: float
) -> list[str] | None:
    """Return [] for a clean no-answer; None when the lookup itself failed."""
    import dns.exception
    import dns.resolver

    try:
        return _resolver_query(resolver, host, rtype, timeout)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout:
        return None
    except (dns.exception.DNSException, ValueError, OSError):
        return None


def _collect_mail_policy(
    resolver: Any, host: str, report: DNSReport, timeout: float
) -> None:
    from venomscan_engine.recon.osint import registrable_domain

    domain = registrable_domain(host)
    apex = domain or host
    txt_sets = [report.records.get("TXT", [])]
    if apex != host:
        # SPF lives on the apex, so a www-only lookup would miss it.
        answers = _optional_query(resolver, apex, "TXT", timeout)
        if answers is None:
            report.error = report.error or "Apex TXT lookup failed"
        else:
            txt_sets.append(answers)
    spf = next(
        (
            value
            for values in txt_sets
            for value in values
            if value.lower().startswith("v=spf1")
        ),
        None,
    )
    if spf:
        report.records["SPF"] = [spf]
        report.mail["spf"] = spf
        report.mail["spf_domain"] = apex if spf not in report.records.get("TXT", []) else host

    candidates = [f"_dmarc.{host}"]
    if domain and domain != host:
        candidates.append(f"_dmarc.{domain}")
    for name in candidates:
        values = _optional_query(resolver, name, "TXT", timeout)
        if values is None:
            report.error = report.error or "DMARC lookup failed"
            continue
        dmarc = next(
            (value for value in values if value.strip().lower().startswith("v=dmarc1")), None
        )
        if dmarc:
            policy = parse_dmarc_policy(dmarc)
            report.records["DMARC"] = [policy["raw"]]
            report.mail["dmarc"] = policy
            return


def _collect_dkim(
    resolver: Any, host: str, report: DNSReport, timeout: float, deadline: float
) -> None:
    import time

    from venomscan_engine.recon.osint import registrable_domain

    domain = registrable_domain(host) or host
    found: list[dict[str, Any]] = []
    for selector in DKIM_SELECTORS:
        if len(found) >= MAX_DKIM or time.monotonic() >= deadline:
            break
        values = _optional_query(resolver, f"{selector}._domainkey.{domain}", "TXT", timeout)
        if not values:
            continue
        record = next((value for value in values if "v=dkim1" in value.lower()), None)
        if record is None:
            continue
        entry = _dkim_entry(selector, record)
        found.append(entry)
        report.records.setdefault("DKIM", []).append(_dkim_label(entry))
    if found:
        report.mail["dkim"] = found


def _collect_srv(resolver: Any, host: str, report: DNSReport) -> None:
    seen: list[str] = []
    for service in SRV_SERVICES:
        values = _optional_query(resolver, f"{service}.{host}", "SRV", 0.8)
        if not values:
            continue
        for value in values:
            seen.append(f"{service} → {value}")
    if seen:
        report.records["SRV"] = seen[:MAX_VALUES]


def _collect_ptr(resolver: Any, host: str, report: DNSReport) -> None:
    import dns.reversename

    addresses = [*report.records.get("A", []), *report.records.get("AAAA", [])]
    values: list[str] = []
    for address in addresses[:MAX_PTR]:
        try:
            name = dns.reversename.from_address(address)
        except ValueError:
            continue
        answers = _optional_query(resolver, name.to_text(), "PTR", 0.8)
        if not answers:
            continue
        for answer in answers:
            values.append(f"{address} → {answer.rstrip('.')}")
    if values:
        report.records["PTR"] = values[:MAX_VALUES]


def _collect(host: str, resolver: Any, timeout: float) -> DNSReport:
    import time

    import dns.exception
    import dns.resolver

    report = DNSReport(host=host)
    deadline = time.monotonic() + max(timeout * 2, 3.0)
    for rtype in RECORD_TYPES:
        if time.monotonic() >= deadline:
            report.error = report.error or "DNS lookup budget reached"
            break
        remaining = max(0.5, deadline - time.monotonic())
        try:
            values = _resolver_query(resolver, host, rtype, min(timeout, remaining))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            continue
        except dns.exception.Timeout:
            report.error = report.error or f"DNS timeout for {rtype}"
            continue
        except (dns.exception.DNSException, ValueError, OSError) as exc:
            report.error = report.error or f"{type(exc).__name__}: {str(exc)[:160]}"
            continue
        if values:
            report.records[rtype] = values

    from venomscan_engine.recon.osint import registrable_domain

    domain = registrable_domain(host)
    if time.monotonic() < deadline and (report.records.get("TXT") or domain):
        _collect_mail_policy(resolver, host, report, min(timeout, 1.5))
    if time.monotonic() < deadline and (
        report.records.get("TXT") or report.records.get("MX") or domain
    ):
        _collect_dkim(resolver, host, report, min(timeout, 0.8), deadline)
    if time.monotonic() < deadline:
        _collect_srv(resolver, host, report)
    if time.monotonic() < deadline:
        _collect_ptr(resolver, host, report)
    return report


async def lookup_dns(
    host: str,
    *,
    resolver: Any | None = None,
    timeout: float = 3.0,  # noqa: ASYNC109 - thread offload needs the timeout value
) -> DNSReport:
    """Resolve common record types in a worker thread; failures never raise."""

    def _run() -> DNSReport:
        import dns.resolver

        active = resolver
        if active is None:
            active = dns.resolver.Resolver()
        try:
            active.lifetime = timeout
            active.timeout = min(timeout, 2.0)
        except AttributeError:
            pass
        return _collect(host, active, timeout)

    try:
        return await asyncio.to_thread(_run)
    except Exception as exc:  # resolver construction failures must not sink the scan
        return DNSReport(host=host, error=f"{type(exc).__name__}: {str(exc)[:160]}")


__all__ = [
    "DKIM_SELECTORS",
    "DNSReport",
    "RECORD_TYPES",
    "SRV_SERVICES",
    "lookup_dns",
    "parse_dmarc_policy",
]
