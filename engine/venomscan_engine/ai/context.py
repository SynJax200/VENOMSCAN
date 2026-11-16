from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any

MAX_LIST = 8
MAX_TEXT = 200

_URL = re.compile(r"https?://[^\s\"'<>)\]}]+")

# Finding families that benefit from a specific slice of recon intelligence.
_RELEVANT: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (("venom.api", "venom.authz"), ("api_intel", "api", "endpoint_intel", "verification")),
    (
        ("venom.secrets.js", "venom.xss.dom", "venom.crawl"),
        ("js_intel", "crawl", "endpoint_intel", "verification"),
    ),
    (("venom.tls", "venom.transport"), ("tls", "verification")),
    (
        ("venom.headers", "venom.clickjacking", "venom.cookies", "venom.cors", "venom.cache"),
        ("waf", "tls", "verification"),
    ),
    (
        ("venom.xss", "venom.sqli", "venom.ssti", "venom.lfi", "venom.ssrf", "venom.xxe", "venom.idor"),
        ("crawl", "js_intel", "endpoint_intel", "verification"),
    ),
)


def _cap(value: Any, limit: int = MAX_LIST) -> list[Any]:
    return list(value or [])[:limit]


def _text(value: Any, limit: int = MAX_TEXT) -> str:
    text = str(value or "").strip()
    return text[:limit]


def _compact(value: Any) -> Any:
    """Drop empties so prompts and cache keys stay small and stable."""
    if isinstance(value, dict):
        cleaned = {key: _compact(item) for key, item in value.items()}
        return {key: item for key, item in cleaned.items() if item not in (None, "", {}, [])}
    if isinstance(value, list):
        return [_compact(item) for item in value if item not in (None, "", {}, [])]
    if isinstance(value, str):
        return value.strip()
    return value


def _dns(recon: dict[str, Any]) -> dict[str, Any]:
    dns = recon.get("dns") or {}
    if not isinstance(dns, dict) or not dns:
        return {}
    mail = dns.get("mail") or {}
    dmarc = mail.get("dmarc") or {}
    records = dns.get("records") or {}
    return {
        "host": dns.get("host"),
        "record_counts": {
            rtype: len(values)
            for rtype, values in records.items()
            if isinstance(values, list) and values
        },
        "spf": _text(mail.get("spf"), 120) or None,
        "dmarc_policy": dmarc.get("policy"),
        "dmarc_subdomain_policy": dmarc.get("subdomain_policy"),
        "dkim_selectors": _cap([item.get("selector") for item in mail.get("dkim") or [] if item]),
        "error": dns.get("error"),
    }


def _ip_intel(recon: dict[str, Any]) -> dict[str, Any]:
    ip_intel = recon.get("ip_intel") or {}
    if not isinstance(ip_intel, dict) or not ip_intel:
        return {}
    return {
        "addresses": [
            {
                "address": item.get("address"),
                "scope": item.get("scope"),
                "asn": item.get("asn"),
                "as_name": item.get("as_name"),
                "country": item.get("country"),
            }
            for item in _cap(ip_intel.get("addresses"))
            if item
        ],
        "hosting": _cap(ip_intel.get("hosting")),
        "error": ip_intel.get("error"),
    }


def _tls(recon: dict[str, Any]) -> dict[str, Any]:
    tls = recon.get("tls") or {}
    if not isinstance(tls, dict) or not tls:
        return {}
    return {
        "protocol": tls.get("protocol"),
        "issuer": tls.get("issuer"),
        "days_to_expiry": tls.get("days_to_expiry"),
        "verified": tls.get("verified"),
        "sans": _cap(tls.get("sans")),
        "error": tls.get("error"),
    }


def _api_intel(recon: dict[str, Any]) -> dict[str, Any]:
    intel = recon.get("api_intel") or {}
    if not isinstance(intel, dict) or not intel:
        return {}
    spec = intel.get("spec") or {}
    jwt = intel.get("jwt") or {}
    graphql = intel.get("graphql") or {}
    return {
        "spec": {
            "documents": spec.get("documents"),
            "routes": spec.get("routes"),
            "operations": spec.get("operations"),
            "public_write_count": spec.get("public_write_count"),
            "public_writes": _cap(
                [
                    {"method": item.get("method"), "path": item.get("path")}
                    for item in spec.get("public_writes") or []
                    if item
                ]
            ),
            "api_key_query_schemes": _cap(spec.get("api_key_query_schemes")),
            "oauth_implicit": _cap(spec.get("oauth_implicit")),
            "cross_origin_servers": _cap(spec.get("cross_origin_servers")),
            "deprecated_count": spec.get("deprecated_count"),
        },
        "jwt": {
            "tokens": len(jwt.get("tokens") or []),
            "flags": sorted(
                {
                    flag
                    for token in jwt.get("tokens") or []
                    for flag in token.get("flags") or []
                    if flag
                }
            ),
        },
        "graphql": {
            "confirmed": _cap(graphql.get("confirmed")),
            "probed": graphql.get("probed"),
            "introspection": graphql.get("introspection"),
            "ide": graphql.get("ide"),
            "type_count": graphql.get("type_count"),
            "mutation_available": graphql.get("mutation_available"),
        },
    }


def _endpoint_intel(recon: dict[str, Any]) -> dict[str, Any]:
    intel = recon.get("endpoint_intel") or {}
    if not isinstance(intel, dict) or not intel:
        return {}
    return {
        "cluster_count": intel.get("cluster_count"),
        "endpoint_count": intel.get("endpoint_count"),
        "templated": intel.get("templated"),
        "api_clusters": intel.get("api_clusters"),
        "clusters": [
            {
                "template": _text(item.get("template")),
                "count": item.get("count"),
                "methods": _cap(item.get("methods"), 4),
                "sources": _cap(item.get("sources"), 4),
            }
            for item in _cap(intel.get("clusters"))
            if item
        ],
    }


def _js_intel(recon: dict[str, Any]) -> dict[str, Any]:
    intel = recon.get("js_intel") or {}
    if not isinstance(intel, dict) or not intel:
        return {}
    return {
        "scripts": intel.get("scripts"),
        "api_calls": intel.get("api_calls"),
        "post_calls": intel.get("post_calls"),
        "source_maps": _cap(
            [item.get("url") for item in intel.get("source_maps") or [] if item and item.get("url")]
        ),
        "graphql_endpoints": _cap(intel.get("graphql_endpoints")),
        "sensitive_paths": _cap(intel.get("sensitive_paths")),
        "third_party_hosts": _cap(intel.get("third_party_hosts")),
        "parameters": _cap(intel.get("parameters")),
    }


def _correlation(recon: dict[str, Any]) -> dict[str, Any]:
    correlation = recon.get("correlation") or {}
    if not isinstance(correlation, dict) or not correlation:
        return {}
    return {
        "boosted_findings": correlation.get("boosted_findings"),
        "max_multiplier": correlation.get("max_multiplier"),
        "chains": [
            {
                "rule": chain.get("rule_id") or chain.get("title"),
                "multiplier": chain.get("multiplier"),
                "gate": (chain.get("gate") or {}).get("check_id"),
                "triggers": _cap(
                    [(item or {}).get("check_id") for item in chain.get("triggers") or [] if item]
                ),
            }
            for chain in _cap(correlation.get("chains"), 5)
            if chain
        ],
    }


def recon_digest(recon: dict[str, Any] | None) -> dict[str, Any]:
    """Compact, redacted view of recon intelligence suitable for a prompt."""
    recon = recon or {}
    if not isinstance(recon, dict):
        return {}
    digest: dict[str, Any] = {
        "dns": _dns(recon),
        "ip_intel": _ip_intel(recon),
        "tls": _tls(recon),
        "waf": {
            "detected": (recon.get("waf") or {}).get("detected"),
            "vendors": _cap(
                [
                    item.get("name")
                    for item in (recon.get("waf") or {}).get("vendors") or []
                    if item and item.get("name")
                ],
                4,
            ),
        }
        if recon.get("waf")
        else {},
        "subdomains": {
            "count": (recon.get("subdomains") or {}).get("count"),
            "names": _cap((recon.get("subdomains") or {}).get("names")),
        }
        if recon.get("subdomains")
        else {},
        "whois": {
            "registrar": (recon.get("whois") or {}).get("registrar"),
            "created": (recon.get("whois") or {}).get("created"),
            "expires": (recon.get("whois") or {}).get("expires"),
        }
        if recon.get("whois")
        else {},
        "history": {
            "count": (recon.get("history") or {}).get("count"),
            "urls": _cap(
                [
                    {"url": item.get("url"), "kind": item.get("kind")}
                    for item in (recon.get("history") or {}).get("urls") or []
                    if item and item.get("url")
                ]
            ),
        }
        if recon.get("history")
        else {},
        "exposure": [
            {
                "address": item.get("address"),
                "source": item.get("source"),
                "ports": _cap(item.get("ports"), 6),
                "vulns": _cap(item.get("vulns"), 5),
            }
            for item in _cap(recon.get("exposure"), 3)
            if item
        ],
        "neighbours": {
            "prefix": (recon.get("neighbours") or {}).get("prefix"),
            "queried": (recon.get("neighbours") or {}).get("queried"),
            "hosts": _cap(
                [item.get("address") for item in (recon.get("neighbours") or {}).get("hosts") or [] if item]
            ),
        }
        if recon.get("neighbours")
        else {},
        "crawl": {
            key: (recon.get("crawl") or {}).get(key)
            for key in (
                "pages",
                "links",
                "forms",
                "js_files",
                "js_endpoints",
                "probed",
                "api_specs",
                "api_endpoints",
                "robots_found",
                "sitemap_urls",
            )
        }
        if recon.get("crawl")
        else {},
        "js_intel": _js_intel(recon),
        "endpoint_intel": _endpoint_intel(recon),
        "dirs": {
            "probed": (recon.get("dirs") or {}).get("probed"),
            "found": (recon.get("dirs") or {}).get("found"),
            "paths": _cap((recon.get("dirs") or {}).get("paths")),
        }
        if recon.get("dirs")
        else {},
        "api": {
            "documents": len((recon.get("api") or {}).get("documents") or []),
            "endpoint_count": (recon.get("api") or {}).get("endpoint_count"),
        }
        if recon.get("api")
        else {},
        "api_intel": _api_intel(recon),
        "verification": recon.get("verification") or {},
        "correlation": _correlation(recon),
    }
    return _compact(digest)


def recon_refs(digest: dict[str, Any]) -> list[str]:
    return [f"recon:{section}" for section, value in digest.items() if value]


def recon_urls(digest: dict[str, Any]) -> set[str]:
    urls: set[str] = set()
    for text in walk_strings(digest):
        for url in _URL.findall(text):
            if "{" not in url and "}" not in url:
                urls.add(url.rstrip(".,;:!?"))
    return urls


def walk_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from walk_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk_strings(item)


def relevant_sections(check_id: str) -> tuple[str, ...]:
    for prefixes, sections in _RELEVANT:
        if check_id.startswith(prefixes):
            return sections
    return ("verification",)


def slice_digest(digest: dict[str, Any], sections: Iterable[str]) -> dict[str, Any]:
    return {section: digest[section] for section in sections if section in digest}


def recon_highlights(recon: dict[str, Any] | None, sections: Iterable[str] | None = None) -> list[str]:
    """Deterministic human-readable recon lines; used by fallback builders."""
    digest = recon_digest(recon)
    if sections is not None:
        digest = slice_digest(digest, sections)
    return digest_highlights(digest)


def digest_highlights(digest: dict[str, Any]) -> list[str]:
    """Human-readable lines from an already-compacted recon digest."""
    lines: list[str] = []
    verification = digest.get("verification") or {}
    if verification:
        line = (
            f"Verification: {verification.get('verified', 0)} verified, "
            f"{verification.get('suspected', 0)} suspected, "
            f"{verification.get('rejected', 0)} rejected"
        )
        if verification.get("downgraded"):
            line += f", {verification['downgraded']} downgraded for incomplete evidence"
        lines.append(line + ".")
    crawl = digest.get("crawl") or {}
    if crawl:
        bits = [
            f"{crawl[key]} {label}"
            for key, label in (("pages", "page(s)"), ("links", "link(s)"), ("forms", "form(s)"))
            if crawl.get(key) is not None
        ]
        if crawl.get("api_endpoints"):
            bits.append(f"{crawl['api_endpoints']} API operation(s)")
        if bits:
            lines.append("Crawl: " + ", ".join(bits) + ".")
    dns = digest.get("dns") or {}
    if dns and (dns.get("spf") or dns.get("dmarc_policy") or dns.get("dkim_selectors")):
        bits = []
        if dns.get("spf"):
            bits.append(f"SPF {dns['spf']}")
        if dns.get("dmarc_policy"):
            bits.append(f"DMARC policy {dns['dmarc_policy']}")
        if dns.get("dkim_selectors"):
            bits.append(f"DKIM selector(s) {', '.join(dns['dkim_selectors'])}")
        lines.append("Email authentication: " + "; ".join(bits) + ".")
    waf = digest.get("waf") or {}
    if waf.get("detected") and waf.get("vendors"):
        lines.append("WAF: " + ", ".join(waf["vendors"]) + ".")
    exposure = digest.get("exposure") or []
    for item in exposure[:2]:
        bits = [item.get("address") or "unknown address"]
        if item.get("ports"):
            bits.append("ports " + ",".join(str(port) for port in item["ports"]))
        if item.get("vulns"):
            bits.append(f"{len(item['vulns'])} known CVE(s)")
        lines.append("Internet exposure (OSINT, not scanned): " + "; ".join(bits) + ".")
    js = digest.get("js_intel") or {}
    if js:
        bits = [
            f"{js[key]} {label}"
            for key, label in (("scripts", "bundle(s)"), ("api_calls", "API call(s)"), ("post_calls", "POST call(s)"))
            if js.get(key) is not None
        ]
        if js.get("sensitive_paths"):
            bits.append(f"paths {', '.join(js['sensitive_paths'][:3])}")
        if js.get("source_maps"):
            bits.append(f"{len(js['source_maps'])} source map(s)")
        if bits:
            lines.append("JavaScript intelligence: " + ", ".join(bits) + ".")
    clusters = digest.get("endpoint_intel") or {}
    if clusters.get("cluster_count"):
        line = (
            f"Endpoint clusters: {clusters['cluster_count']} pattern(s), "
            f"{clusters.get('templated', 0)} parameterised, {clusters.get('api_clusters', 0)} API-like."
        )
        lines.append(line)
    api = digest.get("api_intel") or {}
    spec = api.get("spec") or {}
    if spec:
        bits = [
            f"{spec.get('documents', 0)} spec document(s)",
            f"{spec.get('operations', 0)} operation(s)",
        ]
        if spec.get("public_write_count"):
            bits.append(f"{spec['public_write_count']} public write(s)")
        if spec.get("api_key_query_schemes"):
            bits.append("API key in query: " + ", ".join(spec["api_key_query_schemes"]))
        lines.append("API contract: " + ", ".join(bits) + ".")
    jwt = (api.get("jwt") or {}).get("tokens")
    if jwt:
        flags = (api.get("jwt") or {}).get("flags") or []
        lines.append(f"JWT tokens observed: {jwt}" + (f" (flags: {', '.join(flags)})" if flags else "") + ".")
    graphql = api.get("graphql") or {}
    if graphql.get("confirmed") or graphql.get("introspection"):
        lines.append(
            "GraphQL: "
            + f"{len(graphql.get('confirmed') or [])} confirmed endpoint(s), introspection "
            + ("enabled" if graphql.get("introspection") else "disabled")
            + "."
        )
    correlation = digest.get("correlation") or {}
    if correlation.get("chains"):
        lines.append(
            f"Correlation: {len(correlation['chains'])} attack path(s), "
            f"max multiplier ×{correlation.get('max_multiplier')}."
        )
    dirs = digest.get("dirs") or {}
    if dirs.get("found"):
        paths = ", ".join(dirs.get("paths") or [])
        lines.append(f"Directory probes found {dirs['found']} path(s)" + (f": {paths}" if paths else "") + ".")
    history = digest.get("history") or {}
    if history.get("count"):
        lines.append(f"Archived URLs: {history['count']}.")
    return lines[:12]


def digest_json(digest: dict[str, Any]) -> str:
    """Stable serialization used for fingerprints."""
    return json.dumps(digest, sort_keys=True, default=str)
