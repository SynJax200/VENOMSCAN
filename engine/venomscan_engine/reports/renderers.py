from __future__ import annotations

import hashlib
import html
import json
import re
from datetime import UTC, datetime
from urllib.parse import urlsplit

from venomscan_engine.browser import chromium_launch_kwargs
from venomscan_engine.intel.endpoints import template_path
from venomscan_engine.models import endpoint_state
from venomscan_engine.reports.model import ReportModel

FORMATS = ("json", "markdown", "html", "pdf")

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_MEDIA_TYPES = {
    "json": "application/json",
    "markdown": "text/markdown; charset=utf-8",
    "html": "text/html; charset=utf-8",
    "pdf": "application/pdf",
}


def media_type(fmt: str) -> str:
    return _MEDIA_TYPES[fmt]


def file_extension(fmt: str) -> str:
    return {"markdown": "md"}.get(fmt, fmt)


def render_json(model: ReportModel) -> bytes:
    return json.dumps(model.model_dump(mode="json"), indent=2, ensure_ascii=False).encode("utf-8")


def _fmt(value: object | None) -> str:
    if value is None or value == "":
        return "—"
    return str(value)


_API_PATH = re.compile(r"/(api|graphql|rest|v\d+)(/|$)", re.IGNORECASE)


def _endpoint_anchor(url: str) -> str:
    return hashlib.sha1(url.encode("utf-8", "replace")).hexdigest()[:10]


def _first_sentence(text: object) -> str:
    parts = re.split(r"(?<=[.!?])\s+", str(text or "").strip())
    return parts[0] if parts and parts[0] else ""


def _api_inventory(model: ReportModel) -> list[dict]:
    groups: dict[tuple[str, str], dict] = {}
    for endpoint in model.endpoints:
        path = urlsplit(endpoint.url).path or "/"
        if endpoint.source not in {"openapi", "graphql", "js", "spa"} and not _API_PATH.search(path):
            continue
        template = template_path(endpoint.url)
        key = (endpoint.method.upper(), template)
        row = groups.get(key)
        if row is None:
            row = {
                "method": endpoint.method.upper(),
                "template": template,
                "live": 0,
                "unverified": 0,
                "sources": set(),
                "samples": [],
            }
            groups[key] = row
        if endpoint_state(endpoint.source, endpoint.status_code) == "live":
            row["live"] += 1
        else:
            row["unverified"] += 1
        row["sources"].add(endpoint.source)
        if len(row["samples"]) < 2:
            row["samples"].append(endpoint.url)
    return sorted(
        groups.values(), key=lambda row: (-row["live"], row["method"], row["template"])
    )


def _next_steps(model: ReportModel) -> tuple[str, list[str], str]:
    analysis = next(
        (item for item in reversed(model.ai_analyses) if item.kind == "next_steps"), None
    )
    if analysis is not None:
        mode = "deterministic fallback" if analysis.fallback else f"{analysis.provider}/{analysis.model}"
        return analysis.summary, analysis.steps, mode
    steps: list[str] = []
    ranked = sorted(model.findings, key=lambda item: -item.risk_score)
    for finding in ranked[:6]:
        action = _first_sentence(finding.remediation) or "Apply the vendor fix."
        steps.append(
            f"Fix {finding.title} ({finding.severity}, {finding.verification_status}) at "
            f"{finding.url} — {action}"
        )
    unverified = sum(
        1 for endpoint in model.endpoints if endpoint_state(endpoint.source, endpoint.status_code) != "live"
    )
    if unverified:
        steps.append(
            f"Review the {unverified} unverified endpoint(s) with the target owner before any "
            "deeper active testing."
        )
    summary = (
        f"{len(steps)} follow-up action(s) derived from {len(model.findings)} finding(s). "
        "Every action stays inside the authorized scope."
        if steps
        else "No follow-up action is required from the recorded findings."
    )
    return summary, steps, "deterministic"


def _api_inventory_markdown(model: ReportModel) -> list[str]:
    recon = model.scan.recon or {}
    auth_map = recon.get("auth_map") or {}
    flows = auth_map.get("flows") or []
    bola = recon.get("bola_matrix") or {}
    candidates = bola.get("candidates") or []
    rows = _api_inventory(model)
    if not rows and not flows and not candidates:
        return []
    lines = ["## API inventory", ""]
    if flows:
        lines += ["**Authentication flows**", "", "| Type | Method | Endpoint | State |", "| --- | --- | --- | --- |"]
        for flow in flows[:30]:
            lines.append(
                f"| {_fmt(flow.get('type'))} | {_fmt(flow.get('method'))} | "
                f"{_fmt(flow.get('url'))} | {_fmt(flow.get('state'))} |"
            )
        lines.append("")
    if rows:
        lines += [
            "**API-shaped endpoints**",
            "",
            "| Method | Route | Live | Unverified | Sources |",
            "| --- | --- | --- | --- | --- |",
        ]
        for row in rows[:80]:
            lines.append(
                f"| {row['method']} | {row['template']} | {row['live']} | "
                f"{row['unverified']} | {', '.join(sorted(row['sources']))} |"
            )
        lines.append("")
    if candidates:
        lines += [
            "**BOLA / tenant candidates (manual review scaffold)**",
            "",
            "| Method | Route | Roles | Status |",
            "| --- | --- | --- | --- |",
        ]
        for item in candidates[:20]:
            lines.append(
                f"| {_fmt(item.get('method'))} | {_fmt(item.get('template'))} | "
                f"{', '.join(str(role) for role in item.get('roles') or [])} | "
                f"{_fmt(item.get('status'))} |"
            )
        lines += ["", bola.get("note") or "Non-destructive scaffold; no requests performed.", ""]
    return lines


def _api_inventory_html(model: ReportModel) -> str:
    recon = model.scan.recon or {}
    auth_map = recon.get("auth_map") or {}
    flows = auth_map.get("flows") or []
    bola = recon.get("bola_matrix") or {}
    candidates = bola.get("candidates") or []
    rows = _api_inventory(model)
    if not rows and not flows and not candidates:
        return ""
    esc = html.escape
    parts = ["<h2>API inventory</h2>"]
    if flows:
        flow_rows = "".join(
            f"<tr><td>{esc(_fmt(flow.get('type')))}</td><td>{esc(_fmt(flow.get('method')))}</td>"
            f"<td><code>{esc(_fmt(flow.get('url')))}</code></td>"
            f"<td>{esc(_fmt(flow.get('state')))}</td></tr>"
            for flow in flows[:30]
        )
        parts.append(
            "<h3>Authentication flows</h3><table><thead><tr><th>Type</th><th>Method</th>"
            f"<th>Endpoint</th><th>State</th></tr></thead><tbody>{flow_rows}</tbody></table>"
        )
    if rows:
        endpoint_rows = "".join(
            f"<tr><td>{esc(row['method'])}</td><td><code>{esc(row['template'])}</code></td>"
            f"<td>{row['live']}</td><td>{row['unverified']}</td>"
            f"<td>{esc(', '.join(sorted(row['sources'])))}</td></tr>"
            for row in rows[:80]
        )
        parts.append(
            "<h3>API-shaped endpoints</h3><table><thead><tr><th>Method</th><th>Route</th>"
            f"<th>Live</th><th>Unverified</th><th>Sources</th></tr></thead><tbody>"
            f"{endpoint_rows}</tbody></table>"
        )
    if candidates:
        bola_rows = "".join(
            f"<tr><td>{esc(_fmt(item.get('method')))}</td>"
            f"<td><code>{esc(_fmt(item.get('template')))}</code></td>"
            f"<td>{esc(', '.join(str(role) for role in item.get('roles') or []))}</td>"
            f"<td>{esc(_fmt(item.get('status')))}</td></tr>"
            for item in candidates[:20]
        )
        parts.append(
            "<h3>BOLA / tenant candidates (manual review scaffold)</h3>"
            "<table><thead><tr><th>Method</th><th>Route</th><th>Roles</th><th>Status</th>"
            f"</tr></thead><tbody>{bola_rows}</tbody></table>"
            f"<p class=\"meta\">{esc(bola.get('note') or 'Non-destructive scaffold; no requests performed.')}</p>"
        )
    return "".join(parts)


def _methodology_markdown(model: ReportModel) -> list[str]:
    scan = model.scan
    stats = scan.stats or {}
    consent = "explicit per-scan consent recorded" if scan.profile == "active" else "safe default profile"
    live = sum(
        1 for endpoint in model.endpoints if endpoint_state(endpoint.source, endpoint.status_code) == "live"
    )
    verification = (scan.recon or {}).get("verification") or {}
    verification_line = (
        f"- **Verification:** {_fmt(verification.get('verified'))} verified · "
        f"{_fmt(verification.get('suspected'))} suspected"
        + (
            f" · {_fmt(verification.get('downgraded'))} downgraded for incomplete evidence"
            if verification.get("downgraded")
            else ""
        )
        if verification
        else None
    )
    return [
        "## Scope & methodology",
        "",
        f"- **Profile:** {scan.profile} ({consent})",
        f"- **Budget:** {_fmt(stats.get('requests'))} requests · {_fmt(stats.get('max_seconds'))}s "
        f"scan ceiling · {_fmt(stats.get('rps'))} req/s",
        f"- **Window:** {_fmt(scan.started_at)} → {_fmt(scan.finished_at)}",
        f"- **Endpoints recorded:** {_fmt(stats.get('endpoints'))} "
        f"({live} live · {len(model.endpoints) - live} unverified) · "
        f"**Findings:** {_fmt(stats.get('findings_total'))}",
        *([verification_line] if verification_line else []),
        f"- **Authorization:** {model.authorization.method or 'unknown'} · "
        f"verified {_fmt(model.authorization.verified_at)}",
        "",
    ]


def _recon_markdown(model: ReportModel) -> list[str]:
    recon = model.scan.recon or {}
    if not recon:
        return []
    lines: list[str] = ["## Reconnaissance", ""]

    dns = recon.get("dns") or {}
    records = dns.get("records") or {}
    if records:
        lines += ["**DNS records**", "", "| Type | Values |", "| --- | --- |"]
        for record_type, values in records.items():
            lines.append(
                f"| {record_type} | {', '.join(str(v) for v in (values or [])[:6]) or '—'} |"
            )
        lines.append("")
    elif dns.get("error"):
        lines += [f"**DNS:** lookup failed — {dns['error']}", ""]

    mail = dns.get("mail") or {}
    if mail:
        lines += ["**Email authentication**", ""]
        if mail.get("spf"):
            lines.append(f"- SPF: {str(mail['spf'])[:180]}")
        dmarc = mail.get("dmarc") or {}
        if dmarc:
            lines.append(
                f"- DMARC: policy {_fmt(dmarc.get('policy'))} · subdomain "
                f"{_fmt(dmarc.get('subdomain_policy'))} · pct {_fmt(dmarc.get('percentage'))} · "
                f"rua {', '.join(str(u) for u in dmarc.get('report_uris') or []) or '—'}"
            )
        dkim = mail.get("dkim") or []
        if dkim:
            labels = [
                f"{item.get('selector')} ({item.get('key_type')}"
                + (", revoked" if item.get("revoked") else "")
                + ")"
                for item in dkim
            ]
            lines.append(f"- DKIM selectors: {', '.join(labels)}")
        else:
            lines.append("- DKIM: no record for common provider selectors")
        lines.append("")

    ip_intel = recon.get("ip_intel") or {}
    addresses = ip_intel.get("addresses") or []
    if addresses:
        lines += [
            "**Hosting & IP intelligence**",
            "",
            "| Address | ASN | Organisation | Country |",
            "| --- | --- | --- | --- |",
        ]
        for address in addresses:
            lines.append(
                f"| {_fmt(address.get('address'))} | {_fmt(address.get('asn'))} | "
                f"{_fmt(address.get('as_name'))} | {_fmt(address.get('country'))} |"
            )
        lines.append("")
        if ip_intel.get("hosting"):
            lines += [f"Hosting: {', '.join(str(h) for h in ip_intel['hosting'])}", ""]

    exposures = recon.get("exposure") or []
    if exposures:
        lines += [
            "**Internet exposure (third-party OSINT, not scanned)**",
            "",
            "| Address | Source | Ports | Hostnames | CVEs |",
            "| --- | --- | --- | --- | --- |",
        ]
        for item in exposures:
            lines.append(
                f"| {_fmt(item.get('address'))} | {_fmt(item.get('source'))} | "
                f"{', '.join(str(p) for p in item.get('ports') or []) or '—'} | "
                f"{', '.join(str(n) for n in item.get('hostnames') or []) or '—'} | "
                f"{len(item.get('vulns') or [])} |"
            )
        lines.append("")

    neighbours = recon.get("neighbours") or {}
    if neighbours.get("hosts"):
        names = ", ".join(str(item.get("ptr")) for item in neighbours["hosts"][:8])
        lines += [
            f"**Reverse-DNS neighbours** ({neighbours.get('prefix')}, "
            f"{neighbours.get('queried')} PTR queries, not fetched)",
            "",
            names,
            "",
        ]

    tls = recon.get("tls") or {}
    if tls and not tls.get("error"):
        lines += [
            "**TLS**",
            "",
            f"- Protocol: {_fmt(tls.get('protocol'))} · Cipher: {_fmt(tls.get('cipher'))}",
            f"- Certificate: {_fmt(tls.get('subject'))} · Issuer: {_fmt(tls.get('issuer'))}",
            f"- Valid until {_fmt(tls.get('not_after'))} "
            f"({_fmt(tls.get('days_to_expiry'))} days) · chain verified: {_fmt(tls.get('verified'))}",
            "",
        ]

    waf = recon.get("waf") or {}
    vendors = waf.get("vendors") or []
    if vendors or waf.get("detected"):
        names = ", ".join(
            f"{vendor.get('name')} ({vendor.get('category')}, confidence "
            f"{vendor.get('confidence')})"
            for vendor in vendors
        )
        lines += [f"**WAF / edge:** {names or 'detected'}", ""]

    whois = recon.get("whois") or {}
    if whois and not whois.get("error"):
        lines += [
            "**Registration (RDAP)**",
            "",
            f"- Registrar: {_fmt(whois.get('registrar'))}",
            f"- Created: {_fmt(whois.get('created'))} · Expires: {_fmt(whois.get('expires'))}",
            f"- Nameservers: {', '.join(str(ns) for ns in whois.get('nameservers') or []) or '—'}",
            "",
        ]

    history = recon.get("history") or {}
    history_urls = history.get("urls") or []
    if history_urls:
        counts: dict[str, int] = {}
        for item in history_urls:
            kind = str(item.get("kind") or "page")
            counts[kind] = counts.get(kind, 0) + 1
        breakdown = ", ".join(f"{kind} {count}" for kind, count in sorted(counts.items()))
        lines += [
            f"**Historical URLs (archives, {len(history_urls)}; {breakdown})**",
            "",
            "| Last seen | Kind | URL |",
            "| --- | --- | --- |",
        ]
        for item in history_urls[:12]:
            lines.append(
                f"| {_fmt(item.get('last_seen'))} | {_fmt(item.get('kind'))} | "
                f"{str(item.get('url'))[:120]} |"
            )
        if len(history_urls) > 12:
            lines.append(f"| … | | +{len(history_urls) - 12} more archived URLs |")
        lines.append("")

    crawl = recon.get("crawl") or {}
    if crawl:
        lines += [
            "**Crawl surface**",
            "",
            f"- Pages: {_fmt(crawl.get('pages'))} · Links: {_fmt(crawl.get('links'))} · "
            f"Forms: {_fmt(crawl.get('forms'))} · JS files: {_fmt(crawl.get('js_files'))}",
            f"- JS-derived endpoints: {_fmt(crawl.get('js_endpoints'))} · "
            f"API endpoints: {_fmt(crawl.get('api_endpoints'))} · "
            f"Sitemap URLs: {_fmt(crawl.get('sitemap_urls'))}",
            f"- Stop reason: {_fmt(crawl.get('stopped'))}",
            "",
        ]

    js_intel = recon.get("js_intel") or {}
    if js_intel:
        lines += [
            "**JavaScript intelligence**",
            "",
            f"- Scripts analyzed: {_fmt(js_intel.get('scripts'))} · "
            f"API call sites: {_fmt(js_intel.get('api_calls'))} "
            f"({_fmt(js_intel.get('post_calls'))} non-GET)",
            f"- Source maps exposed: {_fmt(len(js_intel.get('source_maps') or []))} · "
            f"GraphQL references: {_fmt(len(js_intel.get('graphql_endpoints') or []))}",
        ]
        for entry in (js_intel.get("source_maps") or [])[:4]:
            scope = "same origin" if entry.get("same_origin") else "third-party"
            lines.append(f"  - `{str(entry.get('url'))[:140]}` ({scope})")
        if js_intel.get("sensitive_paths"):
            lines.append(
                "- Sensitive paths referenced: "
                + ", ".join(f"`{path}`" for path in js_intel["sensitive_paths"])
            )
        if js_intel.get("third_party_hosts"):
            lines.append(
                "- Third-party hosts: " + ", ".join(js_intel["third_party_hosts"][:8])
            )
        if js_intel.get("parameters"):
            lines.append(
                "- Parameter names: " + ", ".join(js_intel["parameters"][:20])
            )
        lines.append("")

    endpoint_intel = recon.get("endpoint_intel") or {}
    clusters = endpoint_intel.get("clusters") or []
    if clusters:
        lines += [
            f"**Endpoint clusters ({_fmt(endpoint_intel.get('cluster_count'))} patterns, "
            f"{_fmt(endpoint_intel.get('templated'))} parameterised)**",
            "",
            "| Template | Endpoints | Methods | Sources |",
            "| --- | --- | --- | --- |",
        ]
        for cluster in clusters[:12]:
            lines.append(
                f"| `{str(cluster.get('template'))[:120]}` | {_fmt(cluster.get('count'))} | "
                f"{', '.join(cluster.get('methods') or [])} | "
                f"{', '.join(cluster.get('sources') or [])} |"
            )
        lines.append("")

    api_intel = recon.get("api_intel") or {}
    spec = api_intel.get("spec") or {}
    token_intel = ((api_intel.get("jwt") or {}).get("tokens")) or []
    graphql = api_intel.get("graphql") or {}
    if spec or token_intel or int(graphql.get("probed") or 0) > 0:
        lines += ["**API security intelligence**", ""]
        if spec:
            lines.append(
                f"- Spec contracts: {_fmt(spec.get('documents'))} · "
                f"routes {_fmt(spec.get('routes'))} · operations {_fmt(spec.get('operations'))}"
            )
            lines.append(
                f"- Public write operations: {_fmt(spec.get('public_write_count'))} · "
                f"public reads: {_fmt(spec.get('public_reads'))}"
            )
            for operation in (spec.get("public_writes") or [])[:5]:
                lines.append(
                    f"  - {operation.get('method')} `{str(operation.get('path'))[:100]}` without auth"
                )
            if spec.get("api_key_query_schemes"):
                lines.append(
                    "- API keys in query: " + ", ".join(spec["api_key_query_schemes"])
                )
            if spec.get("oauth_implicit"):
                lines.append("- OAuth implicit grant: " + ", ".join(spec["oauth_implicit"]))
            if spec.get("cross_origin_servers"):
                lines.append(
                    "- Cross-origin servers: "
                    + ", ".join(str(server)[:100] for server in spec["cross_origin_servers"])
                )
            if spec.get("deprecated_count"):
                lines.append(f"- Deprecated operations: {_fmt(spec.get('deprecated_count'))}")
        if token_intel:
            flagged = [token for token in token_intel if token.get("flags")]
            lines.append(
                f"- JWT tokens observed: {_fmt(len(token_intel))} · flagged: {_fmt(len(flagged))}"
            )
            for token in token_intel[:5]:
                lifetime = token.get("lifetime_days")
                lines.append(
                    f"  - {token.get('alg')} · {token.get('location')} · "
                    f"lifetime {_fmt(lifetime)}d · flags: "
                    f"{', '.join(token.get('flags') or []) or 'none'}"
                )
        if graphql:
            confirmed = graphql.get("confirmed") or []
            lines.append(
                f"- GraphQL endpoints confirmed: {_fmt(len(confirmed))} of "
                f"{_fmt(graphql.get('probed'))} probed · introspection: "
                f"{'enabled' if graphql.get('introspection') else 'not observed'} · "
                f"IDE: {'exposed' if graphql.get('ide') else 'not observed'}"
            )
            if graphql.get("introspection"):
                lines.append(
                    f"  - Schema types: {_fmt(graphql.get('type_count'))} · objects "
                    f"{_fmt(graphql.get('object_count'))} · mutations "
                    f"{'present' if graphql.get('mutation_available') else 'absent'} · sample: "
                    + (", ".join(graphql.get("sample_types") or []) or "—")
                )
        lines.append("")

    dirs = recon.get("dirs") or {}
    if dirs:
        lines += [
            f"**Content discovery:** {_fmt(dirs.get('probed'))} paths probed · "
            f"{_fmt(dirs.get('found'))} found · soft-404: {_fmt(dirs.get('soft_404'))} · "
            f"stop: {_fmt(dirs.get('stopped'))}",
            "",
        ]

    verification = recon.get("endpoint_verification") or {}
    if verification:
        lines += [
            f"**Endpoint verification:** {_fmt(verification.get('verified'))} verified from "
            f"{_fmt(verification.get('probed'))} probe(s) · "
            f"{_fmt(verification.get('not_found'))} answered 404 · "
            f"stop: {_fmt(verification.get('stopped'))}",
            "",
        ]

    subdomains = recon.get("subdomains") or {}
    if subdomains:
        if subdomains.get("count") and subdomains.get("names"):
            names = ", ".join(str(name) for name in (subdomains.get("names") or [])[:20])
            lines += [f"**Subdomains ({subdomains['count']}):** {names}", ""]
            if subdomains.get("error"):
                lines += [f"Partial source failure: {subdomains['error']}", ""]
        elif subdomains.get("error"):
            lines += [
                f"**Subdomain enumeration:** source {_fmt(subdomains.get('source'))} — "
                f"failed ({subdomains['error']})",
                "",
            ]
        else:
            lines += [
                f"**Subdomain enumeration:** no names observed via "
                f"{_fmt(subdomains.get('source'))}",
                "",
            ]

    return lines


def _coverage_markdown(model: ReportModel) -> list[str]:
    if not model.checks:
        return []
    lines = [
        "## Checks executed",
        "",
        f"{len(model.checks)} checks were in scope for the {model.scan.profile} profile. "
        "\"No finding\" means the check ran without reporting an issue — it is not proof "
        "that the weakness is absent.",
        "",
        "| Check | Name | Category | Result |",
        "| --- | --- | --- | --- |",
    ]
    for check in model.checks:
        result = "FINDING" if check.result == "finding" else "no finding"
        lines.append(f"| `{check.id}` | {check.name} | {check.category} | {result} |")
    lines.append("")
    return lines


def _methodology_html(model: ReportModel) -> str:
    scan = model.scan
    stats = scan.stats or {}
    esc = html.escape
    consent = "explicit per-scan consent recorded" if scan.profile == "active" else "safe default"
    live = sum(
        1 for endpoint in model.endpoints if endpoint_state(endpoint.source, endpoint.status_code) == "live"
    )
    verification = (scan.recon or {}).get("verification") or {}
    verification_cell = ""
    if verification:
        detail = (
            f"{esc(_fmt(verification.get('verified')))} verified · "
            f"{esc(_fmt(verification.get('suspected')))} suspected"
        )
        if verification.get("downgraded"):
            detail += (
                f" · {esc(_fmt(verification.get('downgraded')))} downgraded for incomplete evidence"
            )
        verification_cell = f"<div><b>Verification:</b> {detail}</div>"
    return (
        '<div class="meta-grid">'
        f"<div><b>Profile:</b> {esc(scan.profile)} ({esc(consent)})</div>"
        f"<div><b>Budget:</b> {esc(_fmt(stats.get('requests')))} requests · "
        f"{esc(_fmt(stats.get('max_seconds')))}s ceiling · {esc(_fmt(stats.get('rps')))} req/s</div>"
        f"<div><b>Window:</b> {esc(_fmt(scan.started_at))} → {esc(_fmt(scan.finished_at))}</div>"
        f"<div><b>Endpoints:</b> {esc(_fmt(stats.get('endpoints')))} "
        f"({live} live · {len(model.endpoints) - live} unverified) · "
        f"<b>Findings:</b> {esc(_fmt(stats.get('findings_total')))}</div>"
        f"{verification_cell}"
        "</div>"
    )


def _recon_html(model: ReportModel) -> str:
    recon = model.scan.recon or {}
    if not recon:
        return ""
    esc = html.escape
    parts: list[str] = ["<h2>Reconnaissance</h2>"]

    dns = recon.get("dns") or {}
    records = dns.get("records") or {}
    if records:
        rows = "".join(
            "<tr><td><code>"
            + esc(str(record_type))
            + "</code></td><td>"
            + esc(", ".join(str(v) for v in (values or [])[:6]) or "—")
            + "</td></tr>"
            for record_type, values in records.items()
        )
        parts.append(
            "<h3>DNS records</h3><table><thead><tr><th>Type</th><th>Values</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>"
        )
    elif dns.get("error"):
        parts.append(f"<p>DNS lookup failed: {esc(str(dns['error']))}</p>")

    mail = dns.get("mail") or {}
    if mail:
        rows = ""
        if mail.get("spf"):
            rows += f"<tr><th>SPF</th><td>{esc(str(mail['spf'])[:180])}</td></tr>"
        dmarc = mail.get("dmarc") or {}
        if dmarc:
            rows += (
                f"<tr><th>DMARC policy</th><td>{esc(_fmt(dmarc.get('policy')))}"
                f" (subdomain {esc(_fmt(dmarc.get('subdomain_policy')))}, "
                f"pct {esc(_fmt(dmarc.get('percentage')))})</td></tr>"
                f"<tr><th>DMARC reports</th><td>"
                f"{esc(', '.join(str(u) for u in dmarc.get('report_uris') or []) or '—')}</td></tr>"
            )
        dkim = mail.get("dkim") or []
        dkim_text = (
            ", ".join(
                f"{item.get('selector')} ({item.get('key_type')}"
                + (", revoked" if item.get("revoked") else "")
                + ")"
                for item in dkim
            )
            or "no record for common provider selectors"
        )
        rows += f"<tr><th>DKIM selectors</th><td>{esc(dkim_text)}</td></tr>"
        parts.append(f"<h3>Email authentication</h3><table><tbody>{rows}</tbody></table>")

    ip_intel = recon.get("ip_intel") or {}
    addresses = ip_intel.get("addresses") or []
    if addresses:
        rows = "".join(
            f"<tr><td><code>{esc(_fmt(a.get('address')))}</code></td>"
            f"<td>{esc(_fmt(a.get('asn')))}</td><td>{esc(_fmt(a.get('as_name')))}</td>"
            f"<td>{esc(_fmt(a.get('country')))}</td></tr>"
            for a in addresses
        )
        hosting = ", ".join(str(h) for h in ip_intel.get("hosting") or [])
        parts.append(
            "<h3>Hosting &amp; IP intelligence</h3>"
            '<table><thead><tr><th>Address</th><th>ASN</th><th>Organisation</th>'
            f"<th>Country</th></tr></thead><tbody>{rows}</tbody></table>"
            + (f"<p class=\"meta\">Hosting: {esc(hosting)}</p>" if hosting else "")
        )

    exposures = recon.get("exposure") or []
    if exposures:
        rows = "".join(
            f"<tr><td><code>{esc(_fmt(item.get('address')))}</code></td>"
            f"<td>{esc(_fmt(item.get('source')))}</td>"
            f"<td>{esc(', '.join(str(p) for p in item.get('ports') or []) or '—')}</td>"
            f"<td>{esc(', '.join(str(n) for n in item.get('hostnames') or []) or '—')}</td>"
            f"<td>{len(item.get('vulns') or [])}</td></tr>"
            for item in exposures
        )
        parts.append(
            "<h3>Internet exposure (third-party OSINT, not scanned)</h3>"
            "<table><thead><tr><th>Address</th><th>Source</th><th>Ports</th>"
            f"<th>Hostnames</th><th>CVEs</th></tr></thead><tbody>{rows}</tbody></table>"
        )

    neighbours = recon.get("neighbours") or {}
    if neighbours.get("hosts"):
        names = ", ".join(str(item.get("ptr")) for item in neighbours["hosts"][:8])
        parts.append(
            f"<h3>Reverse-DNS neighbours</h3><p class=\"meta\">"
            f"{esc(_fmt(neighbours.get('prefix')))} · {esc(_fmt(neighbours.get('queried')))} "
            f"PTR queries · not fetched</p><p>{esc(names)}</p>"
        )

    tls = recon.get("tls") or {}
    if tls and not tls.get("error"):
        parts.append(
            "<h3>TLS</h3><table><tbody>"
            f"<tr><th>Protocol / cipher</th><td>{esc(_fmt(tls.get('protocol')))} / "
            f"{esc(_fmt(tls.get('cipher')))}</td></tr>"
            f"<tr><th>Certificate</th><td>{esc(_fmt(tls.get('subject')))}</td></tr>"
            f"<tr><th>Issuer</th><td>{esc(_fmt(tls.get('issuer')))}</td></tr>"
            f"<tr><th>Valid until</th><td>{esc(_fmt(tls.get('not_after')))} "
            f"({esc(_fmt(tls.get('days_to_expiry')))} days)</td></tr>"
            f"<tr><th>Chain verified</th><td>{esc(_fmt(tls.get('verified')))}</td></tr>"
            "</tbody></table>"
        )

    waf = recon.get("waf") or {}
    vendors = waf.get("vendors") or []
    if vendors or waf.get("detected"):
        names = ", ".join(
            f"{v.get('name')} ({v.get('category')}, confidence {v.get('confidence')})"
            for v in vendors
        )
        parts.append(f"<h3>WAF / edge</h3><p>{esc(names or 'detected')}</p>")

    whois = recon.get("whois") or {}
    if whois and not whois.get("error"):
        parts.append(
            "<h3>Registration (RDAP)</h3><table><tbody>"
            f"<tr><th>Registrar</th><td>{esc(_fmt(whois.get('registrar')))}</td></tr>"
            f"<tr><th>Created</th><td>{esc(_fmt(whois.get('created')))}</td></tr>"
            f"<tr><th>Expires</th><td>{esc(_fmt(whois.get('expires')))}</td></tr>"
            f"<tr><th>Nameservers</th><td>{esc(', '.join(str(ns) for ns in whois.get('nameservers') or []) or '—')}</td></tr>"
            "</tbody></table>"
        )

    history = recon.get("history") or {}
    history_urls = history.get("urls") or []
    if history_urls:
        rows = "".join(
            f"<tr><td>{esc(_fmt(item.get('last_seen')))}</td>"
            f"<td>{esc(_fmt(item.get('kind')))}</td>"
            f"<td><code>{esc(str(item.get('url'))[:160])}</code></td></tr>"
            for item in history_urls[:12]
        )
        parts.append(
            f"<h3>Historical URLs ({len(history_urls)} archived)</h3>"
            "<table><thead><tr><th>Last seen</th><th>Kind</th><th>URL</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>"
        )

    crawl = recon.get("crawl") or {}
    if crawl:
        parts.append(
            "<h3>Crawl surface</h3><table><tbody>"
            f"<tr><th>Pages / links / forms</th><td>{esc(_fmt(crawl.get('pages')))} / "
            f"{esc(_fmt(crawl.get('links')))} / {esc(_fmt(crawl.get('forms')))}</td></tr>"
            f"<tr><th>JS files / JS endpoints</th><td>{esc(_fmt(crawl.get('js_files')))} / "
            f"{esc(_fmt(crawl.get('js_endpoints')))}</td></tr>"
            f"<tr><th>API endpoints / sitemap URLs</th><td>{esc(_fmt(crawl.get('api_endpoints')))} / "
            f"{esc(_fmt(crawl.get('sitemap_urls')))}</td></tr>"
            f"<tr><th>Stop reason</th><td>{esc(_fmt(crawl.get('stopped')))}</td></tr>"
            "</tbody></table>"
        )

    js_intel = recon.get("js_intel") or {}
    if js_intel:
        source_rows = "".join(
            f"<tr><td><code>{esc(str(entry.get('url'))[:160])}</code></td>"
            f"<td>{'same origin' if entry.get('same_origin') else 'third-party'}</td></tr>"
            for entry in (js_intel.get("source_maps") or [])[:6]
        )
        parts.append(
            "<h3>JavaScript intelligence</h3><table><tbody>"
            f"<tr><th>Scripts / API call sites</th><td>{esc(_fmt(js_intel.get('scripts')))} / "
            f"{esc(_fmt(js_intel.get('api_calls')))} "
            f"({esc(_fmt(js_intel.get('post_calls')))} non-GET)</td></tr>"
            f"<tr><th>Source maps / GraphQL references</th><td>"
            f"{esc(_fmt(len(js_intel.get('source_maps') or [])))} / "
            f"{esc(_fmt(len(js_intel.get('graphql_endpoints') or [])))}</td></tr>"
            f"<tr><th>Sensitive paths</th><td>"
            f"{esc(', '.join(js_intel.get('sensitive_paths') or []) or '—')}</td></tr>"
            f"<tr><th>Third-party hosts</th><td>"
            f"{esc(', '.join(js_intel.get('third_party_hosts') or []) or '—')}</td></tr>"
            f"<tr><th>Parameter names</th><td>"
            f"{esc(', '.join(js_intel.get('parameters') or []) or '—')}</td></tr>"
            "</tbody></table>"
        )
        if source_rows:
            parts.append(
                "<table><thead><tr><th>Source map</th><th>Scope</th></tr></thead>"
                f"<tbody>{source_rows}</tbody></table>"
            )

    endpoint_intel = recon.get("endpoint_intel") or {}
    clusters = endpoint_intel.get("clusters") or []
    if clusters:
        rows = "".join(
            f"<tr><td><code>{esc(str(cluster.get('template'))[:140])}</code></td>"
            f"<td>{esc(_fmt(cluster.get('count')))}</td>"
            f"<td>{esc(', '.join(cluster.get('methods') or []))}</td>"
            f"<td>{esc(', '.join(cluster.get('sources') or []))}</td></tr>"
            for cluster in clusters[:12]
        )
        parts.append(
            f"<h3>Endpoint clusters ({esc(_fmt(endpoint_intel.get('cluster_count')))} patterns, "
            f"{esc(_fmt(endpoint_intel.get('templated')))} parameterised)</h3>"
            "<table><thead><tr><th>Template</th><th>Endpoints</th><th>Methods</th>"
            f"<th>Sources</th></tr></thead><tbody>{rows}</tbody></table>"
        )

    api_intel = recon.get("api_intel") or {}
    spec = api_intel.get("spec") or {}
    token_intel = ((api_intel.get("jwt") or {}).get("tokens")) or []
    graphql = api_intel.get("graphql") or {}
    if spec or token_intel or int(graphql.get("probed") or 0) > 0:
        write_rows = "".join(
            f"<tr><td>{esc(str(operation.get('method')))}</td>"
            f"<td><code>{esc(str(operation.get('path'))[:140])}</code></td></tr>"
            for operation in (spec.get("public_writes") or [])[:8]
        )
        token_rows = "".join(
            f"<tr><td>{esc(str(token.get('alg')))}</td><td>{esc(str(token.get('location')))}</td>"
            f"<td>{esc(_fmt(token.get('lifetime_days')))} d</td>"
            f"<td>{esc(', '.join(token.get('flags') or []) or 'none')}</td></tr>"
            for token in token_intel[:6]
        )
        parts.append(
            "<h3>API security intelligence</h3><table><tbody>"
            f"<tr><th>Spec contracts / routes / operations</th><td>"
            f"{esc(_fmt(spec.get('documents')))} / {esc(_fmt(spec.get('routes')))} / "
            f"{esc(_fmt(spec.get('operations')))}</td></tr>"
            f"<tr><th>Public writes / public reads</th><td>"
            f"{esc(_fmt(spec.get('public_write_count')))} / "
            f"{esc(_fmt(spec.get('public_reads')))}</td></tr>"
            f"<tr><th>API keys in query</th><td>"
            f"{esc(', '.join(spec.get('api_key_query_schemes') or []) or '—')}</td></tr>"
            f"<tr><th>OAuth implicit / cross-origin servers</th><td>"
            f"{esc(', '.join(spec.get('oauth_implicit') or []) or '—')} / "
            f"{esc(', '.join(str(server) for server in spec.get('cross_origin_servers') or []) or '—')}"
            "</td></tr>"
            f"<tr><th>Deprecated operations</th><td>"
            f"{esc(_fmt(spec.get('deprecated_count')))}</td></tr>"
            f"<tr><th>JWT tokens observed (flagged)</th><td>{esc(_fmt(len(token_intel)))} "
            f"({esc(_fmt(sum(1 for token in token_intel if token.get('flags'))))})</td></tr>"
            f"<tr><th>GraphQL endpoints / introspection</th><td>"
            f"{esc(_fmt(len(graphql.get('confirmed') or [])))} of {esc(_fmt(graphql.get('probed')))} "
            f"probed / {'enabled' if graphql.get('introspection') else 'not observed'}</td></tr>"
            f"<tr><th>GraphQL schema types</th><td>{esc(_fmt(graphql.get('type_count')))}</td></tr>"
            "</tbody></table>"
        )
        if write_rows:
            parts.append(
                "<table><thead><tr><th>Method</th><th>Public operation</th></tr></thead>"
                f"<tbody>{write_rows}</tbody></table>"
            )
        if token_rows:
            parts.append(
                "<table><thead><tr><th>JWT alg</th><th>Seen in</th><th>Lifetime</th>"
                f"<th>Flags</th></tr></thead><tbody>{token_rows}</tbody></table>"
            )

    dirs = recon.get("dirs") or {}
    if dirs:
        parts.append(
            "<h3>Content discovery</h3><table><tbody>"
            f"<tr><th>Paths probed / found</th><td>{esc(_fmt(dirs.get('probed')))} / "
            f"{esc(_fmt(dirs.get('found')))}</td></tr>"
            f"<tr><th>Soft-404 / warnings</th><td>{esc(_fmt(dirs.get('soft_404')))} / "
            f"{esc(_fmt(dirs.get('warnings')))}</td></tr>"
            f"<tr><th>Stop reason</th><td>{esc(_fmt(dirs.get('stopped')))}</td></tr>"
            "</tbody></table>"
        )

    verification = recon.get("endpoint_verification") or {}
    if verification:
        parts.append(
            "<h3>Endpoint verification</h3><table><tbody>"
            f"<tr><th>Verified / probed</th><td>{esc(_fmt(verification.get('verified')))} / "
            f"{esc(_fmt(verification.get('probed')))}</td></tr>"
            f"<tr><th>Answered 404</th><td>{esc(_fmt(verification.get('not_found')))}</td></tr>"
            f"<tr><th>Stop reason</th><td>{esc(_fmt(verification.get('stopped')))}</td></tr>"
            "</tbody></table>"
        )

    subdomains = recon.get("subdomains") or {}
    if subdomains:
        if subdomains.get("count") and subdomains.get("names"):
            parts.append(
                f"<h3>Subdomains ({int(subdomains['count'])})</h3><p>"
                + esc(", ".join(str(n) for n in (subdomains.get("names") or [])[:20]))
                + "</p>"
            )
            if subdomains.get("error"):
                parts.append(
                    f"<p class=\"meta\">Partial source failure: "
                    f"{esc(str(subdomains['error']))}</p>"
                )
        elif subdomains.get("error"):
            parts.append(
                f"<h3>Subdomain enumeration</h3><p>Source {esc(_fmt(subdomains.get('source')))} — "
                f"failed ({esc(str(subdomains['error']))})</p>"
            )
        else:
            parts.append(
                f"<h3>Subdomain enumeration</h3><p>No names observed via "
                f"{esc(_fmt(subdomains.get('source')))}</p>"
            )

    return "".join(parts)


def _coverage_html(model: ReportModel) -> str:
    if not model.checks:
        return ""
    esc = html.escape
    rows = "".join(
        f"<tr><td><code>{esc(check.id)}</code></td><td>{esc(check.name)}</td>"
        f"<td>{esc(check.category)}</td>"
        f"<td>{'<span class=\"badge sev-low\">finding</span>' if check.result == 'finding' else 'no finding'}</td></tr>"
        for check in model.checks
    )
    return (
        f"<h2>Checks executed ({len(model.checks)})</h2>"
        '<p class="meta">Every check included in the selected profile is listed. '
        "&quot;No finding&quot; means the check completed without reporting an issue; "
        "it is not proof that the weakness is absent.</p>"
        "<table><thead><tr><th>Check</th><th>Name</th><th>Category</th><th>Result</th>"
        f"</tr></thead><tbody>{rows}</tbody></table>"
    )


def _next_steps_markdown(model: ReportModel) -> list[str]:
    summary, steps, mode = _next_steps(model)
    if not steps:
        return []
    return [
        "## Recommended next steps",
        "",
        f"{summary} _(source: {mode})_",
        "",
        *[f"{index}. {step}" for index, step in enumerate(steps, start=1)],
        "",
    ]


def _next_steps_html(model: ReportModel) -> str:
    summary, steps, mode = _next_steps(model)
    if not steps:
        return ""
    esc = html.escape
    items = "".join(f"<li>{esc(step)}</li>" for step in steps)
    return (
        "<h2>Recommended next steps</h2>"
        f"<p>{esc(summary)} <span class=\"meta\">(source: {esc(mode)})</span></p>"
        f"<ol>{items}</ol>"
    )


def render_markdown(model: ReportModel) -> bytes:
    scan = model.scan
    counts = model.severity_counts
    lines: list[str] = [
        f"# Security assessment — {scan.target_name or scan.target_url}",
        "",
        f"- **Report generated:** {model.generated_at}",
        f"- **Scan:** `{scan.id}` ({scan.profile} profile, {scan.status})",
        f"- **Target:** {scan.target_url}",
        f"- **Authorization:** {model.authorization.method or 'unknown'} "
        f"(verified {_fmt(model.authorization.verified_at)}, expires "
        f"{_fmt(model.authorization.expires_at)})",
        f"- **Operator:** {_fmt(model.authorization.operator)}",
        "",
        "## Executive summary",
        "",
        scan.summary or "No summary was recorded for this scan.",
        "",
        "## Findings by severity",
        "",
        "| Critical | High | Medium | Low | Info | Total |",
        "| --- | --- | --- | --- | --- | --- |",
        "| "
        + " | ".join(str(counts[level]) for level in _SEVERITY_ORDER)
        + f" | {len(model.findings)} |",
        "",
    ]
    lines += _methodology_markdown(model)
    lines += _recon_markdown(model)
    lines += _coverage_markdown(model)
    if not model.findings:
        lines += [
            "No findings were recorded. Passive checks only cover externally observable "
            "configuration, so a clean result is not proof the target is secure.",
            "",
        ]
    for index, finding in enumerate(model.findings, start=1):
        lines += [
            f"### {index}. [{finding.severity.upper()}] {finding.title}",
            "",
            f"- **Risk:** {finding.risk_score}/10 · **Confidence:** {finding.confidence}/10 · "
            f"**Status:** {finding.verification_status}",
            f"- **Check:** `{finding.check_id}` · **Category:** {finding.category}",
            f"- **Endpoint:** {finding.method} {finding.url} · "
            f"[surface record](#endpoint-{_endpoint_anchor(finding.url)})",
        ]
        if finding.parameter:
            lines.append(f"- **Parameter:** {finding.parameter}")
        if finding.cvss_score is not None:
            lines.append(f"- **CVSS:** {finding.cvss_score} {finding.cvss_vector or ''}".rstrip())
        if finding.cwe or finding.owasp:
            tags = ", ".join([*finding.cwe, *finding.owasp])
            lines.append(f"- **Weakness:** {tags}")
        lines += [
            "",
            f"**Description.** {finding.description}",
            "",
            f"**Impact.** {finding.impact}",
            "",
            f"**Remediation.** {finding.remediation}",
            "",
        ]
        if finding.reproduction:
            lines += ["**Reproduction (authorized target only).**", ""]
            lines += [
                f"{step_index}. {step}"
                for step_index, step in enumerate(finding.reproduction, start=1)
            ]
            lines.append("")
        if finding.ai_summary:
            lines += [f"**AI analyst note.** {finding.ai_summary}", ""]
        if finding.references:
            lines += ["**References.**", *[f"- {ref}" for ref in finding.references], ""]
        evidence = finding.request_evidence or finding.response_evidence
        if evidence:
            lines += [
                "**Evidence.**",
                "",
                "```json",
                json.dumps(evidence, indent=2, ensure_ascii=False)[:4000],
                "```",
                "",
            ]

    if model.technologies:
        lines += ["## Technologies detected", "", "| Technology | Version | Category |", "| --- | --- | --- |"]
        lines += [
            f"| {tech.name} | {_fmt(tech.version)} | {tech.category} |" for tech in model.technologies
        ]
        lines.append("")

    if model.endpoints:
        unverified = sum(
            1 for endpoint in model.endpoints if endpoint_state(endpoint.source, endpoint.status_code) != "live"
        )
        lines += [
            "## Attack surface",
            "",
            f"{len(model.endpoints)} endpoints observed — {len(model.endpoints) - unverified} live "
            f"(scanner received a response), {unverified} unverified (referenced in JS, forms or API specs).",
            "",
        ]
        for endpoint in model.endpoints[:200]:
            state = endpoint_state(endpoint.source, endpoint.status_code)
            status = f" ({endpoint.status_code})" if endpoint.status_code else ""
            marker = " — unverified, not fetched" if state != "live" else ""
            lines.append(f"<a id=\"endpoint-{_endpoint_anchor(endpoint.url)}\"></a>")
            lines.append(f"- `{endpoint.method} {endpoint.url}`{status} — {endpoint.source}{marker}")
        if len(model.endpoints) > 200:
            lines.append(f"- … {len(model.endpoints) - 200} more endpoints omitted")
        lines.append("")

    lines += _api_inventory_markdown(model)
    lines += _next_steps_markdown(model)

    if model.ai_analyses:
        lines += ["## AI intelligence", ""]
        for analysis in model.ai_analyses:
            mode = "deterministic fallback" if analysis.fallback else f"{analysis.provider}/{analysis.model}"
            lines += [f"### {analysis.kind} ({mode})", "", analysis.summary, ""]
            if analysis.citations:
                lines += [
                    "- **Citations:** " + ", ".join(f"`{ref}`" for ref in analysis.citations),
                    "",
                ]

    if model.scan.recon:
        raw = json.dumps(model.scan.recon, indent=2, ensure_ascii=False)
        clipped = raw[:12000] + (
            "\n… truncated — download the JSON report for the complete payload."
            if len(raw) > 12000
            else ""
        )
        lines += ["## Reconnaissance appendix (raw)", "", "```json", clipped, "```", ""]

    lines += [
        "---",
        "",
        "Generated by VENOMSCAN (S&S Researcher). Only test targets you are authorized to "
        "assess. This report reflects the checks enabled for the selected profile.",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def render_html(model: ReportModel, integrity: str = "") -> str:
    scan = model.scan
    counts = model.severity_counts
    esc = html.escape

    severity_rows = "".join(
        f'<div class="sev sev-{level}"><span>{level}</span><strong>{counts[level]}</strong></div>'
        for level in _SEVERITY_ORDER
    )

    finding_blocks: list[str] = []
    for index, finding in enumerate(model.findings, start=1):
        meta = [
            f"Risk {finding.risk_score}/10",
            f"Confidence {finding.confidence}/10",
            f"Status {finding.verification_status}",
            f"Check {finding.check_id}",
        ]
        if finding.parameter:
            meta.append(f"Parameter {finding.parameter}")
        if finding.cvss_score is not None:
            meta.append(f"CVSS {finding.cvss_score}")
        refs = "".join(f"<li>{esc(ref)}</li>" for ref in finding.references)
        tags = "".join(f"<span class=\"tag\">{esc(tag)}</span>" for tag in [*finding.cwe, *finding.owasp])
        evidence_block = ""
        evidence = finding.request_evidence or finding.response_evidence
        if evidence:
            evidence_block = (
                "<h4>Evidence</h4><pre>"
                + esc(json.dumps(evidence, indent=2, ensure_ascii=False)[:4000])
                + "</pre>"
            )
        ai_block = (
            f'<div class="ai"><strong>AI analyst note</strong><p>{esc(finding.ai_summary)}</p></div>'
            if finding.ai_summary
            else ""
        )
        reproduction_block = (
            '<h4>Reproduction (authorized target only)</h4><ol>'
            + "".join(f"<li>{esc(step)}</li>" for step in finding.reproduction)
            + "</ol>"
            if finding.reproduction
            else ""
        )
        finding_blocks.append(
            f'<article class="finding">'
            f'<header><span class="badge sev-{esc(finding.severity)}">{esc(finding.severity)}</span>'
            f"<h3>{index}. {esc(finding.title)}</h3></header>"
            f'<p class="meta">{" · ".join(esc(item) for item in meta)}</p>'
            f'<p class="endpoint"><code>{esc(finding.method)} {esc(finding.url)}</code> · '
            f'<a href="#endpoint-{_endpoint_anchor(finding.url)}">surface record</a></p>'
            f"<h4>Description</h4><p>{esc(finding.description)}</p>"
            f"<h4>Impact</h4><p>{esc(finding.impact)}</p>"
            f"<h4>Remediation</h4><p>{esc(finding.remediation)}</p>"
            f"{reproduction_block}"
            f"{ai_block}"
            + (f"<h4>Weakness</h4><p>{tags}</p>" if tags else "")
            + (f"<h4>References</h4><ul>{refs}</ul>" if refs else "")
            + evidence_block
            + "</article>"
        )
    if not finding_blocks:
        finding_blocks.append(
            '<p class="empty">No findings were recorded. Passive checks only cover externally '
            "observable configuration, so a clean result is not proof the target is secure.</p>"
        )

    tech_rows = "".join(
        f"<tr><td>{esc(tech.name)}</td><td>{esc(_fmt(tech.version))}</td>"
        f"<td>{esc(tech.category)}</td></tr>"
        for tech in model.technologies
    )
    tech_section = (
        f"<h2>Technologies detected</h2><table><thead><tr><th>Technology</th><th>Version</th>"
        f"<th>Category</th></tr></thead><tbody>{tech_rows}</tbody></table>"
        if tech_rows
        else ""
    )

    def _endpoint_cells(endpoint) -> str:
        state = endpoint_state(endpoint.source, endpoint.status_code)
        return (
            f'<tr id="endpoint-{_endpoint_anchor(endpoint.url)}">'
            f"<td><code>{esc(endpoint.method)} {esc(endpoint.url)}</code></td>"
            f"<td>{esc(_fmt(endpoint.status_code))}</td><td>{esc(state)}</td>"
            f"<td>{esc(endpoint.source)}</td></tr>"
        )

    endpoint_rows = "".join(_endpoint_cells(endpoint) for endpoint in model.endpoints[:200])
    unverified = sum(
        1 for endpoint in model.endpoints if endpoint_state(endpoint.source, endpoint.status_code) != "live"
    )
    endpoint_section = (
        f"<h2>Attack surface ({len(model.endpoints)} endpoints)</h2>"
        f"<p>{len(model.endpoints) - unverified} live (scanner received a response), "
        f"{unverified} unverified (referenced in JS, forms or API specs).</p>"
        f"<table><thead><tr><th>Endpoint</th><th>Status</th><th>Surface</th><th>Source</th></tr></thead>"
        f"<tbody>{endpoint_rows}</tbody></table>"
        if endpoint_rows
        else ""
    )

    api_inventory_section = _api_inventory_html(model)
    next_steps_section = _next_steps_html(model)

    ai_section = ""
    if model.ai_analyses:
        blocks = "".join(
            f'<article class="finding"><header><h3>{esc(item.kind)}</h3></header>'
            f'<p class="meta">{"deterministic fallback" if item.fallback else esc(f"{item.provider}/{item.model}")}</p>'
            f"<p>{esc(item.summary)}</p>"
            + (
                '<p class="meta">Citations: '
                + " ".join(f"<code>{esc(ref)}</code>" for ref in item.citations)
                + "</p>"
                if item.citations
                else ""
            )
            + "</article>"
            for item in model.ai_analyses
        )
        ai_section = f"<h2>AI intelligence</h2>{blocks}"

    recon_appendix = ""
    if model.scan.recon:
        raw = json.dumps(model.scan.recon, indent=2, ensure_ascii=False)
        clipped = raw[:12000] + (
            "\n… truncated — download the JSON report for the complete payload."
            if len(raw) > 12000
            else ""
        )
        recon_appendix = (
            "<h2>Reconnaissance appendix (raw)</h2>"
            '<p class="meta">Pipeline artefacts reproduced as stored; third-party OSINT is '
            "metadata only and never sends traffic to the target.</p>"
            f"<pre>{esc(clipped)}</pre>"
        )

    integrity_block = (
        f'<footer><p>SHA-256: <code>{esc(integrity)}</code></p>'
        "<p>VENOMSCAN · S&S Researcher · authorized targets only. This report reflects the "
        "checks enabled for the selected profile.</p></footer>"
        if integrity
        else "<footer><p>VENOMSCAN · S&S Researcher · authorized targets only.</p></footer>"
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VENOMSCAN report — {esc(scan.target_name or scan.target_url)}</title>
<style>
:root {{ color-scheme: light; }}
* {{ box-sizing: border-box; }}
body {{ margin: 0; padding: 40px; font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
  color: #1c1f24; background: #ffffff; font-size: 13px; line-height: 1.6; }}
.wrap {{ max-width: 860px; margin: 0 auto; }}
.brand {{ display: flex; align-items: baseline; gap: 10px; border-bottom: 3px solid #0078A7; padding-bottom: 14px; }}
.brand h1 {{ margin: 0; font-size: 26px; letter-spacing: .02em; color: #0A0A0A; }}
.brand span {{ color: #B71095; font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: .14em; }}
h2 {{ margin-top: 34px; font-size: 17px; color: #0A0A0A; border-bottom: 1px solid #e5e7eb; padding-bottom: 6px;
  break-after: avoid; page-break-after: avoid; }}
h3 {{ margin: 0; font-size: 14.5px; }}
h4 {{ margin: 14px 0 4px; font-size: 11px; text-transform: uppercase; letter-spacing: .1em; color: #6b7280; }}
p {{ margin: 6px 0; }}
.meta {{ color: #4b5563; font-size: 11.5px; }}
.endpoint {{ margin: 8px 0 12px; }}
code, pre {{ font-family: "Cascadia Code", Consolas, monospace; font-size: 11px; }}
code {{ background: #f3f4f6; padding: 1px 5px; border-radius: 4px; word-break: break-all; }}
pre {{ background: #f8fafc; border: 1px solid #e5e7eb; border-radius: 6px; padding: 10px;
  white-space: pre-wrap; word-break: break-word; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 12px; }}
th, td {{ text-align: left; padding: 7px 9px; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}
th {{ background: #f8fafc; font-size: 10.5px; text-transform: uppercase; letter-spacing: .08em; color: #6b7280; }}
.meta-grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 6px 24px; margin-top: 14px;
  padding: 14px 18px; background: #f8fafc; border: 1px solid #e5e7eb; border-radius: 8px; font-size: 12px; }}
.meta-grid b {{ color: #374151; }}
.sev-row {{ display: flex; gap: 10px; margin-top: 12px; }}
.sev {{ flex: 1; padding: 10px 12px; border-radius: 8px; border: 1px solid #e5e7eb; background: #fafafa; }}
.sev span {{ display: block; font-size: 10px; text-transform: uppercase; letter-spacing: .1em; color: #6b7280; }}
.sev strong {{ font-size: 20px; }}
.sev-critical strong {{ color: #B71095; }} .sev-high strong {{ color: #dc2626; }}
.sev-medium strong {{ color: #b45309; }} .sev-low strong {{ color: #0078A7; }}
.sev-info strong {{ color: #4b5563; }}
.finding {{ border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px 18px; margin: 14px 0;
  break-inside: avoid; page-break-inside: avoid; }}
.finding header {{ display: flex; align-items: center; gap: 10px; }}
.badge {{ font-size: 9.5px; font-weight: 700; letter-spacing: .1em; text-transform: uppercase;
  padding: 3px 8px; border-radius: 999px; background: #f3f4f6; }}
.badge.sev-critical {{ background: #fbe7f5; color: #B71095; }}
.badge.sev-high {{ background: #fee2e2; color: #dc2626; }}
.badge.sev-medium {{ background: #fef3c7; color: #b45309; }}
.badge.sev-low {{ background: #e0f2fe; color: #0078A7; }}
.badge.sev-info {{ background: #f3f4f6; color: #4b5563; }}
.tag {{ display: inline-block; margin: 2px 4px 2px 0; padding: 2px 7px; border-radius: 4px;
  background: #eef2ff; color: #3730a3; font-size: 10.5px; }}
.ai {{ margin-top: 12px; padding: 10px 12px; border-left: 3px solid #B71095; background: #fdf4fa; border-radius: 0 6px 6px 0; }}
.ai strong {{ font-size: 10px; letter-spacing: .1em; text-transform: uppercase; color: #B71095; }}
.empty {{ padding: 14px; background: #f8fafc; border: 1px dashed #cbd5e1; border-radius: 8px; }}
footer {{ margin-top: 40px; padding-top: 14px; border-top: 1px solid #e5e7eb; color: #6b7280; font-size: 10.5px; }}
@media print {{ body {{ padding: 0; }} .finding {{ page-break-inside: avoid; }} }}
</style></head>
<body><div class="wrap">
<div class="brand"><h1>VENOMSCAN</h1><span>Security assessment report</span></div>
<div class="meta-grid">
  <div><b>Target:</b> {esc(scan.target_name or scan.target_url)}</div>
  <div><b>URL:</b> {esc(scan.target_url)}</div>
  <div><b>Scan:</b> <code>{esc(scan.id)}</code> ({esc(scan.profile)} profile)</div>
  <div><b>Generated:</b> {esc(model.generated_at)}</div>
  <div><b>Authorization:</b> {esc(model.authorization.method or "unknown")} · expires {esc(_fmt(model.authorization.expires_at))}</div>
  <div><b>Operator:</b> {esc(_fmt(model.authorization.operator))}</div>
</div>
<h2>Executive summary</h2>
<p>{esc(scan.summary or "No summary was recorded for this scan.")}</p>
<div class="sev-row">{severity_rows}</div>
<h2>Scope &amp; methodology</h2>
{_methodology_html(model)}
{_recon_html(model)}
{_coverage_html(model)}
<h2>Findings ({len(model.findings)})</h2>
{''.join(finding_blocks)}
{tech_section}
{endpoint_section}
{api_inventory_section}
{next_steps_section}
{ai_section}
{recon_appendix}
{integrity_block}
</div></body></html>"""


def render_pdf(model: ReportModel, integrity: str = "") -> bytes:
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    document = render_html(model, integrity)
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(**chromium_launch_kwargs())
            try:
                page = browser.new_page()
                page.set_content(document, wait_until="load")
                return page.pdf(
                    format="A4",
                    print_background=True,
                    margin={"top": "14mm", "right": "12mm", "bottom": "14mm", "left": "12mm"},
                    display_header_footer=True,
                    header_template="<span></span>",
                    footer_template=(
                        '<div style="width:100%;font-size:8px;color:#9ca3af;'
                        'padding:0 12mm;display:flex;justify-content:space-between;">'
                        "<span>VENOMSCAN · authorized targets only</span>"
                        '<span class="pageNumber"></span>/<span class="totalPages"></span></div>'
                    ),
                )
            finally:
                browser.close()
    except PlaywrightError as exc:
        raise RuntimeError(
            "PDF rendering needs a Playwright Chromium build "
            "(run: playwright install chromium)"
        ) from exc


def generated_at_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")
