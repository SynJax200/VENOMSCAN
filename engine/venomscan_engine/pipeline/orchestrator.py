from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import asdict
from typing import Any
from urllib.parse import urlsplit

import httpx

from venomscan_engine.checks import checks_for_profile
from venomscan_engine.context import ScanContext
from venomscan_engine.control import ScanCancelled
from venomscan_engine.correlate.engine import correlate_findings
from venomscan_engine.crawl import PROFILE_LIMITS, Crawler, CrawlLimits
from venomscan_engine.crawl.dirs import PROFILE_PROBES, discover_paths
from venomscan_engine.crawl.endpoint_verify import PROFILE_VERIFY, verify_endpoints
from venomscan_engine.crawl.hints import build_surface_hints
from venomscan_engine.crawl.spa import capture_spa
from venomscan_engine.events import EventSink, NullSink
from venomscan_engine.integrations import NucleiConfig, run_nuclei
from venomscan_engine.intel.api import build_api_intel
from venomscan_engine.intel.authflows import build_auth_map
from venomscan_engine.intel.bola import build_bola_matrix
from venomscan_engine.intel.endpoints import cluster_endpoints
from venomscan_engine.models import PROFILE_ORDER, EndpointRecord, ScanResult, ScanStats
from venomscan_engine.oob import OobListener
from venomscan_engine.plugins import PluginError, discover_plugins, run_plugin
from venomscan_engine.plugins.runner import plugin_payload
from venomscan_engine.recon.dns import lookup_dns
from venomscan_engine.recon.exposure import lookup_exposure
from venomscan_engine.recon.ip_intel import lookup_ip_intel, lookup_neighbours
from venomscan_engine.recon.osint import (
    discover_historical_urls,
    discover_subdomains,
    lookup_whois,
    registrable_domain,
)
from venomscan_engine.recon.tech import detect_technologies
from venomscan_engine.recon.tls import probe_tls_async
from venomscan_engine.recon.waf import detect_waf
from venomscan_engine.safety.http import BudgetExceeded, SafeHttpClient
from venomscan_engine.safety.scope import Scope
from venomscan_engine.verify.dedupe import dedupe_findings
from venomscan_engine.verify.verifier import mark_verified


async def run_scan(
    scan_id: str,
    target_url: str,
    *,
    profile: str = "safe",
    sink: EventSink | None = None,
    allow_private: bool = False,
    include_subdomains: bool = False,
    max_requests: int = 120,
    max_seconds: float = 90.0,
    rps: float = 4.0,
    transport: httpx.AsyncBaseTransport | None = None,
    proxy_url: str | None = None,
    nuclei: NucleiConfig | None = None,
    resolver=None,
    dns_resolver: Any | None = None,
    enable_dns: bool = True,
    enable_osint: bool = True,
    enable_history: bool = True,
    enable_ptr_sweep: bool = False,
    osint_transport: httpx.AsyncBaseTransport | None = None,
    shodan_key: str = "",
    censys_id: str = "",
    censys_secret: str = "",
    otx_api_key: str = "",
    crawl_limits: CrawlLimits | None = None,
    disabled_checks: set[str] | None = None,
    active_consent: bool = False,
    cancel_check: Callable[[], bool] | None = None,
    oob: OobListener | None = None,
    auth_accounts: list[dict] | None = None,
    plugin_dirs: tuple[str, ...] = (),
    enable_spa: bool = False,
    enable_dirs: bool = False,
) -> ScanResult:
    if profile not in PROFILE_ORDER:
        raise ValueError(f"unknown scan profile {profile!r}")
    if profile == "active" and not active_consent:
        raise PermissionError("active profile requires explicit per-scan consent")
    sink = sink or NullSink()
    scope = Scope.from_target(target_url, include_subdomains=include_subdomains)
    started = time.monotonic()
    plugin_specs, plugin_problems = discover_plugins(plugin_dirs)
    plugin_specs = [
        spec
        for spec in plugin_specs
        if PROFILE_ORDER.get(spec.profile, 0) <= PROFILE_ORDER[profile]
    ]

    async with SafeHttpClient(
        scope,
        max_requests=max_requests,
        max_seconds=max_seconds,
        rps=rps,
        allow_private=allow_private,
        transport=transport,
        proxy_url=proxy_url,
        resolver=resolver,
        cancel_check=cancel_check,
    ) as client:
        ctx = ScanContext(
            scan_id=scan_id,
            target_url=target_url,
            scope=scope,
            profile=profile,
            sink=sink,
            client=client,
            max_seconds=max_seconds,
            started=started,
        )
        if oob is not None:
            ctx.artifacts["oob"] = oob
        if auth_accounts:
            ctx.artifacts["accounts"] = auth_accounts
        await ctx.emit(
            "authorizing",
            "phase_started",
            f"Scope locked to {', '.join(sorted(scope.hosts))}",
            progress=5,
            payload={"profile": profile, "hosts": sorted(scope.hosts)},
        )
        await ctx.emit("authorizing", "phase_finished", "Scope and profile accepted", progress=10)

        await ctx.emit(
            "recon", "phase_started", "Fetching target root and fingerprinting", progress=15
        )
        root = await client.get(target_url)
        ctx.root = root
        ctx.add_endpoint(
            EndpointRecord(
                url=root.url,
                method="GET",
                source="root",
                status_code=root.status_code,
                content_type=root.header("content-type"),
            )
        )
        for tech in detect_technologies(root):
            ctx.add_technology(tech)
        await ctx.emit(
            "recon",
            "target_fetched",
            f"HTTP {root.status_code} in {root.elapsed_ms} ms",
            progress=25,
            payload={"status_code": root.status_code, "final_url": root.url},
        )

        waf_report = detect_waf(root)
        ctx.artifacts["waf"] = waf_report.as_dict()
        if waf_report.detected:
            await ctx.emit(
                "recon",
                "waf_detected",
                waf_report.summary(),
                progress=31,
                payload=ctx.artifacts["waf"],
            )

        parts = urlsplit(root.url)
        dns_records: dict[str, list[str]] = {}
        if enable_dns and parts.hostname and ctx.remaining_seconds > 3:
            dns_report = await lookup_dns(
                parts.hostname,
                resolver=dns_resolver,
                timeout=min(3.0, ctx.remaining_seconds),
            )
            dns_records = dns_report.records
            ctx.artifacts["dns"] = {
                "host": dns_report.host,
                "records": dns_report.records,
                "mail": dns_report.mail,
                "error": dns_report.error,
            }
            await ctx.emit(
                "recon",
                "dns_records",
                f"DNS: {dns_report.summary()}",
                progress=30,
                payload=ctx.artifacts["dns"],
            )
            if ctx.remaining_seconds > 2:
                intel = await lookup_ip_intel(
                    parts.hostname,
                    dns_records,
                    resolver=dns_resolver,
                    timeout=min(2.0, ctx.remaining_seconds),
                )
                ctx.artifacts["ip_intel"] = intel.as_dict()
                await ctx.emit(
                    "recon",
                    "ip_intel",
                    f"IP intelligence: {intel.summary()}",
                    progress=34,
                    payload=ctx.artifacts["ip_intel"],
                )
                public = [
                    item["address"]
                    for item in ctx.artifacts["ip_intel"].get("addresses", [])
                    if item.get("scope") == "public"
                ]
                if public:
                    exposures = []
                    for address in public[:2]:
                        if ctx.remaining_seconds <= 3:
                            break
                        exposure = await lookup_exposure(
                            address,
                            shodan_key=shodan_key,
                            censys_id=censys_id,
                            censys_secret=censys_secret,
                            transport=osint_transport,
                            timeout=min(8.0, ctx.remaining_seconds),
                        )
                        if exposure is not None:
                            exposures.append(exposure.as_dict())
                    if exposures:
                        ctx.artifacts["exposure"] = exposures
                        await ctx.emit(
                            "recon",
                            "exposure_intel",
                            f"Internet exposure: {len(exposures)} address(es) profiled",
                            progress=35,
                            payload={"exposure": exposures},
                        )
                if enable_ptr_sweep and profile == "active" and ctx.remaining_seconds > 8:
                    neighbours = await lookup_neighbours(
                        public, resolver=dns_resolver, timeout=min(1.0, ctx.remaining_seconds)
                    )
                    ctx.artifacts["neighbours"] = neighbours.as_dict()
                    await ctx.emit(
                        "recon",
                        "ptr_neighbours",
                        neighbours.summary(),
                        progress=35,
                        payload=ctx.artifacts["neighbours"],
                    )

        # OSINT lookups go to crt.sh and IANA's RDAP bootstrap, never to the target,
        # and only for registrable public domains.
        domain = registrable_domain(parts.hostname or "")
        if enable_osint and domain and ctx.remaining_seconds > 20:
            try:
                tasks = [
                    discover_subdomains(
                        domain,
                        transport=osint_transport,
                        timeout=min(15.0, ctx.remaining_seconds),
                        otx_api_key=otx_api_key,
                    ),
                    lookup_whois(
                        domain, transport=osint_transport, timeout=min(10.0, ctx.remaining_seconds)
                    ),
                ]
                if enable_history:
                    tasks.append(
                        discover_historical_urls(
                            domain,
                            transport=osint_transport,
                            timeout=min(12.0, ctx.remaining_seconds),
                        )
                    )
                results = await asyncio.gather(*tasks)
                sub_report, whois_report = results[0], results[1]
                ctx.artifacts["subdomains"] = sub_report.as_dict()
                ctx.artifacts["whois"] = whois_report.as_dict()
                await ctx.emit(
                    "recon",
                    "subdomains",
                    sub_report.summary(),
                    progress=36,
                    payload=ctx.artifacts["subdomains"],
                )
                await ctx.emit(
                    "recon",
                    "whois",
                    whois_report.summary(),
                    progress=38,
                    payload=ctx.artifacts["whois"],
                )
                if enable_history and len(results) > 2:
                    history_report = results[2]
                    ctx.artifacts["history"] = history_report.as_dict()
                    await ctx.emit(
                        "recon",
                        "historical_urls",
                        history_report.summary(),
                        progress=38,
                        payload=ctx.artifacts["history"],
                    )
            except Exception as exc:  # OSINT is enrichment; it must never sink the scan
                await ctx.emit("recon", "warning", f"OSINT lookup failed: {str(exc)[:160]}")

        if parts.scheme == "https" and ctx.remaining_seconds > 3:
            try:
                ctx.artifacts["tls"] = await probe_tls_async(
                    parts.hostname or "", parts.port or 443, timeout=min(8.0, ctx.remaining_seconds)
                )
                await ctx.emit(
                    "recon",
                    "tls_probed",
                    "TLS handshake completed",
                    progress=39,
                    payload={"protocol": ctx.artifacts["tls"].protocol},
                )
            except Exception as exc:  # TLS probe failures must not sink the scan
                await ctx.emit("recon", "warning", f"TLS probe failed: {exc}", progress=39)
        if ctx.technologies:
            await ctx.emit(
                "recon",
                "technologies",
                f"Detected {len(ctx.technologies)} technologie(s)",
                progress=40,
                payload={"technologies": [t.model_dump(mode="json") for t in ctx.technologies]},
            )
        await ctx.emit("recon", "phase_finished", "Reconnaissance complete", progress=40)

        limits = crawl_limits or PROFILE_LIMITS[profile]
        crawler = Crawler(ctx, limits)
        await ctx.emit(
            "crawling",
            "phase_started",
            f"Crawling up to {limits.max_pages} page(s), depth {limits.max_depth}",
            progress=42,
            payload={
                "max_pages": limits.max_pages,
                "max_depth": limits.max_depth,
                "max_path_probes": limits.max_path_probes,
            },
        )
        try:
            crawl_report = await crawler.run()
        except ScanCancelled:
            raise
        except BudgetExceeded:
            crawl_report = crawler.report
            crawl_report.stopped = crawl_report.stopped or "request-budget"
        except Exception as exc:  # a crawl failure must not sink the scan
            crawl_report = crawler.report
            crawl_report.stopped = f"error: {str(exc)[:160]}"
            await ctx.emit("crawling", "warning", f"Crawl stopped: {str(exc)[:200]}", progress=58)
        await ctx.emit(
            "crawling",
            "phase_finished",
            f"{crawl_report.pages} page(s), {len(ctx.endpoints)} endpoint(s), "
            f"{crawl_report.forms} form(s)",
            progress=60,
            payload=crawl_report.as_dict(),
        )

        dir_budget = PROFILE_PROBES.get(profile, 0)
        if enable_dirs and dir_budget and ctx.remaining_seconds > 8:
            await ctx.emit(
                "crawling",
                "dirs_started",
                f"Probing up to {dir_budget} curated path(s)",
                progress=60,
            )
            dir_report = await discover_paths(ctx, max_probes=dir_budget)
            ctx.artifacts["dirs"] = dir_report.as_dict()
            await ctx.emit(
                "crawling",
                "dirs_finished",
                dir_report.summary(),
                progress=60,
                payload=ctx.artifacts["dirs"],
            )

        if enable_spa:
            await ctx.emit(
                "crawling",
                "spa_started",
                "Rendering the application to capture client-side routes",
                progress=61,
            )
            spa_report = await capture_spa(ctx)
            ctx.artifacts["spa"] = spa_report.as_dict()
            await ctx.emit(
                "crawling",
                "spa_finished",
                f"SPA: {spa_report.routes} route(s), {spa_report.xhr} XHR call(s)",
                progress=61,
                payload=ctx.artifacts["spa"],
            )

        verify_budget = PROFILE_VERIFY.get(profile, 0)
        if verify_budget and ctx.remaining_seconds > 8:
            await ctx.emit(
                "crawling",
                "endpoint_verify_started",
                f"Verifying up to {verify_budget} JS-derived endpoint(s)",
                progress=61,
            )
            verify_report = await verify_endpoints(ctx, max_probes=verify_budget)
            ctx.artifacts["endpoint_verification"] = verify_report.as_dict()
            await ctx.emit(
                "crawling",
                "endpoint_verify_finished",
                verify_report.summary(),
                progress=61,
                payload=ctx.artifacts["endpoint_verification"],
            )

        ctx.artifacts["auth_map"] = build_auth_map(ctx.endpoints)
        ctx.artifacts["bola_matrix"] = build_bola_matrix(ctx.endpoints, auth_accounts or [])
        ctx.artifacts["surface"] = build_surface_hints(ctx)
        root_host = (urlsplit(ctx.root.url).hostname or "") if ctx.root is not None else ""
        ctx.artifacts["api_intel"] = build_api_intel(
            [
                document
                for document in (ctx.artifacts.get("openapi") or {}).get("documents") or []
                if isinstance(document, dict)
            ],
            ctx.artifacts.get("api_samples") or [],
            ctx.endpoints,
            ctx.root.set_cookies if ctx.root is not None else [],
            ctx.artifacts.get("js_intel") or {},
            target_host=root_host,
        )

        classes = checks_for_profile(profile, disabled_checks)
        await ctx.emit(
            "analyzing",
            "phase_started",
            f"Running {len(classes)} check(s)",
            progress=62,
            payload={
                "checks": [c.id for c in classes],
                "plugins": [spec.check_id for spec in plugin_specs],
            },
        )
        for problem in plugin_problems:
            await ctx.emit("analyzing", "warning", f"Plugin ignored: {problem}", progress=62)
        span = 23
        budget_reported = False
        for index, check_cls in enumerate(classes):
            if cancel_check is not None and cancel_check():
                raise ScanCancelled("scan cancelled by operator")
            check = check_cls()
            progress = 62 if not classes else 62 + int(span * index / len(classes))
            await ctx.emit(
                "analyzing",
                "check_started",
                check.name,
                progress=progress,
                payload={"check_id": check.id},
            )
            try:
                produced = await check.run(ctx)
            except ScanCancelled:
                raise
            except BudgetExceeded:
                # Request-based checks stop touching the network, but checks that
                # only read collected artifacts must still run.
                if not budget_reported:
                    budget_reported = True
                    await ctx.emit(
                        "analyzing", "warning", "Request budget reached", progress=progress
                    )
                continue
            except Exception as exc:
                await ctx.emit(
                    "analyzing",
                    "check_failed",
                    f"{check.name} failed: {exc}",
                    progress=progress,
                    payload={"check_id": check.id, "error": str(exc)[:300]},
                )
                continue
            for finding in produced:
                ctx.add_finding(finding)
            if produced:
                await ctx.emit(
                    "analyzing",
                    "findings",
                    f"{check.name}: {len(produced)} finding(s)",
                    progress=progress,
                    payload={
                        "check_id": check.id,
                        "findings": [
                            {
                                "check_id": f.check_id,
                                "title": f.title,
                                "severity": f.severity.value,
                                "url": f.url,
                            }
                            for f in produced
                        ],
                    },
                )
        if nuclei is not None and ctx.remaining_seconds > 8:
            await ctx.emit(
                "analyzing",
                "tool_started",
                "Running the operator-installed Nuclei binary",
                progress=85,
                payload={"severities": list(nuclei.severities), "rate_limit": nuclei.rate_limit},
            )
            try:
                external = await run_nuclei(nuclei, root.url, scope)
            except Exception as exc:  # a tool failure must not sink the scan
                ctx.artifacts["nuclei"] = {"enabled": True, "error": str(exc)[:300], "findings": 0}
                await ctx.emit(
                    "analyzing", "warning", f"Nuclei skipped: {str(exc)[:200]}", progress=85
                )
            else:
                for finding in external:
                    ctx.add_finding(finding)
                ctx.artifacts["nuclei"] = {
                    "enabled": True,
                    "error": "",
                    "findings": len(external),
                }
                await ctx.emit(
                    "analyzing",
                    "tool_finished",
                    f"Nuclei returned {len(external)} finding(s)",
                    progress=85,
                    payload={"findings": len(external)},
                )
        plugin_findings = 0
        for spec in plugin_specs:
            if plugin_findings >= 50 or ctx.remaining_seconds <= 3:
                await ctx.emit(
                    "analyzing",
                    "warning",
                    "Plugin time budget reached",
                    progress=85,
                )
                break
            if cancel_check is not None and cancel_check():
                raise ScanCancelled("scan cancelled by operator")
            await ctx.emit(
                "analyzing",
                "plugin_started",
                f"Isolated plugin: {spec.name}",
                progress=85,
                payload={"check_id": spec.check_id, "timeout": spec.timeout_seconds},
            )
            try:
                produced = await run_plugin(spec, plugin_payload(ctx), scope)
            except PluginError as exc:
                await ctx.emit(
                    "analyzing",
                    "plugin_failed",
                    str(exc)[:300],
                    progress=85,
                    payload={"check_id": spec.check_id},
                )
                continue
            for finding in produced:
                ctx.add_finding(finding)
            plugin_findings += len(produced)
            await ctx.emit(
                "analyzing",
                "plugin_finished",
                f"{spec.name}: {len(produced)} finding(s)",
                progress=85,
                payload={"check_id": spec.check_id, "findings": len(produced)},
            )
        ctx.artifacts["plugins"] = {
            "loaded": len(plugin_specs),
            "findings": plugin_findings,
            "problems": plugin_problems,
        }
        await ctx.emit("analyzing", "phase_finished", "Analysis complete", progress=85)

        await ctx.emit("verifying", "phase_started", "Verifying evidence", progress=88)
        verification = mark_verified(ctx.findings)
        ctx.artifacts["verification"] = verification
        message = (
            f"{verification['verified']} verified · {verification['suspected']} suspected"
            + (
                f" · {verification['downgraded']} downgraded for missing evidence"
                if verification["downgraded"]
                else ""
            )
        )
        await ctx.emit(
            "verifying", "phase_finished", message, progress=92, payload=verification
        )

        await ctx.emit(
            "correlating", "phase_started", "Normalizing and de-duplicating", progress=94
        )
        final = dedupe_findings(ctx.findings)
        await ctx.emit(
            "correlating",
            "phase_finished",
            f"{len(final)} unique finding(s)",
            progress=95,
            payload={"removed_duplicates": len(ctx.findings) - len(final)},
        )

        correlation = correlate_findings(final)
        final.sort(key=lambda f: (-f.risk_score, f.check_id, f.url))
        ctx.artifacts["correlation"] = correlation.as_dict()
        if correlation.chains:
            await ctx.emit(
                "correlating",
                "attack_paths",
                f"{len(correlation.chains)} attack path(s) correlated, "
                f"{correlation.boosted} finding(s) re-scored",
                progress=96,
                payload=ctx.artifacts["correlation"],
            )

        duration_ms = int((time.monotonic() - started) * 1000)
        tls_info = ctx.artifacts.get("tls")
        live_endpoints = sum(1 for endpoint in ctx.endpoints if endpoint.state == "live")
        result = ScanResult(
            findings=final,
            technologies=ctx.technologies,
            endpoints=ctx.endpoints,
            stats=ScanStats(
                requests=client.request_count,
                findings_total=len(final),
                endpoints=len(ctx.endpoints),
                endpoints_live=live_endpoints,
                endpoints_unverified=len(ctx.endpoints) - live_endpoints,
                technologies=len(ctx.technologies),
                duration_ms=duration_ms,
            ),
            recon={
                "dns": ctx.artifacts.get("dns", {}),
                "ip_intel": ctx.artifacts.get("ip_intel", {}),
                "tls": asdict(tls_info) if tls_info is not None else {},
                "waf": ctx.artifacts.get("waf", {}),
                "robots": ctx.artifacts.get("robots", {}),
                "subdomains": ctx.artifacts.get("subdomains", {}),
                "whois": ctx.artifacts.get("whois", {}),
                "history": ctx.artifacts.get("history", {}),
                "exposure": ctx.artifacts.get("exposure", []),
                "neighbours": ctx.artifacts.get("neighbours", {}),
                "crawl": crawl_report.as_dict(),
                "js_intel": ctx.artifacts.get("js_intel", {}),
                "endpoint_intel": cluster_endpoints(ctx.endpoints),
                "dirs": ctx.artifacts.get("dirs", {"probed": 0, "found": 0, "paths": []}),
                "endpoint_verification": ctx.artifacts.get(
                    "endpoint_verification", {"probed": 0, "verified": 0}
                ),
                "surface": ctx.artifacts.get("surface", {}),
                "auth_map": ctx.artifacts.get("auth_map", {"flows": [], "count": 0}),
                "bola_matrix": ctx.artifacts.get(
                    "bola_matrix", {"candidates": [], "count": 0, "roles": []}
                ),
                "api": ctx.artifacts.get("openapi", {}),
                "api_intel": ctx.artifacts.get("api_intel", {}),
                "verification": ctx.artifacts.get(
                    "verification", {"verified": 0, "suspected": 0, "rejected": 0, "downgraded": 0}
                ),
                "nuclei": ctx.artifacts.get("nuclei", {"enabled": False}),
                "plugins": ctx.artifacts.get("plugins", {"loaded": 0, "findings": 0}),
                "spa": ctx.artifacts.get("spa", {"enabled": False}),
                "correlation": ctx.artifacts.get("correlation", {"chains": []}),
            },
        )
        await ctx.emit(
            "reporting",
            "scan_completed",
            f"Scan finished with {len(final)} finding(s) in {duration_ms / 1000:.1f}s",
            progress=100,
            payload={"stats": result.stats.model_dump(mode="json")},
        )
        return result


__all__ = ["run_scan"]
