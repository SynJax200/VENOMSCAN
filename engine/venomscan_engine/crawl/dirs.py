from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from venomscan_engine.context import ScanContext
from venomscan_engine.models import EndpointRecord
from venomscan_engine.safety.http import (
    BudgetExceeded,
    ResponseBundle,
    TargetUnreachable,
    TooManyRedirects,
)
from venomscan_engine.safety.scope import ScopeViolation

# Curated read-only GET wordlist. Every entry is safe to request repeatedly:
# no state-changing verbs, no destructive payloads. Ordered by value density so
# small probe budgets still hit configuration, admin and API surfaces first.
WORDLIST: tuple[str, ...] = (
    "/.well-known/security.txt",
    "/security.txt",
    "/.env",
    "/.git/HEAD",
    "/admin",
    "/admin/",
    "/administrator",
    "/login",
    "/signin",
    "/dashboard",
    "/console",
    "/panel",
    "/manage",
    "/internal",
    "/cpanel",
    "/phpmyadmin",
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/docs",
    "/docs",
    "/swagger",
    "/swagger-ui",
    "/graphql",
    "/graphiql",
    "/health",
    "/healthz",
    "/readyz",
    "/metrics",
    "/status",
    "/ping",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/server-status",
    "/server-info",
    "/debug",
    "/trace",
    "/info",
    "/.git/config",
    "/.env.local",
    "/.env.production",
    "/.svn/entries",
    "/.DS_Store",
    "/.htaccess",
    "/.htpasswd",
    "/backup",
    "/backups",
    "/backup.zip",
    "/backup.tar.gz",
    "/db.sql",
    "/database.sql",
    "/dump.sql",
    "/config",
    "/config.json",
    "/config.php",
    "/configuration.php",
    "/settings.php",
    "/wp-config.php",
    "/web.config",
    "/appsettings.json",
    "/nginx.conf",
    "/phpinfo.php",
    "/info.php",
    "/signup",
    "/register",
    "/staff",
    "/backoffice",
    "/manager",
    "/adminer.php",
    "/api/swagger",
    "/api-docs",
    "/redoc",
    "/livez",
    "/actuator/info",
    "/console/login",
    "/old",
    "/dev",
    "/test",
    "/staging",
    "/prod",
    "/user",
    "/users",
    "/account",
    "/profile",
    "/settings",
    "/upload",
    "/uploads",
    "/files",
    "/download",
    "/downloads",
    "/export",
    "/exports",
    "/logs",
    "/log",
    "/tmp",
    "/temp",
    "/private",
    "/secrets",
    "/keys",
    "/jwt",
    "/oauth",
    "/auth",
    "/authorize",
    "/token",
    "/sso",
    "/wp-admin",
    "/wp-login.php",
    "/wp-json",
    "/xmlrpc.php",
    "/blog",
    "/jira",
    "/confluence",
    "/jenkins",
    "/gitlab",
    "/grafana",
    "/kibana",
    "/prometheus",
    "/portainer",
    "/sonar",
    "/nexus",
    "/artifactory",
    "/portal",
    "/intranet",
    "/extranet",
    "/vpn",
    "/mail",
    "/webmail",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/robots.txt",
    "/sitemap.xml",
    "/favicon.ico",
    "/trace.axd",
    "/elmah.axd",
    "/.dockerignore",
    "/docker-compose.yml",
    "/Dockerfile",
    "/composer.json",
    "/package.json",
    "/yarn.lock",
)

PROFILE_PROBES: dict[str, int] = {"passive": 0, "safe": 24, "active": 40}
MAX_DISCOVERIES = 20
MAX_WARNINGS = 3
MAX_FINGERPRINT_BYTES = 4_000
_FOUND_STATUSES = frozenset({200, 204, 301, 302, 303, 307, 308, 401, 403})


@dataclass
class DirReport:
    probed: int = 0
    found: int = 0
    paths: list[str] = field(default_factory=list)
    soft_404: bool = False
    stopped: str = ""
    warnings: int = 0

    def summary(self) -> str:
        if self.stopped and not self.found:
            return f"Directory probe stopped: {self.stopped}"
        text = f"{self.found} path(s) discovered from {self.probed} probe(s)"
        if self.soft_404:
            text += " · soft-404 filtered"
        if self.stopped:
            text += f" · stopped: {self.stopped}"
        return text

    def as_dict(self) -> dict:
        return {
            "probed": self.probed,
            "found": self.found,
            "paths": self.paths,
            "soft_404": self.soft_404,
            "stopped": self.stopped or None,
            "warnings": self.warnings,
        }


def _robots_blocked(path: str, disallows: list[str]) -> bool:
    target = "/" + path.lstrip("/")
    for pattern in disallows:
        cleaned = pattern.strip()
        if not cleaned or cleaned == "/":
            continue
        prefix = cleaned.rstrip("$").split("*", 1)[0]
        if prefix and target.startswith(prefix):
            return True
    return False


def _fingerprint(bundle: ResponseBundle) -> tuple[int, str]:
    normalized = "".join((bundle.body or "").split())[:MAX_FINGERPRINT_BYTES]
    digest = hashlib.sha1(normalized.encode("utf-8", "replace")).hexdigest()
    return bundle.status_code, digest


def _same_as_baseline(bundle: ResponseBundle, baseline: ResponseBundle) -> bool:
    if _fingerprint(bundle) == _fingerprint(baseline):
        return True
    if baseline.status_code in {301, 302, 303, 307, 308} and bundle.status_code == baseline.status_code:
        location = (bundle.header("location") or "").rstrip("/")
        baseline_location = (baseline.header("location") or "").rstrip("/")
        return bool(location) and location == baseline_location
    return False


async def _fetch(ctx: ScanContext, url: str, report: DirReport) -> ResponseBundle | None:
    try:
        return await ctx.client.get(url)
    except BudgetExceeded:
        report.stopped = "request-budget"
        return None
    except (TargetUnreachable, TooManyRedirects, ScopeViolation) as exc:
        if report.warnings < MAX_WARNINGS:
            report.warnings += 1
            await ctx.emit("crawling", "warning", f"Directory probe skipped: {str(exc)[:160]}")
        return None


async def discover_paths(
    ctx: ScanContext,
    *,
    max_probes: int = 24,
    budget_seconds: float = 25.0,
) -> DirReport:
    """Probe a curated GET wordlist without leaving scope, robots or the budget."""

    report = DirReport()
    root = ctx.root
    if root is None or max_probes <= 0:
        report.stopped = "disabled"
        return report
    budget = min(budget_seconds, max(ctx.remaining_seconds - 5.0, 0.0))
    if budget < 4:
        report.stopped = "time-budget"
        return report

    parts = urlsplit(ctx.target_url)
    origin = f"{parts.scheme}://{parts.netloc}"
    disallows = list(ctx.artifacts.get("robots", {}).get("disallow", []))
    visited = {endpoint.url for endpoint in ctx.endpoints}

    baseline = await _fetch(ctx, urljoin(origin, f"/_venomscan-{secrets.token_hex(4)}"), report)
    if baseline is None and report.stopped:
        return report
    report.soft_404 = baseline is not None and baseline.status_code in {200, 204}

    import time

    deadline = time.monotonic() + budget
    for path in WORDLIST:
        if report.probed >= max_probes or report.found >= MAX_DISCOVERIES:
            break
        if time.monotonic() >= deadline or ctx.remaining_seconds < 4:
            report.stopped = report.stopped or "time-budget"
            break
        url = urljoin(origin, path)
        if url in visited:
            continue
        if _robots_blocked(path, disallows):
            continue
        bundle = await _fetch(ctx, url, report)
        if bundle is None:
            if report.stopped == "request-budget":
                break
            continue
        report.probed += 1
        visited.add(url)
        if bundle.status_code not in _FOUND_STATUSES:
            continue
        if baseline is not None and _same_as_baseline(bundle, baseline):
            continue
        report.found += 1
        report.paths.append(urlsplit(bundle.url).path or path)
        ctx.add_endpoint(
            EndpointRecord(
                url=bundle.url,
                method="GET",
                source="dirs",
                status_code=bundle.status_code,
                content_type=bundle.header("content-type"),
                depth=1,
            )
        )
    return report


__all__ = ["DirReport", "PROFILE_PROBES", "WORDLIST", "discover_paths"]
