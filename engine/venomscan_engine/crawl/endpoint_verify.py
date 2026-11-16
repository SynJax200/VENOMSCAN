from __future__ import annotations

import hashlib
import re
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from venomscan_engine.context import ScanContext
from venomscan_engine.safety.http import (
    BudgetExceeded,
    ResponseBundle,
    TargetUnreachable,
    TooManyRedirects,
)
from venomscan_engine.safety.scope import ScopeViolation

# A bounded read-only pass over routes recovered from JavaScript/SPA capture.
# Unknown routes stay unverified; only a real response promotes them to live.
PROFILE_VERIFY: dict[str, int] = {"passive": 0, "safe": 12, "active": 20}
VERIFIED_SOURCES = frozenset({"js", "spa"})
FOUND_STATUSES = frozenset({200, 204, 301, 302, 303, 307, 308, 401, 403})
MAX_WARNINGS = 3
_FINGERPRINT_BYTES = 4_000
_SKIP_ASSET = re.compile(
    r"\.(?:js|mjs|css|map|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|webp|avif|mp4|webm)$",
    re.IGNORECASE,
)


@dataclass
class EndpointVerifyReport:
    candidates: int = 0
    probed: int = 0
    verified: int = 0
    not_found: int = 0
    skipped: int = 0
    soft_404: bool = False
    stopped: str = ""
    warnings: int = 0

    def summary(self) -> str:
        if self.stopped and not self.probed:
            return f"Endpoint verification stopped: {self.stopped}"
        text = (
            f"{self.verified} endpoint(s) verified from {self.probed} probe(s); "
            f"{self.not_found} answered 404"
        )
        if self.soft_404:
            text += " · soft-404 filtered"
        if self.stopped:
            text += f" · stopped: {self.stopped}"
        return text

    def as_dict(self) -> dict:
        return {
            "candidates": self.candidates,
            "probed": self.probed,
            "verified": self.verified,
            "not_found": self.not_found,
            "skipped": self.skipped,
            "soft_404": self.soft_404,
            "stopped": self.stopped or None,
            "warnings": self.warnings,
        }


def _fingerprint(bundle: ResponseBundle) -> tuple[int, str]:
    normalized = "".join((bundle.body or "").split())[:_FINGERPRINT_BYTES]
    return bundle.status_code, hashlib.sha1(normalized.encode("utf-8", "replace")).hexdigest()


def _same_as_baseline(bundle: ResponseBundle, baseline: ResponseBundle) -> bool:
    return _fingerprint(bundle) == _fingerprint(baseline)


def is_verifiable(url: str, method: str, status_code: int | None, source: str) -> bool:
    if status_code is not None or method.upper() != "GET":
        return False
    if source not in VERIFIED_SOURCES:
        return False
    parts = urlsplit(url)
    if parts.query:
        return False
    return not _SKIP_ASSET.search(parts.path)


async def _fetch(
    ctx: ScanContext, url: str, report: EndpointVerifyReport
) -> ResponseBundle | None:
    try:
        return await ctx.client.get(url)
    except BudgetExceeded:
        report.stopped = "request-budget"
        return None
    except (TargetUnreachable, TooManyRedirects, ScopeViolation) as exc:
        if report.warnings < MAX_WARNINGS:
            report.warnings += 1
            await ctx.emit("crawling", "warning", f"Endpoint probe skipped: {str(exc)[:160]}")
        return None


async def verify_endpoints(
    ctx: ScanContext,
    *,
    max_probes: int = 12,
    budget_seconds: float = 20.0,
) -> EndpointVerifyReport:
    """Attach real status/headers to JS-derived routes inside scope and budget."""

    report = EndpointVerifyReport()
    if ctx.root is None or max_probes <= 0:
        report.stopped = "disabled"
        return report
    candidates = [
        endpoint
        for endpoint in ctx.endpoints
        if is_verifiable(endpoint.url, endpoint.method, endpoint.status_code, endpoint.source)
    ]
    report.candidates = len(candidates)
    if not candidates:
        report.stopped = "no-candidates"
        return report
    budget = min(budget_seconds, max(ctx.remaining_seconds - 5.0, 0.0))
    if budget < 4:
        report.stopped = "time-budget"
        return report

    parts = urlsplit(ctx.target_url)
    origin = f"{parts.scheme}://{parts.netloc}"
    disallows = list(ctx.artifacts.get("robots", {}).get("disallow", []))
    baseline = await _fetch(ctx, urljoin(origin, f"/_venomscan-{secrets.token_hex(4)}"), report)
    if baseline is None and report.stopped:
        return report
    report.soft_404 = baseline is not None and baseline.status_code in {200, 204}

    deadline = time.monotonic() + budget
    for endpoint in candidates:
        if report.probed >= max_probes:
            report.stopped = report.stopped or "probe-cap"
            break
        if time.monotonic() >= deadline or ctx.remaining_seconds < 4:
            report.stopped = report.stopped or "time-budget"
            break
        path = urlsplit(endpoint.url).path or "/"
        blocked = [
            prefix
            for prefix in (
                str(item).strip().rstrip("$").split("*", 1)[0] for item in disallows if item
            )
            if prefix and prefix != "/"
        ]
        if any(path.startswith(prefix) for prefix in blocked):
            report.skipped += 1
            continue
        bundle = await _fetch(ctx, endpoint.url, report)
        if bundle is None:
            if report.stopped == "request-budget":
                break
            report.skipped += 1
            continue
        report.probed += 1
        if bundle.status_code == 404 or (
            baseline is not None and _same_as_baseline(bundle, baseline)
        ):
            report.not_found += 1
            continue
        if bundle.status_code not in FOUND_STATUSES:
            report.skipped += 1
            continue
        endpoint.status_code = bundle.status_code
        endpoint.content_type = bundle.header("content-type")
        if endpoint.depth == 0:
            endpoint.depth = 1
        report.verified += 1
    return report


__all__ = [
    "EndpointVerifyReport",
    "PROFILE_VERIFY",
    "is_verifiable",
    "verify_endpoints",
]
