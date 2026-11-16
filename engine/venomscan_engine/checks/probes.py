"""Shared helpers for active, consent-gated probe checks.

Every helper keeps probes read-only, same-scope and deterministic so the same
target produces the same payload (and therefore the same dedup key) across
scans.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit

from venomscan_engine.context import ScanContext
from venomscan_engine.safety.http import (
    ResponseBundle,
    TargetUnreachable,
    TooManyRedirects,
)

_SKIP_PARAMS = {
    "csrf",
    "csrf_token",
    "_csrf",
    "token",
    "_token",
    "authenticity_token",
    "password",
    "passwd",
    "email",
}
_SKIP_PATHS = re.compile(
    r"(?i)(logout|signout|delete|remove|unsubscribe|checkout|purchase|pay|subscribe)"
)


@dataclass(frozen=True)
class ProbePoint:
    url: str
    parameter: str


def canary(ctx: ScanContext, check_id: str, parameter: str) -> str:
    raw = f"{ctx.target_url}|{check_id}|{parameter}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:8]


def probe_points(
    ctx: ScanContext,
    limit: int,
    preferred: tuple[str, ...] = (),
    accept: Callable[[str, str], bool] | None = None,
) -> list[ProbePoint]:
    """One query parameter per same-scope GET endpoint, capped at `limit`."""
    points: list[ProbePoint] = []
    seen: set[tuple[str, str, str, str]] = set()
    for endpoint in ctx.endpoints:
        if len(points) >= limit:
            break
        if endpoint.method != "GET" or endpoint.state != "live":
            continue
        parts = urlsplit(endpoint.url)
        if parts.hostname not in ctx.scope.hosts or _SKIP_PATHS.search(parts.path):
            continue
        pairs = [
            (name, value)
            for name, value in parse_qsl(parts.query, keep_blank_values=True)
            if name.lower() not in _SKIP_PARAMS
        ]
        if not pairs:
            continue
        names = [name for name, _ in pairs]
        if preferred:
            names.sort(key=lambda name: not any(word in name.lower() for word in preferred))
        chosen = None
        for name in names:
            current = next(value for candidate, value in pairs if candidate == name)
            if accept is not None and not accept(name, current):
                continue
            chosen = name
            break
        if chosen is None:
            continue
        key = (parts.scheme, parts.netloc, parts.path, chosen)
        if key in seen:
            continue
        seen.add(key)
        points.append(ProbePoint(url=endpoint.url, parameter=chosen))
    return points


def with_value(point: ProbePoint, value: str) -> str:
    parts = urlsplit(point.url)
    pairs = [
        (name, value if name == point.parameter else current)
        for name, current in parse_qsl(parts.query, keep_blank_values=True)
    ]
    return parts._replace(query=urlencode(pairs, doseq=True)).geturl()


def is_html(response: ResponseBundle) -> bool:
    return "html" in (response.header("content-type") or "").lower()


_BLOCK_MARKERS = re.compile(
    r"(?i)(request blocked|access denied|attention required|are you a robot|captcha|"
    r"mod_security|web application firewall|cloudflare ray id)"
)


def looks_blocked(response: ResponseBundle) -> bool:
    """WAF/challenge pages echo payloads without executing them; never confirm from one."""
    if response.status_code in {403, 406, 429}:
        return True
    return bool(_BLOCK_MARKERS.search(response.body[:4000]))


async def get_probe(ctx: ScanContext, point: ProbePoint, value: str) -> ResponseBundle | None:
    if ctx.client is None or ctx.remaining_seconds < 3:
        return None
    try:
        return await ctx.client.get(with_value(point, value))
    except (TargetUnreachable, TooManyRedirects):
        return None
