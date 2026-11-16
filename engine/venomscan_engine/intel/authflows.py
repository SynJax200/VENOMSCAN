from __future__ import annotations

import re
from collections import Counter
from urllib.parse import urlsplit

from venomscan_engine.models import EndpointRecord

MAX_FLOWS = 40

# Ordered so specific flows win over the generic token/authorize match.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("login", re.compile(r"/(?:log-?in|sign-?in|session/new|auth/login)(?:/|$)", re.I)),
    ("logout", re.compile(r"/(?:log-?out|sign-?out|session/delete)(?:/|$)", re.I)),
    (
        "register",
        re.compile(r"/(?:register|sign-?up|create-account|users/new)(?:/|$)", re.I),
    ),
    (
        "password_reset",
        re.compile(r"/(?:forgot|reset|recover|change)[-_]?(?:password|credentials)(?:/|$)", re.I),
    ),
    ("mfa", re.compile(r"/(?:mfa|2fa|otp|totp|verify)(?:/|$)", re.I)),
    (
        "token",
        re.compile(r"/(?:token|oauth|oauth2|authorize|refresh|jwks)(?:/|$)", re.I),
    ),
    ("session", re.compile(r"/(?:session|sessions|auth|authenticate|sso)(?:/|$)", re.I)),
)


def classify_path(url: str) -> str | None:
    path = urlsplit(url).path or "/"
    for flow_type, pattern in _PATTERNS:
        if pattern.search(path):
            return flow_type
    return None


def build_auth_map(endpoints: list[EndpointRecord]) -> dict:
    """Classify authentication flows from discovered endpoints; no traffic is generated."""
    flows: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for endpoint in endpoints:
        flow_type = classify_path(endpoint.url)
        if flow_type is None:
            continue
        key = (flow_type, endpoint.url)
        if key in seen:
            continue
        seen.add(key)
        flows.append(
            {
                "type": flow_type,
                "method": endpoint.method.upper(),
                "url": endpoint.url,
                "state": endpoint.state,
                "source": endpoint.source,
                "status_code": endpoint.status_code,
            }
        )
    flows.sort(key=lambda item: (item["type"], item["url"]))
    counts = Counter(flow["type"] for flow in flows)
    live = sum(1 for flow in flows if flow["state"] == "live")
    return {
        "flows": flows[:MAX_FLOWS],
        "count": len(flows),
        "live": live,
        "types": dict(sorted(counts.items())),
        "summary": (
            f"{len(flows)} authentication flow endpoint(s) classified, {live} with a live response"
        ),
    }


__all__ = ["MAX_FLOWS", "build_auth_map", "classify_path"]
