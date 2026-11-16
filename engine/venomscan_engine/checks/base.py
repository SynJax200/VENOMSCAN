from __future__ import annotations

from typing import ClassVar, Protocol

from venomscan_engine.context import ScanContext
from venomscan_engine.models import Finding, Severity
from venomscan_engine.safety.http import ResponseBundle

_CHALLENGE_HEADERS = (
    "x-vercel-challenge-token",
    "x-vercel-mitigated",
    "cf-mitigated",
    "x-amzn-waf-action",
    "x-datadome",
)

_CHALLENGE_MARKERS = (
    "just a moment",
    "checking your browser",
    "verify you are human",
    "cf-challenge",
    "pardon our interruption",
    "_incapsula_resource",
    "enable javascript and cookies to continue",
)


def is_interstitial(bundle: ResponseBundle | None) -> bool:
    """True when the response is an edge/WAF challenge, not the site itself.

    Config findings read from a challenge page describe the block page, not the
    application, so callers skip them instead of reporting false positives.
    """
    if bundle is None:
        return False
    if bundle.status_code == 429:
        return True
    if any(bundle.header(name) for name in _CHALLENGE_HEADERS):
        return True
    if bundle.status_code >= 400:
        body = bundle.body[:4000].lower()
        return any(marker in body for marker in _CHALLENGE_MARKERS)
    return False


class Check(Protocol):
    id: ClassVar[str]
    name: ClassVar[str]
    category: ClassVar[str]
    default_severity: ClassVar[Severity]
    profile: ClassVar[str]

    async def run(self, ctx: ScanContext) -> list[Finding]: ...


def request_evidence(ctx: ScanContext, method: str = "GET") -> dict:
    return {"method": method, "url": ctx.target_url}


def response_evidence(ctx: ScanContext) -> dict:
    return ctx.root.evidence() if ctx.root is not None else {}
