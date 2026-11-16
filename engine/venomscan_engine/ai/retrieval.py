from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from venomscan_engine.ai.context import recon_refs, recon_urls, slice_digest, walk_strings

_SURFACE_QUESTION = re.compile(
    r"(?i)\b(api|endpoint|surface|route|path|crawl|url|graphql|js|javascript|bundle)\b"
)


def _tokens(text: str) -> set[str]:
    return {token for token in re.split(r"[^a-z0-9]+", (text or "").lower()) if len(token) >= 3}


def _hits(tokens: set[str], text: str) -> int:
    lowered = (text or "").lower()
    return sum(1 for token in tokens if token in lowered)


@dataclass(slots=True)
class Retrieved:
    context: dict[str, Any]
    refs: list[str] = field(default_factory=list)
    urls: set[str] = field(default_factory=set)


def _select_findings(
    tokens: set[str], findings: list[dict[str, Any]], limit: int
) -> list[dict[str, Any]]:
    if not findings:
        return []
    scored: list[tuple[int, float, dict[str, Any]]] = []
    for finding in findings:
        haystack = " ".join(
            str(finding.get(key, ""))
            for key in ("check_id", "title", "category", "severity", "url", "parameter")
        )
        score = _hits(tokens, haystack)
        risk = float(finding.get("risk_score") or 0)
        scored.append((score, risk, finding))
    matched = [item for item in scored if item[0] > 0]
    matched.sort(key=lambda item: (item[0], item[1]), reverse=True)
    chosen = [item[2] for item in matched[:limit]]
    if len(chosen) < min(4, len(findings)):
        chosen_ids = {id(item) for item in chosen}
        for _, _, finding in sorted(scored, key=lambda item: item[1], reverse=True):
            if id(finding) not in chosen_ids:
                chosen.append(finding)
            if len(chosen) >= min(4, len(findings)):
                break
    return chosen


def _select_endpoints(
    question: str, tokens: set[str], endpoints: list[dict[str, Any]], limit: int
) -> list[dict[str, Any]]:
    if not endpoints:
        return []
    scored = [
        (
            _hits(
                tokens,
                " ".join(
                    str(item.get(key, ""))
                    for key in ("url", "source", "method", "status_code")
                ),
            ),
            item,
        )
        for item in endpoints
    ]
    matched = sorted(
        (item for item in scored if item[0] > 0), key=lambda item: item[0], reverse=True
    )
    if matched:
        return [item[1] for item in matched[:limit]]
    if _SURFACE_QUESTION.search(question):
        return endpoints[:limit]
    return []


def _select_recon(
    tokens: set[str], digest: dict[str, Any], limit: int
) -> dict[str, Any]:
    if not digest:
        return {}
    scored: list[tuple[int, str]] = []
    for section, value in digest.items():
        haystack = section + " " + " ".join(walk_strings(value))
        scored.append((_hits(tokens, haystack), section))
    positive = [item for item in sorted(scored, key=lambda item: item[0], reverse=True) if item[0] > 0]
    sections = [section for _, section in positive[:limit]]
    if "verification" in digest and "verification" not in sections and len(sections) < limit:
        sections.append("verification")
    return slice_digest(digest, sections)


def retrieve(question: str, context: dict[str, Any], *, limit_findings: int = 8, limit_endpoints: int = 6, limit_recon: int = 4) -> Retrieved:
    """Pick the scan evidence that actually answers the question, bounded for the prompt."""
    tokens = _tokens(question)
    refs: list[str] = []
    for ref in context.get("refs") or []:
        if str(ref).startswith("scan:") and ref not in refs:
            refs.append(str(ref))

    findings = _select_findings(tokens, list(context.get("findings") or []), limit_findings)
    endpoints = _select_endpoints(question, tokens, list(context.get("endpoints") or []), limit_endpoints)
    digest = context.get("recon") if isinstance(context.get("recon"), dict) else {}
    recon = _select_recon(tokens, digest, limit_recon)

    allowed_refs = set(context.get("refs") or [])
    for finding in findings:
        ref = f"finding:{finding.get('id', '')}"
        if ref in allowed_refs and ref not in refs:
            refs.append(ref)
    urls: set[str] = set()
    for endpoint in endpoints:
        url = str(endpoint.get("url") or "")
        if not url:
            continue
        urls.add(url)
        ref = f"url:{url}"
        if ref in allowed_refs and ref not in refs:
            refs.append(ref)
    for ref in recon_refs(recon):
        if ref not in refs:
            refs.append(ref)
    urls |= recon_urls(recon)

    selected = dict(context)
    if "findings" in context:
        selected["findings"] = findings
    if "endpoints" in context:
        selected["endpoints"] = endpoints
    if recon:
        selected["recon"] = recon
    elif "recon" in context:
        selected.pop("recon", None)
    return Retrieved(context=selected, refs=refs, urls=urls)
