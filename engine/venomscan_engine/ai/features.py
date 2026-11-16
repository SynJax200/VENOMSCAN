from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from venomscan_engine.ai import fallback
from venomscan_engine.ai.grounding import GroundingError, GroundingValidator
from venomscan_engine.ai.prompts import PROMPT_VERSION, build_messages
from venomscan_engine.ai.provider import LLMProvider
from venomscan_engine.ai.schemas import SCHEMAS

FALLBACKS = {
    "explanation": fallback.explanation,
    "fp_review": fallback.fp_review,
    "summary": fallback.summary,
    "prioritize": fallback.prioritize,
    "surface_summary": fallback.surface_summary,
    "remediation": fallback.remediation,
    "correlate": fallback.correlate,
    "education": fallback.education,
    "endpoint_prioritize": fallback.endpoint_prioritize,
    "next_steps": fallback.next_steps,
    "js_analysis": fallback.js_analysis,
    "api_analysis": fallback.api_analysis,
    "fp_triage": fallback.fp_triage,
}


@dataclass(slots=True)
class AnalysisResult:
    kind: str
    payload: BaseModel
    provider: str
    model: str
    prompt_version: str
    grounded: bool
    fallback: bool
    provider_error: str = ""
    refused: bool = False


def check_contract(kind: str, payload: BaseModel, context: dict[str, Any]) -> None:
    """Deterministic consistency rules the model must satisfy for the scan data."""
    if kind == "fp_review":
        status = (context.get("finding") or {}).get("verification_status")
        likelihood = float(getattr(payload, "fp_likelihood", 0.0))
        if status == "verified" and likelihood > 0.5:
            raise GroundingError("verified finding cannot be flagged as a likely false positive")
        if status == "rejected" and likelihood < 0.5:
            raise GroundingError("rejected finding must carry a high false-positive likelihood")
    elif kind == "prioritize":
        known = {
            str(finding.get("id")): str(finding.get("title", "")).strip()
            for finding in context.get("findings") or []
            if finding.get("id")
        }
        order = getattr(payload, "order", [])
        if known and not order:
            raise GroundingError("prioritization omitted every finding in the scan")
        seen: set[str] = set()
        for item in order:
            finding_id = str(item.finding_id)
            if finding_id not in known:
                raise GroundingError(f"unknown finding in prioritization: {finding_id}")
            if finding_id in seen:
                raise GroundingError(f"duplicate finding in prioritization: {finding_id}")
            seen.add(finding_id)
            if item.title.strip() != known[finding_id]:
                raise GroundingError(f"title mismatch for finding {finding_id}")
    elif kind == "remediation":
        if not getattr(payload, "steps", []):
            raise GroundingError("remediation returned no actionable steps")
    elif kind == "endpoint_prioritize":
        known = {str(e.get("url")) for e in context.get("endpoints") or [] if e.get("url")}
        order = getattr(payload, "order", [])
        if known and not order:
            raise GroundingError("endpoint prioritization omitted every endpoint")
        seen: set[str] = set()
        for item in order:
            url = str(item.url)
            if known and url not in known:
                raise GroundingError(f"unknown endpoint in prioritization: {url}")
            if url in seen:
                raise GroundingError(f"duplicate endpoint in prioritization: {url}")
            seen.add(url)
    elif kind == "next_steps":
        if (context.get("findings") or []) and not getattr(payload, "steps", []):
            raise GroundingError("next steps omitted every finding")
    elif kind == "js_analysis":
        known = {str(e.get("url")) for e in context.get("endpoints") or [] if e.get("url")}
        for route in getattr(payload, "routes", []):
            if known and str(route.url) not in known:
                raise GroundingError(f"unknown JavaScript route: {route.url}")
    elif kind == "fp_triage":
        findings = {
            str(f.get("id")): f for f in context.get("findings") or [] if f.get("id")
        }
        seen: set[str] = set()
        for review in getattr(payload, "reviews", []):
            finding_id = str(review.finding_id)
            if finding_id not in findings:
                raise GroundingError(f"unknown finding in triage: {finding_id}")
            if finding_id in seen:
                raise GroundingError(f"duplicate finding in triage: {finding_id}")
            seen.add(finding_id)
            finding = findings[finding_id]
            status = str(finding.get("verification_status", "suspected"))
            likelihood = float(review.fp_likelihood)
            if status == "verified" and likelihood > 0.5:
                raise GroundingError("verified finding cannot be triaged as likely false positive")
            if status == "rejected" and likelihood < 0.5:
                raise GroundingError("rejected finding must carry a high false-positive likelihood")
            if review.recommendation not in {"keep", "review", "dismiss"}:
                raise GroundingError(f"unknown triage recommendation: {review.recommendation}")


async def analyze(
    kind: str,
    context: dict[str, Any],
    *,
    provider: LLMProvider | None = None,
    allowed_urls: Iterable[str] = (),
    allowed_cves: Iterable[str] = (),
    allowed_refs: Iterable[str] = (),
    max_tokens: int = 900,
    provider_name: str = "fallback",
    model_name: str = "deterministic",
) -> AnalysisResult:
    """Run one AI feature. Never raises: degrades to the deterministic fallback."""
    if kind not in FALLBACKS:
        raise ValueError(f"unknown AI kind {kind!r}")

    deterministic = FALLBACKS[kind](context).model_dump()  # type: ignore[operator]
    payload = SCHEMAS[kind].model_validate(deterministic)
    base = AnalysisResult(
        kind=kind,
        payload=payload,
        provider=provider_name,
        model=model_name,
        prompt_version=PROMPT_VERSION,
        grounded=True,
        fallback=True,
    )
    if provider is None:
        return base

    system, user = build_messages(kind, context)
    try:
        candidate = await provider.complete(
            system=system, user=user, schema=SCHEMAS[kind], max_tokens=max_tokens
        )
        if not isinstance(candidate, BaseModel):
            raise GroundingError("provider returned an unstructured payload")
        GroundingValidator(allowed_urls, allowed_cves, allowed_refs).validate(candidate)
        check_contract(kind, candidate, context)
    except Exception as exc:  # noqa: BLE001 - fallback must always be reachable
        message = str(exc) or exc.__class__.__name__
        return AnalysisResult(
            kind=kind,
            payload=base.payload,
            provider=getattr(provider, "name", provider_name),
            model=getattr(provider, "model", model_name),
            prompt_version=PROMPT_VERSION,
            grounded=True,
            fallback=True,
            provider_error=message[:300],
        )
    return AnalysisResult(
        kind=kind,
        payload=candidate,
        provider=getattr(provider, "name", provider_name),
        model=getattr(provider, "model", model_name),
        prompt_version=PROMPT_VERSION,
        grounded=True,
        fallback=False,
    )
