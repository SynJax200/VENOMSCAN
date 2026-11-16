from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit

from venomscan_engine.ai import fallback
from venomscan_engine.ai.features import AnalysisResult
from venomscan_engine.ai.grounding import GroundingError, GroundingValidator
from venomscan_engine.ai.prompts import PROMPT_VERSION, build_messages
from venomscan_engine.ai.provider import LLMProvider
from venomscan_engine.ai.retrieval import retrieve
from venomscan_engine.ai.schemas import SCHEMAS, AnswerPayload

_URL = re.compile(r"https?://[^\s\"'<>)\]]+")
_UNSAFE_INTENT = re.compile(
    r"(?i)\b(scan|pentest|attack|hack|exploit|brute[ -]?force)\b[^.\n]{0,80}"
    r"\b(another|other|external|different|new)\b"
)
_INJECTION = re.compile(
    r"(?i)(ignore\s+(all\s+|your\s+)?(previous|prior|above)|disregard\s+your|"
    r"system\s+prompt|you\s+are\s+now|reveal\s+your\s+instructions)"
)

REFUSAL = (
    "I can only answer questions about the authorized scan data provided here. "
    "I cannot scan or analyze other targets, and I ignore instructions embedded in scan data."
)


def out_of_scope(question: str, allowed_hosts: Iterable[str]) -> bool:
    hosts = {host.lower().split(":")[0] for host in allowed_hosts if host}
    if _UNSAFE_INTENT.search(question) or _INJECTION.search(question):
        return True
    for url in _URL.findall(question):
        host = (urlsplit(url).hostname or "").lower()
        if host and host not in hosts:
            return True
    return False


async def answer(
    question: str,
    context: dict[str, Any],
    *,
    provider: LLMProvider | None = None,
    allowed_hosts: Iterable[str] = (),
    allowed_urls: Iterable[str] = (),
    allowed_cves: Iterable[str] = (),
    allowed_refs: Iterable[str] = (),
    max_tokens: int = 900,
    provider_name: str = "fallback",
    model_name: str = "deterministic",
) -> AnalysisResult:
    """Grounded question answering over one scan. No tools, no new target traffic."""
    if out_of_scope(question, allowed_hosts):
        return AnalysisResult(
            kind="assistant",
            payload=AnswerPayload(answer=REFUSAL, evidence_refs=[]),
            provider="policy",
            model="deterministic",
            prompt_version=PROMPT_VERSION,
            grounded=True,
            fallback=True,
            refused=True,
        )

    base_refs = list(dict.fromkeys([*(context.get("refs") or []), *allowed_refs]))
    retrieved = retrieve(question, {**context, "refs": base_refs})
    context = {
        **retrieved.context,
        "question": question,
        "refs": retrieved.refs or base_refs,
    }
    allowed_urls = set(allowed_urls) | retrieved.urls
    allowed_refs = context["refs"]
    deterministic = fallback.assistant_answer(context, question)
    result = AnalysisResult(
        kind="assistant",
        payload=deterministic,
        provider=provider_name,
        model=model_name,
        prompt_version=PROMPT_VERSION,
        grounded=True,
        fallback=True,
    )
    if provider is None:
        return result

    system, user = build_messages("assistant", context)
    try:
        candidate = await provider.complete(
            system=system, user=user, schema=SCHEMAS["assistant"], max_tokens=max_tokens
        )
        if not isinstance(candidate, AnswerPayload):
            raise GroundingError("provider returned an unstructured payload")
        GroundingValidator(allowed_urls, allowed_cves, allowed_refs).validate(candidate)
    except Exception as exc:  # noqa: BLE001 - deterministic answer must always be reachable
        result.provider_error = (str(exc) or exc.__class__.__name__)[:300]
        return result
    return AnalysisResult(
        kind="assistant",
        payload=candidate,
        provider=getattr(provider, "name", provider_name),
        model=getattr(provider, "model", model_name),
        prompt_version=PROMPT_VERSION,
        grounded=True,
        fallback=False,
    )
