from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel, ValidationError

from venomscan_engine.ai.provider import LLMError

_FENCE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.IGNORECASE)


def parse_json_object(text: str) -> dict[str, Any]:
    raw = _FENCE.sub("", text or "").strip()
    if not raw:
        raise LLMError("provider returned an empty response")
    start, end = raw.find("{"), raw.rfind("}")
    if start == -1 or end <= start:
        raise LLMError("provider response contained no JSON object")
    try:
        data = json.loads(raw[start : end + 1])
    except json.JSONDecodeError as exc:
        raise LLMError(f"provider returned invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise LLMError("provider returned a JSON value that is not an object")
    return data


def validate_payload(schema: type[BaseModel], text: str) -> BaseModel:
    data = parse_json_object(text)
    try:
        return schema.model_validate(data)
    except ValidationError as exc:
        raise LLMError(f"provider response did not match the schema: {exc.error_count()} issue(s)") from exc
