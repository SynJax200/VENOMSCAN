from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from venomscan_engine.ai.provider import LLMError
from venomscan_engine.ai.providers._http import post_json
from venomscan_engine.ai.providers._json import validate_payload


@dataclass(slots=True)
class OpenAICompatProvider:
    """Any server exposing the OpenAI /chat/completions contract."""

    model: str
    base_url: str = "https://api.openai.com/v1"
    api_key: str = ""
    timeout: float = 30.0
    transport: Any = None
    retries: int = 1
    allow_private: bool = False
    name: str = "openai_compat"

    async def complete(
        self,
        *,
        system: str,
        user: str,
        schema: type[BaseModel],
        max_tokens: int = 900,
    ) -> BaseModel:
        body = {
            "model": self.model,
            "temperature": 0.2,
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        url = f"{self.base_url.rstrip('/')}/chat/completions"
        response = await post_json(
            url,
            headers=headers,
            body=body,
            timeout_seconds=self.timeout,
            transport=self.transport,
            retries=self.retries,
            pin_public=not self.allow_private,
        )
        try:
            content = response.json()["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise LLMError("provider response shape was not OpenAI-compatible") from exc
        return validate_payload(schema, content if isinstance(content, str) else str(content))
