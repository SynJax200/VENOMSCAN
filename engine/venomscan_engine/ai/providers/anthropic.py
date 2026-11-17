from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from venomscan_engine.ai.provider import LLMError
from venomscan_engine.ai.providers._http import post_json
from venomscan_engine.ai.providers._json import validate_payload


@dataclass(slots=True)
class AnthropicProvider:
    model: str
    base_url: str = "https://api.anthropic.com"
    api_key: str = ""
    timeout: float = 30.0
    transport: Any = None
    retries: int = 1
    allow_private: bool = False
    name: str = "anthropic"

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
            "max_tokens": max_tokens,
            "temperature": 0.2,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }
        url = f"{self.base_url.rstrip('/')}/v1/messages"
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
            blocks = response.json()["content"]
            text = "".join(block["text"] for block in blocks if block.get("type") == "text")
        except (ValueError, KeyError, TypeError) as exc:
            raise LLMError("provider response shape was not Anthropic-compatible") from exc
        return validate_payload(schema, text)
