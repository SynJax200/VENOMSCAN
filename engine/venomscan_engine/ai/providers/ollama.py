from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from venomscan_engine.ai.provider import LLMError
from venomscan_engine.ai.providers._http import post_json
from venomscan_engine.ai.providers._json import validate_payload


@dataclass(slots=True)
class OllamaProvider:
    """Local Ollama server; no credentials leave the deployment."""

    model: str
    base_url: str = "http://127.0.0.1:11434"
    timeout: float = 60.0
    transport: Any = None
    retries: int = 1
    name: str = "ollama"

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
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.2, "num_predict": max_tokens},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        url = f"{self.base_url.rstrip('/')}/api/chat"
        response = await post_json(
            url,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            body=body,
            timeout_seconds=self.timeout,
            transport=self.transport,
            retries=self.retries,
        )
        try:
            content = response.json()["message"]["content"]
        except (ValueError, KeyError, TypeError) as exc:
            raise LLMError("provider response shape was not Ollama-compatible") from exc
        return validate_payload(schema, content if isinstance(content, str) else str(content))
