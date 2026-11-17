from __future__ import annotations

from typing import Any, Protocol, TypeVar

from pydantic import BaseModel

ModelT = TypeVar("ModelT", bound=BaseModel)


class LLMError(RuntimeError):
    """Raised when an LLM provider cannot produce a usable structured answer."""


class LLMProvider(Protocol):
    name: str
    model: str

    async def complete(
        self,
        *,
        system: str,
        user: str,
        schema: type[BaseModel],
        max_tokens: int = 900,
    ) -> BaseModel: ...


def build_provider(
    provider: str,
    *,
    model: str,
    base_url: str = "",
    api_key: str = "",
    timeout: float = 30.0,
    retries: int = 1,
    transport: Any = None,
    allow_private: bool = False,
) -> LLMProvider | None:
    """Return a provider instance, or None when the configuration cannot call out.

    Cloud providers require a key; Ollama is local and needs none. Returning None
    keeps scans running on the deterministic fallback path instead of failing.
    """
    from venomscan_engine.ai.providers.anthropic import AnthropicProvider
    from venomscan_engine.ai.providers.ollama import OllamaProvider
    from venomscan_engine.ai.providers.openai_compat import OpenAICompatProvider

    if provider == "openai_compat" and api_key:
        return OpenAICompatProvider(
            model=model, base_url=base_url or "https://api.openai.com/v1",
            api_key=api_key, timeout=timeout, retries=retries, transport=transport,
            allow_private=allow_private,
        )
    if provider == "anthropic" and api_key:
        return AnthropicProvider(
            model=model, base_url=base_url or "https://api.anthropic.com",
            api_key=api_key, timeout=timeout, retries=retries, transport=transport,
            allow_private=allow_private,
        )
    if provider == "ollama":
        return OllamaProvider(
            model=model, base_url=base_url or "http://127.0.0.1:11434",
            timeout=timeout, retries=retries, transport=transport,
        )
    return None
