from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from venomscan_api.config import Settings

OLLAMA_HOSTS = {"localhost", "127.0.0.1", "::1"}


class AiDestinationError(ValueError):
    pass


def validate_ai_base_url(provider: str, base_url: str, settings: Settings) -> str:
    """Reject destinations that could receive a stored provider key.

    Keys are write-only and encrypted at rest. A caller who can edit the base
    URL must not be able to point the next probe at a host they control, so
    keyed providers are limited to HTTPS and an explicit host allowlist.
    """
    value = (base_url or "").strip().rstrip("/")
    if not value:
        return ""
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise AiDestinationError("Base URL must be an absolute http(s) URL")
    if parsed.username or parsed.password:
        raise AiDestinationError("Base URL must not contain credentials")
    if parsed.fragment:
        raise AiDestinationError("Base URL must not contain a fragment")
    host = parsed.hostname.lower()
    if provider == "ollama":
        if parsed.scheme != "http" and parsed.scheme != "https":
            raise AiDestinationError("Ollama base URL must use http or https")
        if host not in OLLAMA_HOSTS and host not in settings.ai_allowed_host_list:
            raise AiDestinationError(
                "Ollama base URL host is not in AI_ALLOWED_HOSTS"
            )
        return value
    if parsed.scheme != "https":
        raise AiDestinationError("HTTPS is required for cloud AI providers")
    if host not in settings.ai_allowed_host_list:
        raise AiDestinationError(
            "Base URL host is not allowed. Add it to AI_ALLOWED_HOSTS after review."
        )
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return value
    if not address.is_global:
        raise AiDestinationError("Base URL must resolve to a public destination")
    return value
