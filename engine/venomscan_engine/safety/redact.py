from __future__ import annotations

import re

SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
}

_SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|secret|password|passwd|session[_-]?id)"
    r"(\s*[\"']?\s*[:=]\s*[\"']?)([A-Za-z0-9\-_\.]{8,})"
)
_SENSITIVE_LINE_RE = re.compile(
    r"(?im)^((?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token)"
    r"\s*:\s*).+$"
)


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in SENSITIVE_HEADERS:
            out[key] = "«redacted»"
        else:
            out[key] = value
    return out


def redact_text(text: str, *, limit: int = 1200) -> str:
    clipped = text[:limit]
    if len(text) > limit:
        clipped += "…"
    clipped = _SENSITIVE_LINE_RE.sub(lambda m: f"{m.group(1)}«redacted»", clipped)
    return _SECRET_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}«redacted»", clipped)
