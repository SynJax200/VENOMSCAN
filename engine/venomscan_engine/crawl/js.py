from __future__ import annotations

import re
from urllib.parse import urlsplit

from venomscan_engine.crawl.html_extract import normalize_url

_QUOTED = re.compile(r"""["'`]([^"'`\s<>]{2,300})["'`]""")

# Static assets add noise without extending the attack surface. JSON is kept
# because API documents and data endpoints are worth surfacing.
_BLOCKED_EXTENSIONS = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".avif",
        ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".map", ".mp4", ".webm", ".mp3", ".wav", ".ogg",
    }
)


def is_static_asset(url: str) -> bool:
    path = urlsplit(url).path.lower()
    dot = path.rfind(".")
    if dot == -1:
        return False
    return path[dot:] in _BLOCKED_EXTENSIONS


_TEMPLATE_PLACEHOLDER = re.compile(r"\$\{[^}]*\}")
# Route tables in bundled JS are full of regex fragments ("/(.+?)", "^/api$").
# They are not endpoints, so drop candidates that still look like patterns.
_REGEX_NOISE = re.compile(r"[()\[\]\\^$|]")


def _looks_like_route(candidate: str) -> bool:
    return not _REGEX_NOISE.search(_TEMPLATE_PLACEHOLDER.sub("", candidate))


def extract_js_endpoints(text: str, base_url: str, limit: int = 120) -> list[str]:
    """Extract URL-shaped string literals (fetch/axios/router calls, templates)."""
    found: list[str] = []
    for match in _QUOTED.finditer(text):
        candidate = match.group(1)
        lowered = candidate.lower()
        if lowered.startswith(("data:", "mailto:", "javascript:", "#")):
            continue
        if not candidate.startswith(("/", "./", "../", "http://", "https://")):
            continue
        if not _looks_like_route(candidate):
            continue
        normalized = normalize_url(base_url, candidate)
        if not normalized or is_static_asset(normalized):
            continue
        if normalized not in found:
            found.append(normalized)
        if len(found) >= limit:
            break
    return found
