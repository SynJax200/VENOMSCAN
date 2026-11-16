from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from urllib.parse import parse_qsl, urlsplit

# A JWT is header.payload.signature in base64url. The signature may be empty
# for alg=none tokens, so the third segment is allowed to be short.
_JWT = re.compile(
    r"(eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*)(?![A-Za-z0-9_-])"
)
_SENSITIVE_CLAIMS = re.compile(
    r"(?i)(password|passwd|secret|api[_-]?key|private[_-]?key|credit[_-]?card|"
    r"ssn|social[_-]?security|refresh[_-]?token|session[_-]?id)"
)
MAX_TOKENS = 20
MAX_CLAIMS = 30
LONG_LIFETIME_DAYS = 30.0
EXTERNAL_KEY_HEADERS = ("jku", "x5u")


def _decode_segment(segment: str) -> dict | None:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        value = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    return value if isinstance(value, dict) else None


def decode(token: str) -> dict | None:
    """Decode header and claims without verifying anything. Never trusts the result."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header = _decode_segment(parts[0])
    claims = _decode_segment(parts[1])
    if header is None or claims is None:
        return None
    return {"header": header, "claims": claims}


def looks_like_jwt(value: str) -> bool:
    return bool(_JWT.fullmatch(value.strip()))


def _lifetime_days(claims: dict, now: float) -> float | None:
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)):
        return None
    return round((float(exp) - now) / 86_400.0, 1)


def analyze(token: str, *, location: str, source: str, now: float | None = None) -> dict | None:
    """Masked, verification-free token report. The raw token is never returned."""
    decoded = decode(token)
    if decoded is None:
        return None
    now = time.time() if now is None else now
    header = decoded["header"]
    claims = decoded["claims"]
    alg = str(header.get("alg") or "").lower()
    lifetime = _lifetime_days(claims, now)

    flags: list[str] = []
    if alg == "none":
        flags.append("alg_none")
    if any(_SENSITIVE_CLAIMS.search(str(name)) for name in claims):
        flags.append("sensitive_claims")
    host = urlsplit(source).hostname or ""
    for name in EXTERNAL_KEY_HEADERS:
        value = header.get(name)
        if isinstance(value, str) and value.startswith(("http://", "https://")):
            if (urlsplit(value).hostname or "") != host:
                flags.append("external_key_url")
                break
    if location == "url query":
        flags.append("url_exposure")
    if "exp" not in claims:
        flags.append("missing_exp")
    elif lifetime is not None and lifetime > LONG_LIFETIME_DAYS:
        flags.append("long_lifetime")
    if lifetime is not None and lifetime < 0:
        flags.append("expired")

    return {
        "fingerprint": hashlib.sha256(token.encode("utf-8")).hexdigest()[:12],
        "prefix": token[:10],
        "alg": alg or "unknown",
        "claims": sorted(str(name) for name in claims)[:MAX_CLAIMS],
        "lifetime_days": lifetime,
        "flags": flags,
        "location": location,
        "source": source.split("?")[0][:300],
    }


def _unique(tokens: list[tuple[str, str, str]]) -> list[tuple[str, str, str]]:
    seen: set[str] = set()
    kept: list[tuple[str, str, str]] = []
    for token, location, source in tokens:
        if token in seen:
            continue
        seen.add(token)
        kept.append((token, location, source))
        if len(kept) >= MAX_TOKENS:
            break
    return kept


def collect(
    samples: list[dict],
    endpoints: list,
    set_cookies: list[str] | None = None,
    *,
    now: float | None = None,
) -> list[dict]:
    """Harvest tokens already seen by the scanner: response bodies, cookies and URLs."""
    found: list[tuple[str, str, str]] = []
    for sample in samples[:12]:
        if not isinstance(sample, dict):
            continue
        source = str(sample.get("url") or "")
        for token in _JWT.findall(str(sample.get("body") or "")):
            found.append((token, "response body", source))
    for cookie in (set_cookies or [])[:20]:
        for token in _JWT.findall(str(cookie)):
            found.append((token, "cookie", "set-cookie"))
    for endpoint in endpoints:
        url = getattr(endpoint, "url", "") or ""
        for _name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            if looks_like_jwt(value):
                found.append((value, "url query", url))
                break

    analyses: list[dict] = []
    for token, location, source in _unique(found):
        report = analyze(token, location=location, source=source, now=now)
        if report is not None:
            analyses.append(report)
    return analyses


__all__ = [
    "LONG_LIFETIME_DAYS",
    "MAX_TOKENS",
    "analyze",
    "collect",
    "decode",
    "looks_like_jwt",
]
