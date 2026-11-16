from __future__ import annotations

import asyncio
import secrets
from datetime import timedelta
from urllib.parse import urlsplit

from venomscan_engine.safety import SafeHttpClient, Scope

from venomscan_api.db import utcnow

ARTIFACT_PATH = "/.well-known/venomscan-verify.txt"
AUTHORIZATION_DAYS = 90
ATTESTATION_TEXT = (
    "I confirm that I own this target or hold written authorization to test it, "
    "that the scan stays within the scope I defined, and that I accept responsibility "
    "for the traffic VENOMSCAN sends."
)


def new_verification_token() -> str:
    return "venomscan-" + secrets.token_urlsafe(18)


def host_from_url(url: str) -> str:
    parts = urlsplit(url.strip())
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("target URL must start with http:// or https:// and include a hostname")
    return parts.hostname.lower()


def origin(url: str) -> str:
    parts = urlsplit(url.strip())
    return f"{parts.scheme}://{parts.netloc}"


def dns_record_name(host: str) -> str:
    return f"_venomscan.{host}"


def well_known_url(url: str) -> str:
    return origin(url) + ARTIFACT_PATH


def verified_until() -> object:
    return utcnow() + timedelta(days=AUTHORIZATION_DAYS)


async def check_dns(host: str, token: str) -> tuple[bool, str]:
    import dns.resolver

    try:
        answers = await asyncio.to_thread(dns.resolver.resolve, dns_record_name(host), "TXT")
    except Exception as exc:
        return False, f"DNS lookup failed: {type(exc).__name__}: {exc}"
    values = [record.to_text().strip('"') for record in answers]
    if any(token in value for value in values):
        return True, "TXT record matches the verification token"
    return False, "TXT record does not contain the verification token yet"


async def check_well_known(url: str, token: str, *, allow_private: bool) -> tuple[bool, str]:
    scope = Scope.from_target(url)
    async with SafeHttpClient(
        scope,
        max_requests=4,
        max_seconds=20,
        rps=2,
        allow_private=allow_private,
    ) as client:
        try:
            bundle = await client.get(well_known_url(url))
        except Exception as exc:
            return False, f"Could not fetch verification file: {exc}"
    if bundle.status_code != 200:
        return False, f"Verification file returned HTTP {bundle.status_code}"
    if token not in bundle.body:
        return False, "Verification file does not contain the token"
    return True, "Verification file matches the token"
