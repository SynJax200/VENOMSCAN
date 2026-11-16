from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from venomscan_engine.intel.endpoints import template_path
from venomscan_engine.models import EndpointRecord

MAX_CANDIDATES = 20
PROTECTED_METHODS = frozenset({"GET", "PUT", "PATCH", "DELETE"})
_ID_PARAM = re.compile(
    r"^(?:id|uid|uuid|[a-z_]*_id|user|account|tenant|org|order|invoice|customer|project|file|document)$",
    re.IGNORECASE,
)
_ID_SEGMENT = re.compile(
    r"^(\d+|[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}|\{[A-Za-z_][\w-]*\}|:[A-Za-z_][\w-]*)$"
)


def _object_parameters(endpoint: EndpointRecord) -> list[str]:
    names = list(endpoint.parameters or [])
    names += [name for name, _ in parse_qsl(urlsplit(endpoint.url).query, keep_blank_values=True)]
    return sorted({name for name in names if _ID_PARAM.match(name)})


def _is_object_route(endpoint: EndpointRecord) -> bool:
    if _object_parameters(endpoint):
        return True
    return any(_ID_SEGMENT.match(segment) for segment in urlsplit(endpoint.url).path.split("/") if segment)


def _roles(accounts: list[dict] | None) -> list[str]:
    roles = {
        str(account.get("role") or "").strip().lower()
        for account in accounts or []
        if account.get("role")
    }
    return sorted(role for role in roles if role)


def build_bola_matrix(endpoints: list[EndpointRecord], accounts: list[dict] | None = None) -> dict:
    """Candidate matrix for manual role/tenant review; never performs a request."""
    roles = _roles(accounts) or ["authenticated"]
    candidates: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for endpoint in endpoints:
        method = endpoint.method.upper()
        if method not in PROTECTED_METHODS or endpoint.state == "archived":
            continue
        if not _is_object_route(endpoint):
            continue
        template = template_path(endpoint.url)
        key = (method, template)
        if key in seen:
            continue
        seen.add(key)
        parameters = _object_parameters(endpoint)
        candidates.append(
            {
                "method": method,
                "url": endpoint.url,
                "template": template,
                "state": endpoint.state,
                "status_code": endpoint.status_code,
                "parameters": parameters[:8],
                "roles": ["anonymous", *roles],
                "checks": ["cross-role object access", "tenant boundary"],
                "status": "candidate",
                "authorization_observed": endpoint.status_code in {401, 403},
            }
        )
        if len(candidates) >= MAX_CANDIDATES:
            break
    return {
        "candidates": candidates,
        "count": len(candidates),
        "roles": roles,
        "note": (
            "Non-destructive scaffold: candidates require manual review with authorized test "
            "accounts. No impersonation, credential guessing or state-changing requests are made."
        ),
    }


__all__ = ["MAX_CANDIDATES", "PROTECTED_METHODS", "build_bola_matrix"]
