"""Offline technology → CVE intelligence.

The snapshot is curated and shipped with the engine so the panel works without
network access. It is triage input, never proof that a target is vulnerable.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

_SNAPSHOT = Path(__file__).with_name("cve_snapshot.json")
_VERSION_RE = re.compile(r"\d+")


class IntelCve(BaseModel):
    id: str
    severity: str
    cvss: float | None = None
    summary: str
    cwe: list[str] = Field(default_factory=list)
    refs: list[str] = Field(default_factory=list)


class IntelMatch(BaseModel):
    technology: str
    version: str | None = None
    product: str
    version_unknown: bool = False
    cve: IntelCve


class IntelReport(BaseModel):
    snapshot_version: str
    source: str
    matches: list[IntelMatch] = Field(default_factory=list)


@lru_cache
def _snapshot() -> dict[str, Any]:
    return json.loads(_SNAPSHOT.read_text(encoding="utf-8"))


def snapshot_version() -> str:
    return str(_snapshot().get("version", "unknown"))


def _version_tuple(value: str | None) -> tuple[int, ...] | None:
    if not value:
        return None
    numbers = _VERSION_RE.findall(value)
    if not numbers:
        return None
    return tuple(int(item) for item in numbers)


def _in_range(version: str, entry: dict[str, Any]) -> bool:
    parsed = _version_tuple(version)
    if parsed is None:
        return False
    while len(parsed) < 3:
        parsed += (0,)

    def _bound(raw: str) -> tuple[int, ...]:
        parts = _version_tuple(raw) or ()
        return parts + (0,) * (3 - len(parts)) if len(parts) < 3 else parts

    low = entry.get("min")
    high = entry.get("max")
    if low and parsed < _bound(low):
        return False
    if high:
        boundary = _bound(high)
        if entry.get("max_inclusive", True):
            if parsed > boundary:
                return False
        elif parsed >= boundary:
            return False
    return True


def _names(entry: dict[str, Any]) -> list[str]:
    return [entry.get("product", "").lower(), *(alias.lower() for alias in entry.get("aliases", []))]


def lookup(technologies: list[tuple[str, str | None]]) -> IntelReport:
    """Match detected technologies against the offline snapshot (name + version range)."""
    data = _snapshot()
    matches: list[IntelMatch] = []
    for name, version in technologies:
        normalized = (name or "").strip().lower()
        if not normalized:
            continue
        for entry in data.get("entries", []):
            if not any(alias and (alias in normalized or normalized in alias) for alias in _names(entry)):
                continue
            version_known = bool(version and _version_tuple(version))
            has_range = bool(entry.get("min") or entry.get("max"))
            if has_range and version_known and not _in_range(version or "", entry):
                continue
            for cve in entry.get("cves", []):
                matches.append(
                    IntelMatch(
                        technology=name,
                        version=version,
                        product=str(entry.get("product", "")),
                        version_unknown=not version_known and has_range,
                        cve=IntelCve(**cve),
                    )
                )
    matches.sort(key=lambda item: (-(item.cve.cvss or 0.0), item.technology))
    return IntelReport(
        snapshot_version=str(data.get("version", "unknown")),
        source=str(data.get("source", "")),
        matches=matches,
    )


__all__ = [
    "IntelCve",
    "IntelMatch",
    "IntelReport",
    "lookup",
    "snapshot_version",
]
