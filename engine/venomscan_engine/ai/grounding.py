from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel

_URL = re.compile(r"https?://[^\s\"'<>)\]]+")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_REF_FIELDS = {"evidence_refs", "finding_id", "scan_id"}


class GroundingError(ValueError):
    """The model produced facts that are not present in the scan data."""


def normalize_url(url: str) -> str:
    parts = urlsplit(url.strip())
    path = parts.path.rstrip("/") or "/"
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}{path}"


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


class GroundingValidator:
    """Rejects URLs, CVEs and evidence refs the scan never observed."""

    def __init__(
        self,
        allowed_urls: Iterable[str] = (),
        allowed_cves: Iterable[str] = (),
        allowed_refs: Iterable[str] = (),
    ) -> None:
        self.urls = {normalize_url(url) for url in allowed_urls if url}
        self.cves = {cve.upper() for cve in allowed_cves}
        self.refs = set(allowed_refs)

    def validate(self, payload: BaseModel) -> BaseModel:
        for text in _strings(payload.model_dump()):
            for url in _URL.findall(text):
                if normalize_url(url.rstrip(".,;:!?")) not in self.urls:
                    raise GroundingError(f"unknown URL in model output: {url}")
            for cve in _CVE.findall(text):
                if cve.upper() not in self.cves:
                    raise GroundingError(f"CVE not present in scan intelligence: {cve}")
        self._validate_refs(payload.model_dump())
        return payload

    def _validate_refs(self, value: Any, key: str = "") -> None:
        if isinstance(value, dict):
            for field, item in value.items():
                self._validate_refs(item, field)
        elif isinstance(value, list):
            for item in value:
                self._validate_refs(item, key)
        elif isinstance(value, str) and key in _REF_FIELDS:
            if key == "finding_id":
                expected = f"finding:{value}"
                if expected not in self.refs:
                    raise GroundingError(f"unknown finding reference: {value}")
            elif value and value not in self.refs:
                raise GroundingError(f"unknown evidence reference: {value}")
