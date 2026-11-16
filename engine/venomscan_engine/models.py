from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, computed_field


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VerificationStatus(StrEnum):
    SUSPECTED = "suspected"
    VERIFIED = "verified"
    REJECTED = "rejected"


class ScanPhase(StrEnum):
    AUTHORIZING = "authorizing"
    RECON = "recon"
    CRAWLING = "crawling"
    ANALYZING = "analyzing"
    VERIFYING = "verifying"
    CORRELATING = "correlating"
    AI_ENRICHING = "ai_enriching"
    REPORTING = "reporting"


PROFILE_ORDER = {"passive": 0, "safe": 1, "active": 2}

# Documented risk model (ARCHITECTURE §8):
#   risk = impact * (0.6 + 0.4 * confidence/10)
# Confidence scales a finding down when evidence is weak; it never inflates impact.
DEFAULT_IMPACT: dict[Severity, float] = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 8.0,
    Severity.MEDIUM: 5.5,
    Severity.LOW: 2.5,
    Severity.INFO: 0.0,
}


def severity_from_risk(risk: float) -> Severity:
    if risk >= 9.0:
        return Severity.CRITICAL
    if risk >= 7.0:
        return Severity.HIGH
    if risk >= 4.0:
        return Severity.MEDIUM
    if risk >= 0.1:
        return Severity.LOW
    return Severity.INFO


class Finding(BaseModel):
    check_id: str
    title: str
    category: str
    severity: Severity
    confidence: int = Field(ge=0, le=10)
    verification_status: VerificationStatus = VerificationStatus.SUSPECTED
    url: str
    method: str = "GET"
    parameter: str | None = None
    payload: str | None = None
    description: str
    impact: str
    remediation: str
    references: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    cvss_vector: str | None = None
    cvss_score: float | None = None
    request_evidence: dict[str, Any] = Field(default_factory=dict)
    response_evidence: dict[str, Any] = Field(default_factory=dict)
    dedup_key: str = ""
    risk_score: float = 0.0

    def finalize(self) -> Finding:
        impact = self.cvss_score if self.cvss_score is not None else DEFAULT_IMPACT[self.severity]
        risk = impact * (0.6 + 0.4 * (float(self.confidence) / 10.0))
        self.risk_score = round(min(max(risk, 0.0), 10.0), 2)
        self.severity = severity_from_risk(self.risk_score)
        self.dedup_key = self.compute_dedup_key()
        return self

    def compute_dedup_key(self) -> str:
        from urllib.parse import urlsplit

        parts = urlsplit(self.url)
        normalized = f"{parts.scheme}://{parts.netloc.lower()}{parts.path.rstrip('/') or '/'}"
        raw = "|".join([self.check_id, normalized, self.parameter or "", self.payload or ""])
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()


class Technology(BaseModel):
    name: str
    version: str | None = None
    category: str = "unknown"
    confidence: float = Field(default=0.6, ge=0.0, le=1.0)
    evidence: str = ""


def endpoint_state(source: str, status_code: int | None) -> str:
    """live = the scanner saw a real response, unverified = referenced only (JS/forms/specs)."""
    if source == "archive":
        return "archived"
    return "live" if status_code is not None else "unverified"


class EndpointRecord(BaseModel):
    url: str
    method: str = "GET"
    source: str = "crawl"
    status_code: int | None = None
    content_type: str | None = None
    depth: int = 0
    parameters: list[str] = Field(default_factory=list)

    @computed_field
    @property
    def state(self) -> str:
        return endpoint_state(self.source, self.status_code)


class ScanStats(BaseModel):
    requests: int = 0
    findings_total: int = 0
    endpoints: int = 0
    endpoints_live: int = 0
    endpoints_unverified: int = 0
    technologies: int = 0
    duration_ms: int = 0


class ScanResult(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    technologies: list[Technology] = Field(default_factory=list)
    endpoints: list[EndpointRecord] = Field(default_factory=list)
    stats: ScanStats = Field(default_factory=ScanStats)
    recon: dict[str, Any] = Field(default_factory=dict)
