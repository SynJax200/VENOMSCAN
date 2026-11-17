from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field


class ReportFinding(BaseModel):
    id: str
    check_id: str
    title: str
    category: str
    severity: str
    verification_status: str
    confidence: int
    risk_score: float
    url: str
    method: str = "GET"
    parameter: str | None = None
    payload: str | None = None
    description: str = ""
    impact: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    cvss_score: float | None = None
    cvss_vector: str | None = None
    request_evidence: dict[str, Any] = Field(default_factory=dict)
    response_evidence: dict[str, Any] = Field(default_factory=dict)
    reproduction: list[str] = Field(default_factory=list)
    ai_summary: str = ""


class ReportTechnology(BaseModel):
    name: str
    version: str | None = None
    category: str = "unknown"
    confidence: float = 0.0
    evidence: str = ""


class ReportEndpoint(BaseModel):
    url: str
    method: str = "GET"
    source: str = "crawl"
    status_code: int | None = None
    depth: int = 0


class ReportCheck(BaseModel):
    id: str
    name: str
    category: str = "general"
    profile: str = "safe"
    severity: str = "info"
    result: str = "no finding"  # "finding" when the check produced at least one result


class ReportScan(BaseModel):
    id: str
    target_name: str
    target_url: str
    host: str
    profile: str
    status: str
    summary: str = ""
    stats: dict[str, Any] = Field(default_factory=dict)
    recon: dict[str, Any] = Field(default_factory=dict)
    started_at: str | None = None
    finished_at: str | None = None
    created_at: str | None = None


class ReportAuthorization(BaseModel):
    method: str = ""
    verified_at: str | None = None
    expires_at: str | None = None
    operator: str = ""


class ReportAi(BaseModel):
    kind: str
    summary: str = ""
    steps: list[str] = Field(default_factory=list)
    citations: list[str] = Field(default_factory=list)
    provider: str = ""
    model: str = ""
    fallback: bool = True
    created_at: str | None = None


class ReportModel(BaseModel):
    """Canonical report document. Every renderer consumes exactly this shape."""

    report_version: str = "1"
    generated_at: str
    scan: ReportScan
    authorization: ReportAuthorization
    findings: list[ReportFinding] = Field(default_factory=list)
    checks: list[ReportCheck] = Field(default_factory=list)
    technologies: list[ReportTechnology] = Field(default_factory=list)
    endpoints: list[ReportEndpoint] = Field(default_factory=list)
    ai_analyses: list[ReportAi] = Field(default_factory=list)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.findings:
            if finding.severity in counts:
                counts[finding.severity] += 1
        return counts


def canonical_json(model: ReportModel) -> bytes:
    """Stable serialisation used for the SHA-256 integrity value."""
    payload = model.model_dump(mode="json")
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
