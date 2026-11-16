from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

Profile = Literal["passive", "safe", "active"]


class UserOut(BaseModel):
    id: str
    email: str
    name: str
    created_at: datetime


class RegisterIn(BaseModel):
    email: str = Field(min_length=5, max_length=320)
    password: str = Field(min_length=10, max_length=200)
    name: str = Field(default="", max_length=120)

    @field_validator("email")
    @classmethod
    def _email_shape(cls, value: str) -> str:
        value = value.strip().lower()
        if "@" not in value or value.startswith("@") or value.endswith("@"):
            raise ValueError("enter a valid email address")
        return value


class LoginIn(BaseModel):
    email: str
    password: str


class AuthOut(BaseModel):
    user: UserOut
    csrf_token: str


class CsrfOut(BaseModel):
    csrf_token: str


class VerificationOut(BaseModel):
    verified: bool
    method: str | None = None
    verified_at: datetime | None = None
    expires_at: datetime | None = None
    token: str
    dns_record_name: str
    dns_record_value: str
    well_known_url: str
    attestation_required_text: str


class TargetCreate(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    url: str = Field(min_length=8, max_length=2048)
    scope_notes: str = Field(default="", max_length=2000)


class TargetOut(BaseModel):
    id: str
    name: str
    url: str
    host: str
    scope_notes: str
    scan_count: int
    created_at: datetime
    verification: VerificationOut


class AttestIn(BaseModel):
    attestation: str = Field(min_length=20, max_length=2000)
    accepted: bool


class ScanCreate(BaseModel):
    target_id: str
    profile: Profile | None = None
    active_consent: bool = False


class FindingOut(BaseModel):
    id: str
    scan_id: str
    check_id: str
    title: str
    category: str
    severity: str
    verification_status: str
    confidence: int
    risk_score: float
    url: str
    method: str
    parameter: str | None
    payload: str | None
    description: str
    impact: str
    remediation: str
    references: list[str]
    cwe: list[str]
    owasp: list[str]
    cvss_score: float | None
    cvss_vector: str | None
    request_evidence: dict[str, Any]
    response_evidence: dict[str, Any]
    ai_summary: str
    ai_priority: str
    ai_false_positive_likelihood: float | None
    occurrences: int = 1
    created_at: datetime


class ScanEventOut(BaseModel):
    id: int
    phase: str
    type: str
    message: str
    progress: int
    payload: dict[str, Any]
    created_at: datetime


class ScanOut(BaseModel):
    id: str
    target_id: str
    target_name: str
    target_url: str
    profile: str
    status: str
    phase: str
    progress: int
    stats: dict[str, Any]
    recon: dict[str, Any] = Field(default_factory=dict)
    summary: str
    error: str
    findings_total: int
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime


class TechnologyOut(BaseModel):
    name: str
    version: str | None
    category: str
    confidence: float


class EndpointOut(BaseModel):
    url: str
    method: str
    source: str
    status_code: int | None
    content_type: str | None
    depth: int = 0
    parameters: list[str] = Field(default_factory=list)
    state: Literal["live", "unverified", "archived"] = "unverified"


class ScanDetailOut(ScanOut):
    findings: list[FindingOut]
    technologies: list[TechnologyOut]
    endpoints: list[EndpointOut]


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class DashboardScan(BaseModel):
    id: str
    target_name: str
    target_url: str
    profile: str
    status: str
    progress: int
    findings_total: int
    created_at: datetime


class TechSlice(BaseModel):
    name: str
    count: int


class DashboardTarget(BaseModel):
    id: str
    name: str
    url: str
    scans: int
    findings: int
    last_scan_at: datetime | None = None
    last_status: str = ""


class SplitSlice(BaseModel):
    name: str
    count: int


class DashboardOut(BaseModel):
    total_scans: int
    completed_scans: int
    active_scans: int
    total_findings: int
    severity: SeverityCounts
    recent_scans: list[DashboardScan]
    technologies: list[TechSlice]
    targets: list[DashboardTarget] = []
    by_check: list[SplitSlice] = []
    by_owasp: list[SplitSlice] = []
    insights: list[str]


class AuditOut(BaseModel):
    id: int
    action: str
    target_type: str
    target_id: str
    detail: dict[str, Any]
    created_at: datetime


class ScanDefaults(BaseModel):
    profile: Profile = "safe"


class SettingsIn(BaseModel):
    scan_defaults: ScanDefaults = Field(default_factory=ScanDefaults)
    disabled_checks: list[str] = Field(default_factory=list, max_length=100)


class SettingsOut(BaseModel):
    scan_defaults: ScanDefaults
    disabled_checks: list[str]
    updated_at: datetime | None = None


class CheckLearning(BaseModel):
    what: str
    why: str
    verify: str


class CheckOut(BaseModel):
    id: str
    name: str
    category: str
    profile: str
    severity: str
    learning: CheckLearning


CredentialRole = Literal["user", "viewer", "analyst", "student", "admin", "other"]


class CredentialIn(BaseModel):
    label: str = Field(min_length=2, max_length=80)
    role: CredentialRole = "user"
    identity: str = Field(default="", max_length=200)
    headers: dict[str, str] = Field(min_length=1, max_length=5)

    @field_validator("headers")
    @classmethod
    def _header_shape(cls, value: dict[str, str]) -> dict[str, str]:
        cleaned: dict[str, str] = {}
        for name, header_value in value.items():
            if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", name):
                raise ValueError(f"invalid header name {name!r}")
            if not header_value or len(header_value) > 2000 or "\r" in header_value or "\n" in header_value:
                raise ValueError(f"invalid value for header {name!r}")
            cleaned[name] = header_value
        return cleaned


class CredentialOut(BaseModel):
    id: str
    label: str
    role: str
    identity: str
    header_names: list[str]
    created_at: datetime


AiProvider = Literal["openai_compat", "anthropic", "ollama"]


class AiSettingsIn(BaseModel):
    provider: AiProvider = "openai_compat"
    model: str = Field(default="gpt-4o-mini", min_length=1, max_length=120)
    base_url: str = Field(default="", max_length=500)
    api_key: str | None = Field(default=None, max_length=4000)


class AiSettingsOut(BaseModel):
    provider: str
    model: str
    base_url: str
    key_configured: bool
    updated_at: datetime | None = None


class AiRequestIn(BaseModel):
    kind: str | None = None


class AiAnalysisOut(BaseModel):
    id: str
    kind: str
    provider: str
    model: str
    prompt_version: str
    grounded: bool
    fallback: bool
    payload: dict[str, Any]
    created_at: datetime


class AiProviderTestOut(BaseModel):
    configured: bool
    reachable: bool
    provider: str
    model: str
    latency_ms: int
    error: str = ""


class AssistantIn(BaseModel):
    scan_id: str
    question: str = Field(min_length=3, max_length=2000)


class AssistantOut(BaseModel):
    answer: str
    grounded: bool
    fallback: bool
    provider: str
    model: str
    prompt_version: str
    refused: bool = False
    references: list[str] = Field(default_factory=list)


ReportFormat = Literal["json", "markdown", "html", "pdf"]


class ReportIn(BaseModel):
    format: ReportFormat


class ReportOut(BaseModel):
    id: str
    scan_id: str
    format: str
    title: str
    filename: str
    sha256: str
    size: int
    created_at: datetime
    expires_at: datetime
    download_url: str
    preview_url: str
    signed_url: str


class CompareFinding(BaseModel):
    id: str
    check_id: str
    title: str
    severity: str
    risk_score: float
    url: str
    verification_status: str


class ScanCompareOut(BaseModel):
    base_scan_id: str
    other_scan_id: str
    base_label: str
    other_label: str
    new: list[CompareFinding] = Field(default_factory=list)
    fixed: list[CompareFinding] = Field(default_factory=list)
    persisting: list[CompareFinding] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)


class NucleiStatusOut(BaseModel):
    enabled: bool
    configured: bool
    binary_present: bool
    templates_present: bool
    severities: list[str]
    rate_limit: int
    timeout: int


class IntegrationStatusOut(BaseModel):
    nuclei: NucleiStatusOut
    burp_import: bool
    burp_export: bool
    upstream_proxy: bool
    plugin_dirs: list[str]


class BurpImportOut(BaseModel):
    scan_id: str
    imported: int
    skipped: int
    out_of_scope: int


class PluginOut(BaseModel):
    check_id: str
    name: str
    category: str
    severity: str
    profile: str
    timeout_seconds: int
    memory_mb: int
    file: str


class PluginCatalogOut(BaseModel):
    plugins: list[PluginOut] = Field(default_factory=list)
    problems: list[str] = Field(default_factory=list)
    isolation: str = "subprocess · scrubbed env · timeout · memory cap · analysis-only"


class LearningLessonOut(BaseModel):
    id: str
    name: str
    category: str
    profile: str
    severity: str
    objective: str
    what: str
    why: str
    verify: str
    status: str = "not_started"
    updated_at: datetime | None = None


class LearningTrackOut(BaseModel):
    id: str
    title: str
    level: str
    focus: str
    outcome: str
    scan_profile: str = "safe"
    consent: str = ""
    check_ids: list[str]
    lessons: list[LearningLessonOut]
    completed: int
    total: int
    percent: int


class LearningPathsOut(BaseModel):
    tracks: list[LearningTrackOut]
    check_count: int
    completed: int
    in_progress: int
    percent: int


ProgressStatus = Literal["not_started", "in_progress", "completed"]


class EndpointLearningLessonOut(BaseModel):
    finding_id: str
    check_id: str
    title: str
    severity: str
    verification_status: str
    risk_score: float
    what: str = ""
    why: str = ""
    verify: str = ""


class EndpointLearningOut(BaseModel):
    url: str
    method: str
    source: str
    state: str
    status_code: int | None = None
    finding_count: int
    lessons: list[EndpointLearningLessonOut]


class ScanEndpointLearningOut(BaseModel):
    scan_id: str
    target_url: str
    endpoint_count: int
    with_findings: int
    endpoints: list[EndpointLearningOut]


class LearningProgressIn(BaseModel):
    status: ProgressStatus


class LearningProgressOut(BaseModel):
    check_id: str
    status: str
    updated_at: datetime | None = None


class PracticeFindingOut(BaseModel):
    id: str
    scan_id: str
    check_id: str
    title: str
    category: str
    severity: str
    verification_status: str
    confidence: int
    risk_score: float
    url: str
    method: str
    created_at: datetime


class WalkthroughStepOut(BaseModel):
    key: str
    title: str
    detail: str
    evidence: dict[str, str] = Field(default_factory=dict)


class WalkthroughLearningOut(BaseModel):
    what: str = ""
    why: str = ""
    verify: str = ""


class WalkthroughOut(BaseModel):
    finding_id: str
    check_id: str
    title: str
    severity: str
    url: str
    method: str
    verification_status: str
    confidence: int | None = None
    risk_score: float | None = None
    learning: WalkthroughLearningOut = Field(default_factory=WalkthroughLearningOut)
    steps: list[WalkthroughStepOut]
    questions: list[str]
    safety: str
    references: list[str] = Field(default_factory=list)


class PracticeExerciseOut(BaseModel):
    id: str
    type: str
    prompt: str
    options: list[str]
    answer: list[str]
    multi: bool
    explanation: str
