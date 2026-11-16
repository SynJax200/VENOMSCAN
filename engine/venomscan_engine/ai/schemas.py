from __future__ import annotations

from pydantic import BaseModel, Field


class ExplanationPayload(BaseModel):
    summary: str = Field(min_length=1, max_length=2000)
    why_it_matters: str = Field(min_length=1, max_length=2000)
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)


class FpReviewPayload(BaseModel):
    fp_likelihood: float = Field(ge=0.0, le=1.0)
    reasoning: str = Field(min_length=1, max_length=2000)
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)


class SummaryPayload(BaseModel):
    headline: str = Field(min_length=1, max_length=300)
    summary: str = Field(min_length=1, max_length=3000)
    priorities: list[str] = Field(default_factory=list, max_length=10)
    evidence_refs: list[str] = Field(default_factory=list, max_length=50)


class PrioritizeItem(BaseModel):
    finding_id: str
    title: str = Field(min_length=1, max_length=300)
    url: str = ""
    reason: str = Field(default="", max_length=500)


class PrioritizePayload(BaseModel):
    order: list[PrioritizeItem] = Field(default_factory=list, max_length=100)
    evidence_refs: list[str] = Field(default_factory=list, max_length=50)


class SurfacePayload(BaseModel):
    summary: str = Field(min_length=1, max_length=3000)
    clusters: list[str] = Field(default_factory=list, max_length=20)
    evidence_refs: list[str] = Field(default_factory=list, max_length=50)


class RemediationPayload(BaseModel):
    summary: str = Field(min_length=1, max_length=2000)
    steps: list[str] = Field(default_factory=list, max_length=20)
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)


class CorrelationPayload(BaseModel):
    summary: str = Field(min_length=1, max_length=3000)
    themes: list[str] = Field(default_factory=list, max_length=20)
    evidence_refs: list[str] = Field(default_factory=list, max_length=50)


class AnswerPayload(BaseModel):
    answer: str = Field(min_length=1, max_length=4000)
    evidence_refs: list[str] = Field(default_factory=list, max_length=30)


class EducationPayload(BaseModel):
    plain_language: str = Field(min_length=1, max_length=2000)
    why_it_matters: str = Field(min_length=1, max_length=2000)
    how_to_verify: str = Field(min_length=1, max_length=2000)
    practice_tip: str = Field(default="", max_length=1000)
    evidence_refs: list[str] = Field(default_factory=list, max_length=10)


class EndpointPriorityItem(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    method: str = Field(default="GET", max_length=10)
    reason: str = Field(default="", max_length=500)


class EndpointPrioritizePayload(BaseModel):
    summary: str = Field(min_length=1, max_length=2000)
    order: list[EndpointPriorityItem] = Field(default_factory=list, max_length=50)
    evidence_refs: list[str] = Field(default_factory=list, max_length=50)


class NextStepItem(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    detail: str = Field(default="", max_length=800)


class NextStepsPayload(BaseModel):
    summary: str = Field(min_length=1, max_length=2000)
    steps: list[NextStepItem] = Field(default_factory=list, max_length=12)
    evidence_refs: list[str] = Field(default_factory=list, max_length=50)


class JsRouteItem(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    method: str = Field(default="GET", max_length=10)
    source: str = Field(default="js", max_length=40)
    verified: bool = False


class JsAnalysisPayload(BaseModel):
    summary: str = Field(min_length=1, max_length=3000)
    routes: list[JsRouteItem] = Field(default_factory=list, max_length=60)
    exposures: list[str] = Field(default_factory=list, max_length=20)
    evidence_refs: list[str] = Field(default_factory=list, max_length=50)


class ApiAnalysisPayload(BaseModel):
    summary: str = Field(min_length=1, max_length=3000)
    auth_flows: list[str] = Field(default_factory=list, max_length=15)
    risks: list[str] = Field(default_factory=list, max_length=15)
    bola_candidates: list[str] = Field(default_factory=list, max_length=20)
    evidence_refs: list[str] = Field(default_factory=list, max_length=50)


class FpTriageReview(BaseModel):
    finding_id: str = Field(min_length=1, max_length=64)
    title: str = Field(min_length=1, max_length=300)
    fp_likelihood: float = Field(ge=0.0, le=1.0)
    recommendation: str = Field(default="keep", max_length=20)
    reason: str = Field(default="", max_length=500)


class FpTriagePayload(BaseModel):
    reviews: list[FpTriageReview] = Field(default_factory=list, max_length=60)
    evidence_refs: list[str] = Field(default_factory=list, max_length=50)


class ProbePayload(BaseModel):
    """Tiny structured answer used by the provider self-test."""

    ok: bool
    note: str = Field(default="", max_length=200)


SCHEMAS: dict[str, type[BaseModel]] = {
    "explanation": ExplanationPayload,
    "fp_review": FpReviewPayload,
    "summary": SummaryPayload,
    "prioritize": PrioritizePayload,
    "surface_summary": SurfacePayload,
    "remediation": RemediationPayload,
    "correlate": CorrelationPayload,
    "assistant": AnswerPayload,
    "education": EducationPayload,
    "endpoint_prioritize": EndpointPrioritizePayload,
    "next_steps": NextStepsPayload,
    "js_analysis": JsAnalysisPayload,
    "api_analysis": ApiAnalysisPayload,
    "fp_triage": FpTriagePayload,
}
