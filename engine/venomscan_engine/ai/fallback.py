from __future__ import annotations

import re
from collections import Counter
from typing import Any

from venomscan_engine.ai.context import digest_highlights, recon_refs
from venomscan_engine.ai.schemas import (
    AnswerPayload,
    ApiAnalysisPayload,
    CorrelationPayload,
    EducationPayload,
    EndpointPrioritizePayload,
    EndpointPriorityItem,
    ExplanationPayload,
    FpReviewPayload,
    FpTriagePayload,
    FpTriageReview,
    JsAnalysisPayload,
    JsRouteItem,
    NextStepItem,
    NextStepsPayload,
    PrioritizeItem,
    PrioritizePayload,
    RemediationPayload,
    SummaryPayload,
    SurfacePayload,
)

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_API_PATH = re.compile(r"/(api|graphql|rest|v\d+)(/|$)", re.IGNORECASE)
_SENSITIVE_PATH = re.compile(
    r"(admin|internal|account|user|auth|token|key|export|upload|debug|config|billing)",
    re.IGNORECASE,
)
_API_CHECK_PREFIXES = ("venom.api.", "venom.authz.", "venom.idor")


def _refs(ctx: dict[str, Any], *extra: str, limit: int = 10) -> list[str]:
    allowed = list(ctx.get("refs") or [])
    chosen = [ref for ref in extra if ref in allowed]
    if not chosen:
        chosen = allowed
    seen: list[str] = []
    for ref in chosen:
        if ref not in seen:
            seen.append(ref)
    return seen[:limit]


def _finding_ref(finding: dict[str, Any]) -> str:
    return f"finding:{finding.get('id', '')}"


def explanation(ctx: dict[str, Any]) -> ExplanationPayload:
    finding = ctx.get("finding") or {}
    status = finding.get("verification_status", "suspected")
    summary = (
        f"{finding.get('title', 'Finding')} was observed on "
        f"{finding.get('method', 'GET')} {finding.get('url', '')}. "
        f"{finding.get('description', '')}"
    ).strip()
    why = (
        f"{finding.get('impact', '')} The engine recorded confidence "
        f"{finding.get('confidence', 0)}/10 with status '{status}'."
    ).strip()
    return ExplanationPayload(
        summary=summary[:2000],
        why_it_matters=why[:2000],
        evidence_refs=_refs(ctx, _finding_ref(finding), f"url:{finding.get('url', '')}"),
    )


def fp_review(ctx: dict[str, Any]) -> FpReviewPayload:
    finding = ctx.get("finding") or {}
    status = finding.get("verification_status", "suspected")
    confidence = int(finding.get("confidence", 0) or 0)
    if status == "verified":
        likelihood, reason = 0.03, "The engine independently confirmed this finding with a deterministic verifier."
    elif status == "rejected":
        likelihood, reason = 0.95, "The verifier already rejected this finding."
    elif confidence >= 8:
        likelihood, reason = 0.25, "Confidence is high but the finding has not been independently verified."
    else:
        likelihood, reason = 0.55, "Confidence is moderate and the finding has not been independently verified."
    keys = sorted((finding.get("request_evidence") or {}).keys())
    if keys:
        reason += f" Evidence keys captured: {', '.join(keys[:6])}."
    return FpReviewPayload(
        fp_likelihood=likelihood,
        reasoning=reason[:2000],
        evidence_refs=_refs(ctx, _finding_ref(finding)),
    )


def summary(ctx: dict[str, Any]) -> SummaryPayload:
    scan = ctx.get("scan") or {}
    findings = ctx.get("findings") or []
    counts = Counter(f.get("severity", "info") for f in findings)
    verified = sum(1 for f in findings if f.get("verification_status") == "verified")
    headline = (
        f"{len(findings)} findings on {scan.get('target_name', 'target')} "
        f"({counts.get('critical', 0)} critical, {counts.get('high', 0)} high)"
    )
    summary_text = (
        f"A scan of {scan.get('target_url', scan.get('url', ''))} using the "
        f"{scan.get('profile', 'safe')} profile completed with status "
        f"'{scan.get('status', 'completed')}' after {scan.get('stats', {}).get('requests', 0)} requests. "
        f"{len(findings)} findings were recorded, {verified} of them independently verified. "
        f"Severity mix: {', '.join(f'{k}={v}' for k, v in sorted(counts.items(), key=lambda i: _SEVERITY_ORDER.get(i[0], 9)))}."
    )
    ranked = sorted(findings, key=lambda f: float(f.get("risk_score") or 0), reverse=True)[:5]
    priorities = [
        f"{f.get('title', 'Finding')} — {f.get('url', '')} "
        f"({f.get('severity', 'info')}, {f.get('verification_status', 'suspected')})"
        for f in ranked
    ]
    highlights = digest_highlights(ctx.get("recon") or {})
    if highlights:
        summary_text += " " + " ".join(highlights[:3])
    refs = _refs(
        ctx,
        *[f"finding:{f.get('id', '')}" for f in ranked],
        *recon_refs(ctx.get("recon") or {})[:3],
        limit=12,
    )
    return SummaryPayload(
        headline=headline[:300],
        summary=summary_text[:3000],
        priorities=priorities,
        evidence_refs=refs,
    )


def prioritize(ctx: dict[str, Any]) -> PrioritizePayload:
    findings = sorted(
        ctx.get("findings") or [],
        key=lambda f: (float(f.get("risk_score") or 0), -_SEVERITY_ORDER.get(f.get("severity"), 9)),
        reverse=True,
    )
    order = [
        PrioritizeItem(
            finding_id=str(f.get("id", "")),
            title=f.get("title", "Finding")[:300],
            url=f.get("url", ""),
            reason=(
                f"{f.get('severity', 'info')} severity, risk {f.get('risk_score', 0)}, "
                f"status {f.get('verification_status', 'suspected')}"
            )[:500],
        )
        for f in findings[:50]
    ]
    return PrioritizePayload(
        order=order,
        evidence_refs=_refs(ctx, *[f"finding:{f.get('id', '')}" for f in findings[:10]]),
    )


def surface_summary(ctx: dict[str, Any]) -> SurfacePayload:
    endpoints = ctx.get("endpoints") or []
    technologies = ctx.get("technologies") or []
    recon = ctx.get("recon") or {}
    by_source = Counter(e.get("source", "unknown") for e in endpoints)
    parameterized = sum(1 for e in endpoints if e.get("parameters"))
    clusters = [f"{source}: {count} endpoints" for source, count in by_source.most_common(8)]
    patterns = (recon.get("endpoint_intel") or {}).get("clusters") or []
    if patterns:
        clusters = [
            f"{', '.join(item.get('methods') or ['GET'])} {item.get('template', '')} "
            f"({item.get('count', 0)} endpoint(s))"
            for item in patterns[:8]
        ]
    tech_names = ", ".join(t.get("name", "") for t in technologies[:6]) or "none fingerprinted"
    summary_text = (
        f"The scan mapped {len(endpoints)} endpoints across {len(by_source)} sources; "
        f"{parameterized} accept parameters. Detected technologies: {tech_names}."
    )
    highlights = digest_highlights(recon)
    if highlights:
        summary_text += " " + " ".join(highlights[:2])
    refs = _refs(
        ctx,
        *[f"url:{e.get('url', '')}" for e in endpoints[:10]],
        *recon_refs(recon)[:2],
        limit=12,
    )
    return SurfacePayload(
        summary=summary_text[:3000],
        clusters=clusters,
        evidence_refs=refs,
    )


def remediation(ctx: dict[str, Any]) -> RemediationPayload:
    finding = ctx.get("finding") or {}
    steps = [s for s in re.split(r"(?<=[.!?])\s+", finding.get("remediation", "")) if s.strip()][:10]
    if not steps:
        steps = ["Apply the vendor-recommended fix for this weakness class."]
    steps.append("Re-run a safe scan against the authorized target to confirm the fix.")
    summary_text = (
        f"Remediate {finding.get('title', 'the finding')} at {finding.get('url', '')}. "
        f"{finding.get('remediation', '')}"
    ).strip()
    return RemediationPayload(
        summary=summary_text[:2000],
        steps=[s[:500] for s in steps],
        evidence_refs=_refs(ctx, _finding_ref(finding)),
    )


def correlate(ctx: dict[str, Any]) -> CorrelationPayload:
    findings = ctx.get("findings") or []
    by_category = Counter(f.get("category", "other") for f in findings)
    by_check = Counter(f.get("check_id", "") for f in findings)
    themes = [f"{category}: {count} findings" for category, count in by_category.most_common(8)]
    repeated = [check for check, count in by_check.items() if count > 1]
    summary_text = (
        f"{len(findings)} findings cluster into {len(by_category)} categories. "
        f"Weakness classes: {', '.join(by_category.keys()) or 'none'}. "
    )
    if repeated:
        summary_text += f"Repeated checks that recur across locations: {', '.join(repeated[:5])}."
    recon = ctx.get("recon") or {}
    chains = (recon.get("correlation") or {}).get("chains") or []
    if chains:
        titles = ", ".join(chain.get("rule") or "chain" for chain in chains[:5])
        themes.append(f"Documented attack paths: {len(chains)}")
        summary_text += f" Documented attack paths: {titles}."
    return CorrelationPayload(
        summary=summary_text[:3000],
        themes=themes,
        evidence_refs=_refs(
            ctx,
            *[f"finding:{f.get('id', '')}" for f in findings[:10]],
            *recon_refs(recon)[:2],
            limit=12,
        ),
    )


def assistant_answer(ctx: dict[str, Any], question: str) -> AnswerPayload:
    findings = ctx.get("findings") or []
    recon = ctx.get("recon") or {}
    highlights = digest_highlights(recon)
    tokens = {t for t in re.split(r"[^a-z0-9]+", question.lower()) if len(t) >= 3}
    scored = []
    for finding in findings:
        haystack = " ".join(
            str(finding.get(key, "")) for key in ("title", "category", "check_id", "url", "severity")
        ).lower()
        score = sum(1 for token in tokens if token in haystack)
        if score:
            scored.append((score, finding))
    scored.sort(key=lambda item: (item[0], float(item[1].get("risk_score") or 0)), reverse=True)
    if not scored and re.search(r"(?i)\b(urgent|priorit\w*|most important|first|worst|riskiest)\b", question):
        ranked = sorted(findings, key=lambda f: float(f.get("risk_score") or 0), reverse=True)[:3]
        scored = [(1, f) for f in ranked]
    if scored:
        lines = [
            f"- {f.get('check_id', '')}: {f.get('title', 'Finding')} at {f.get('url', '')} "
            f"({f.get('severity', 'info')}, {f.get('verification_status', 'suspected')})"
            for _, f in scored[:4]
        ]
        answer = "The scan data matches these findings:\n" + "\n".join(lines)
        if highlights:
            answer += "\n\nScan intelligence:\n" + "\n".join(f"- {line}" for line in highlights[:4])
        refs = _refs(
            ctx,
            *[f"finding:{f.get('id', '')}" for _, f in scored[:4]],
            *recon_refs(recon)[:3],
            limit=10,
        )
    elif highlights:
        answer = "The scan intelligence matches:\n" + "\n".join(f"- {line}" for line in highlights[:6])
        refs = _refs(ctx, *recon_refs(recon), limit=8)
    elif findings:
        answer = (
            f"No finding matched that question. The scan recorded {len(findings)} findings; "
            "ask about a check id, category, severity, or URL from this scan."
        )
        refs = _refs(ctx, limit=3)
    else:
        answer = "No findings were recorded for this scan, so there is nothing to report on that question."
        refs = _refs(ctx, limit=3)
    return AnswerPayload(answer=answer[:4000], evidence_refs=refs)


def education(ctx: dict[str, Any]) -> EducationPayload:
    check = ctx.get("check") or {}
    learning = check.get("learning") or {}
    name = check.get("name") or check.get("id") or "This check"
    category = check.get("category") or "web application"
    tip = (
        f"Practice: pull one '{check.get('id', 'check')}' finding from a scan, read the request "
        "and response evidence, and explain in your own words which line proves the issue."
    )
    return EducationPayload(
        plain_language=f"{name} ({category}). {learning.get('what', '')}".strip()[:2000],
        why_it_matters=str(learning.get("why", ""))[:2000] or name[:2000],
        how_to_verify=str(learning.get("verify", ""))[:2000] or "Review the evidence attached to the finding.",
        practice_tip=tip[:1000],
        evidence_refs=_refs(ctx),
    )


def _endpoint_path(endpoint: dict[str, Any]) -> str:
    url = str(endpoint.get("url", ""))
    match = re.match(r"https?://[^/]+(/.*)?$", url)
    return (match.group(1) if match and match.group(1) else "/")[:300]


def _endpoint_score(endpoint: dict[str, Any]) -> tuple[int, str]:
    path = _endpoint_path(endpoint)
    score = 0
    if endpoint.get("state") == "live":
        score += 3
    if endpoint.get("parameters"):
        score += 2
    if _API_PATH.search(path):
        score += 2
    if _SENSITIVE_PATH.search(path):
        score += 1
    if endpoint.get("status_code") in (401, 403):
        score += 1
    if endpoint.get("source") in {"openapi", "graphql"}:
        score += 1
    return score, path


def endpoint_prioritize(ctx: dict[str, Any]) -> EndpointPrioritizePayload:
    endpoints = [e for e in ctx.get("endpoints") or [] if e.get("url")]
    ranked = sorted(endpoints, key=lambda e: (_endpoint_score(e)[0], e.get("url", "")), reverse=True)
    order = []
    for endpoint in ranked[:30]:
        score, path = _endpoint_score(endpoint)
        bits = [f"{endpoint.get('method', 'GET')} {path}"]
        if endpoint.get("state"):
            bits.append(str(endpoint["state"]))
        if endpoint.get("status_code"):
            bits.append(f"HTTP {endpoint['status_code']}")
        if endpoint.get("parameters"):
            bits.append("parameters: " + ", ".join(str(p) for p in endpoint["parameters"][:5]))
        order.append(
            EndpointPriorityItem(
                url=str(endpoint["url"])[:2048],
                method=str(endpoint.get("method", "GET")).upper()[:10],
                reason=("score " + str(score) + " · " + " · ".join(bits))[:500],
            )
        )
    parameterized = sum(1 for e in endpoints if e.get("parameters"))
    summary_text = (
        f"Prioritized {len(order)} of {len(endpoints)} discovered endpoints. "
        f"{parameterized} accept parameters; live endpoints and API/sensitive paths rank first."
    )
    refs = _refs(
        ctx,
        *[f"endpoint:{e.get('url', '')}" for e in ranked[:10]],
        *[f"param:{p}" for e in ranked[:5] for p in (e.get("parameters") or [])[:2]],
        limit=12,
    )
    return EndpointPrioritizePayload(summary=summary_text[:2000], order=order, evidence_refs=refs)


def next_steps(ctx: dict[str, Any]) -> NextStepsPayload:
    findings = sorted(
        ctx.get("findings") or [], key=lambda f: float(f.get("risk_score") or 0), reverse=True
    )
    steps: list[NextStepItem] = []
    for finding in findings[:8]:
        remediation = re.split(r"(?<=[.!?])\s+", str(finding.get("remediation") or ""))
        action = remediation[0] if remediation and remediation[0].strip() else "Apply the vendor fix."
        steps.append(
            NextStepItem(
                title=f"Fix {str(finding.get('title') or 'finding')[:150]}",
                detail=(
                    f"{finding.get('url', '')} ({finding.get('severity', 'info')}, "
                    f"{finding.get('verification_status', 'suspected')}). {action}"
                )[:800],
            )
        )
    endpoints = ctx.get("endpoints") or []
    if endpoints:
        unverified = sum(1 for e in endpoints if e.get("state") != "live")
        steps.append(
            NextStepItem(
                title="Review the remaining attack surface",
                detail=(
                    f"{len(endpoints)} endpoints were mapped, {unverified} still unverified. "
                    "Confirm ownership and authorization before any deeper active testing."
                )[:800],
            )
        )
    summary_text = (
        f"Next steps derived from {len(findings)} findings and {len(endpoints)} endpoints. "
        "Priorities follow risk score and verification status; every action stays inside the "
        "authorized scope."
    )
    return NextStepsPayload(
        summary=summary_text[:2000],
        steps=steps[:12],
        evidence_refs=_refs(
            ctx,
            *[f"finding:{f.get('id', '')}" for f in findings[:8]],
            *[f"endpoint:{e.get('url', '')}" for e in endpoints[:3]],
            limit=12,
        ),
    )


def js_analysis(ctx: dict[str, Any]) -> JsAnalysisPayload:
    endpoints = [e for e in ctx.get("endpoints") or [] if e.get("url")]
    js = ctx.get("js") or {}
    routes = [
        e
        for e in endpoints
        if str(e.get("source", "")).lower() in {"js", "javascript", "spa"}
        or str(e.get("url", "")).split("?")[0].endswith(".js")
    ]
    findings = ctx.get("findings") or []
    secret_findings = [f for f in findings if str(f.get("check_id", "")).startswith("venom.secrets")]
    exposures = [
        str(item)[:300] for item in (js.get("exposures") or []) if str(item).strip()
    ][:10]
    if not exposures:
        exposures = [
            f"{f.get('title', 'Exposure')} at {f.get('url', '')}" for f in secret_findings[:10]
        ]
    verified = sum(1 for e in routes if e.get("state") == "live")
    summary_text = (
        f"{len(routes)} JavaScript-derived route(s) were recovered from "
        f"{js.get('files', js.get('scripts', 'the crawled bundles'))}; "
        f"{verified} have a live response. {len(exposures)} exposure hint(s) are attached. "
        "Source maps and AST routes are analysis-only; no JavaScript is executed."
    )
    return JsAnalysisPayload(
        summary=summary_text[:3000],
        routes=[
            JsRouteItem(
                url=str(e.get("url", ""))[:2048],
                method=str(e.get("method", "GET")).upper()[:10],
                source=str(e.get("source", "js"))[:40],
                verified=e.get("state") == "live",
            )
            for e in routes[:60]
        ],
        exposures=[item[:200] for item in exposures[:20]],
        evidence_refs=_refs(
            ctx,
            *[f"js:{e.get('url', '')}" for e in routes[:8]],
            *[f"finding:{f.get('id', '')}" for f in secret_findings[:4]],
            limit=12,
        ),
    )


def api_analysis(ctx: dict[str, Any]) -> ApiAnalysisPayload:
    endpoints = [e for e in ctx.get("endpoints") or [] if e.get("url")]
    api_endpoints = [
        e
        for e in endpoints
        if str(e.get("source", "")).lower() in {"openapi", "graphql", "js", "spa"}
        or _API_PATH.search(_endpoint_path(e))
    ]
    api_findings = [
        f
        for f in ctx.get("findings") or []
        if str(f.get("check_id", "")).startswith(_API_CHECK_PREFIXES)
    ]
    auth_map = ctx.get("auth_map") or {}
    flows = auth_map.get("flows") or []
    flow_labels = [
        f"{item.get('type', 'auth')} · {item.get('method', 'GET')} {item.get('url', '')}"
        for item in flows[:10]
        if isinstance(item, dict)
    ]
    bola = ctx.get("bola_matrix") or []
    bola_candidates = [
        f"{item.get('method', 'GET')} {item.get('url', '')} · roles: "
        f"{', '.join(str(r) for r in (item.get('roles') or []))}"
        for item in bola[:10]
        if isinstance(item, dict)
    ]
    risks = [
        f"{f.get('title', 'API finding')} · {f.get('url', '')} "
        f"({f.get('severity', 'info')}, {f.get('verification_status', 'suspected')})"
        for f in sorted(api_findings, key=lambda f: float(f.get("risk_score") or 0), reverse=True)[:10]
    ]
    summary_text = (
        f"{len(api_endpoints)} API-shaped endpoint(s) and {len(api_findings)} API/authz finding(s). "
        f"{len(flow_labels)} auth flow(s) classified; {len(bola_candidates)} BOLA candidate(s) "
        "flagged for manual review. The matrix is a non-destructive scaffold: no role "
        "impersonation or credential guessing is performed."
    )
    return ApiAnalysisPayload(
        summary=summary_text[:3000],
        auth_flows=flow_labels,
        risks=[item[:300] for item in risks],
        bola_candidates=[item[:300] for item in bola_candidates],
        evidence_refs=_refs(
            ctx,
            *[f"endpoint:{e.get('url', '')}" for e in api_endpoints[:8]],
            *[f"finding:{f.get('id', '')}" for f in api_findings[:4]],
            limit=12,
        ),
    )


def fp_triage(ctx: dict[str, Any]) -> FpTriagePayload:
    reviews: list[FpTriageReview] = []
    for finding in ctx.get("findings") or []:
        status = str(finding.get("verification_status", "suspected"))
        confidence = int(finding.get("confidence", 0) or 0)
        evidence = finding.get("request_evidence") or {}
        response = finding.get("response_evidence") or {}
        if status == "verified":
            likelihood, recommendation = 0.03, "keep"
            reason = "Deterministic verifier confirmed the finding."
        elif status == "rejected":
            likelihood, recommendation = 0.95, "dismiss"
            reason = "Verifier rejected the finding."
        elif status == "suspected" and confidence >= 7 and (evidence or response):
            likelihood, recommendation = 0.35, "review"
            reason = "Suspected with high confidence and captured evidence; needs manual review."
        elif status == "suspected":
            likelihood, recommendation = 0.55, "review"
            reason = "Suspected with limited evidence; review before reporting."
        else:
            likelihood, recommendation = 0.5, "review"
            reason = "No deterministic verification signal."
        reviews.append(
            FpTriageReview(
                finding_id=str(finding.get("id", "")),
                title=str(finding.get("title", "Finding"))[:300],
                fp_likelihood=likelihood,
                recommendation=recommendation,
                reason=reason[:500],
            )
        )
    return FpTriagePayload(
        reviews=reviews[:60],
        evidence_refs=_refs(
            ctx,
            *[f"finding:{r.finding_id}" for r in reviews[:10]],
            limit=12,
        ),
    )
