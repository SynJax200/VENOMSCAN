from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session
from venomscan_engine.ai import AnalysisResult, analyze, answer, build_provider
from venomscan_engine.ai.context import (
    recon_digest,
    recon_refs,
    recon_urls,
    relevant_sections,
    slice_digest,
)
from venomscan_engine.ai.prompts import PROMPT_VERSION
from venomscan_engine.ai.schemas import SCHEMAS, ProbePayload
from venomscan_engine.models import endpoint_state

from venomscan_api.config import get_settings
from venomscan_api.crypto import decrypt
from venomscan_api.db import session_factory, utcnow
from venomscan_api.models import AiAnalysis, AiSetting, Endpoint, Finding, Scan, Technology
from venomscan_api.services.ai_policy import AiDestinationError, validate_ai_base_url
from venomscan_api.services.finding_integrity import effective_finding_status

_URL = re.compile(r"https?://[^\s\"'<>)\]]+")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

FINDING_KINDS = ("explanation", "fp_review", "remediation")
SCAN_KINDS = (
    "summary",
    "prioritize",
    "surface_summary",
    "correlate",
    "endpoint_prioritize",
    "next_steps",
    "js_analysis",
    "api_analysis",
    "fp_triage",
)
ENDPOINT_KINDS = {
    "surface_summary",
    "endpoint_prioritize",
    "next_steps",
    "js_analysis",
    "api_analysis",
}


def _config(db: Session) -> tuple[str, str, str, str]:
    env = get_settings()
    row = db.get(AiSetting, "default")
    provider = row.provider if row else env.llm_provider
    model = row.model if row else env.llm_model
    if provider == "ollama":
        base_url = (row.base_url if row else "") or ""
        api_key = ""
    else:
        base_url = (row.base_url if row else "") or env.llm_base_url
        api_key = (decrypt(env.secret_key, row.api_key_encrypted) if row else "") or env.llm_api_key
    return provider, model, base_url, api_key


def provider_for(db: Session):
    provider, model, base_url, api_key = _config(db)
    env = get_settings()
    try:
        validate_ai_base_url(provider, base_url, env)
    except AiDestinationError:
        # A legacy or tampered row must never receive the decrypted key.
        return None
    return build_provider(
        provider,
        model=model,
        base_url=base_url,
        api_key=api_key,
        timeout=env.llm_timeout,
        retries=env.llm_retries,
    )


def _provider_and_labels(db: Session):
    provider = provider_for(db)
    if provider is None:
        return None, "fallback", "deterministic"
    return provider, getattr(provider, "name", "unknown"), getattr(provider, "model", "")


def _cache_key(kind: str, provider: str, model: str, context: dict[str, Any]) -> str:
    payload = json.dumps(
        {
            "kind": kind,
            "provider": provider,
            "model": model,
            "prompt_version": PROMPT_VERSION,
            "context": context,
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _cached_row(
    db: Session,
    *,
    kind: str,
    cache_key: str,
    finding_id: str | None = None,
    scan_id: str | None = None,
) -> AiAnalysis | None:
    ttl = max(0, get_settings().ai_cache_ttl_seconds)
    if ttl <= 0:
        return None
    query = select(AiAnalysis).where(
        AiAnalysis.kind == kind,
        AiAnalysis.fallback.is_(False),
        AiAnalysis.created_at >= utcnow() - timedelta(seconds=ttl),
    )
    if finding_id:
        query = query.where(AiAnalysis.finding_id == finding_id)
    else:
        query = query.where(AiAnalysis.scan_id == scan_id, AiAnalysis.finding_id.is_(None))
    for row in db.scalars(query.order_by(AiAnalysis.created_at.desc()).limit(20)).all():
        if ((row.payload or {}).get("meta") or {}).get("cache_key") == cache_key:
            return row
    return None


def _reused_result(row: AiAnalysis) -> AnalysisResult:
    schema = SCHEMAS[row.kind]
    payload = {
        key: value
        for key, value in (row.payload or {}).items()
        if key in schema.model_fields
    }
    return AnalysisResult(
        kind=row.kind,
        payload=schema.model_validate(payload),
        provider=row.provider,
        model=row.model,
        prompt_version=row.prompt_version,
        grounded=row.grounded,
        fallback=False,
    )


def _finding_recon(finding: Finding) -> dict[str, Any]:
    scan = finding.scan
    if scan is None:
        return {}
    return slice_digest(recon_digest(scan.recon), relevant_sections(finding.check_id))


def _finding_dict(finding: Finding) -> dict[str, Any]:
    status, _ = effective_finding_status(finding)
    return {
        "id": finding.id,
        "check_id": finding.check_id,
        "title": finding.title,
        "category": finding.category,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "verification_status": status,
        "url": finding.url,
        "method": finding.method,
        "parameter": finding.parameter,
        "payload": finding.payload,
        "description": finding.description,
        "impact": finding.impact,
        "remediation": finding.remediation,
        "references": finding.references or [],
        "cwe": finding.cwe or [],
        "owasp": finding.owasp or [],
        "cvss_score": finding.cvss_score,
        "risk_score": finding.risk_score,
        "request_evidence": finding.request_evidence or {},
        "response_evidence": finding.response_evidence or {},
    }


def _scan_dict(scan: Scan) -> dict[str, Any]:
    return {
        "id": scan.id,
        "target_name": scan.target.name if scan.target else "",
        "target_url": scan.target.url if scan.target else "",
        "profile": scan.profile,
        "status": scan.status,
        "progress": scan.progress,
        "stats": scan.stats or {},
        "findings_total": len(scan.findings),
    }


def _finding_urls(finding: Finding) -> set[str]:
    urls = {finding.url}
    blob = f"{finding.request_evidence or {}} {finding.response_evidence or {}} {finding.references or []}"
    urls.update(_URL.findall(blob))
    return urls


def _finding_cves(finding: Finding) -> set[str]:
    return {cve.upper() for cve in _CVE.findall(" ".join(finding.references or []))}


def _persist(
    db: Session,
    result: AnalysisResult,
    *,
    scan_id: str | None,
    finding_id: str | None,
    meta: dict[str, Any] | None = None,
) -> AiAnalysis:
    payload = result.payload.model_dump()
    if result.provider_error:
        payload["provider_error"] = result.provider_error
    if result.refused:
        payload["refused"] = True
    if meta:
        payload["meta"] = meta
    row = AiAnalysis(
        scan_id=scan_id,
        finding_id=finding_id,
        kind=result.kind,
        provider=result.provider,
        model=result.model,
        prompt_version=result.prompt_version,
        grounded=result.grounded,
        fallback=result.fallback,
        payload=payload,
    )
    db.add(row)
    return row


def _reuse(
    db: Session,
    *,
    kind: str,
    context: dict[str, Any],
    provider,
    provider_name: str,
    model_name: str,
    finding_id: str | None = None,
    scan_id: str | None = None,
) -> tuple[str, AnalysisResult | None]:
    key = _cache_key(kind, provider_name, model_name, context)
    if provider is None:
        return key, None
    row = _cached_row(db, kind=kind, cache_key=key, finding_id=finding_id, scan_id=scan_id)
    return key, _reused_result(row) if row is not None else None


async def run_finding(db: Session, finding: Finding, kind: str) -> AiAnalysis:
    finding_ctx: dict[str, Any] = {
        "finding": _finding_dict(finding),
        "refs": [
            f"finding:{finding.id}",
            f"scan:{finding.scan_id}",
            f"url:{finding.url}",
        ],
    }
    recon = _finding_recon(finding)
    urls = _finding_urls(finding)
    if recon:
        finding_ctx["recon"] = recon
        finding_ctx["refs"] += recon_refs(recon)
        urls |= recon_urls(recon)
    provider, provider_name, model_name = _provider_and_labels(db)
    key, reused = _reuse(
        db,
        kind=kind,
        context=finding_ctx,
        provider=provider,
        provider_name=provider_name,
        model_name=model_name,
        finding_id=finding.id,
        scan_id=finding.scan_id,
    )
    started = time.perf_counter()
    if reused is not None:
        result = reused
        meta = {"cache_key": key, "cached": True}
    else:
        result = await analyze(
            kind,
            finding_ctx,
            provider=provider,
            allowed_urls=urls,
            allowed_cves=_finding_cves(finding),
            allowed_refs=finding_ctx["refs"],
            provider_name=provider_name,
            model_name=model_name,
        )
        meta = {
            "cache_key": key,
            "cached": False,
            "duration_ms": int((time.perf_counter() - started) * 1000),
        }
    if kind == "explanation":
        finding.ai_summary = str(result.payload.summary)[:2000]
    elif kind == "fp_review":
        likelihood = getattr(result.payload, "fp_likelihood", None)
        if isinstance(likelihood, (int, float)):
            finding.ai_false_positive_likelihood = float(likelihood)
        if result.fallback:
            finding.ai_priority = "review"
    row = _persist(db, result, scan_id=finding.scan_id, finding_id=finding.id, meta=meta)
    db.commit()
    db.refresh(row)
    return row


async def run_check_education(db: Session, entry: dict[str, Any]) -> AiAnalysis:
    refs = [f"check:{entry['id']}"]
    context: dict[str, Any] = {
        "check": {
            "id": entry["id"],
            "name": entry["name"],
            "category": entry["category"],
            "profile": entry["profile"],
            "severity": entry["severity"],
            "learning": entry.get("learning") or {},
        },
        "refs": refs,
    }
    provider, provider_name, model_name = _provider_and_labels(db)
    key, reused = _reuse(
        db,
        kind="education",
        context=context,
        provider=provider,
        provider_name=provider_name,
        model_name=model_name,
    )
    started = time.perf_counter()
    if reused is not None:
        result = reused
        meta = {"cache_key": key, "cached": True}
    else:
        result = await analyze(
            "education",
            context,
            provider=provider,
            allowed_urls=(),
            allowed_cves=(),
            allowed_refs=refs,
            provider_name=provider_name,
            model_name=model_name,
        )
        meta = {
            "cache_key": key,
            "cached": False,
            "duration_ms": int((time.perf_counter() - started) * 1000),
        }
    row = _persist(db, result, scan_id=None, finding_id=None, meta=meta)
    db.commit()
    db.refresh(row)
    return row


async def run_scan(db: Session, scan: Scan, kind: str) -> AiAnalysis:
    findings = list(
        db.scalars(
            select(Finding)
            .where(Finding.scan_id == scan.id)
            .order_by(Finding.risk_score.desc())
            .limit(60)
        ).all()
    )
    findings_payload = [_finding_dict(f) for f in findings]
    refs = [f"scan:{scan.id}", *[f"finding:{f.id}" for f in findings]]
    urls = {scan.target.url} if scan.target else set()
    cves: set[str] = set()
    for finding in findings:
        urls |= _finding_urls(finding)
        cves |= _finding_cves(finding)

    context: dict[str, Any] = {
        "scan": _scan_dict(scan),
        "findings": findings_payload,
        "refs": refs,
    }
    recon = recon_digest(scan.recon)
    if recon:
        context["recon"] = recon
        context["refs"] = refs + recon_refs(recon)
        urls |= recon_urls(recon)
    if kind in ENDPOINT_KINDS:
        endpoints = list(
            db.scalars(select(Endpoint).where(Endpoint.scan_id == scan.id).limit(300)).all()
        )
        technologies = list(
            db.scalars(select(Technology).where(Technology.scan_id == scan.id)).all()
        )
        context["endpoints"] = [
            {
                "url": e.url,
                "method": e.method,
                "source": e.source,
                "status_code": e.status_code,
                "state": endpoint_state(e.source, e.status_code),
                "parameters": e.parameters or [],
            }
            for e in endpoints
        ]
        context["technologies"] = [
            {"name": t.name, "version": t.version, "category": t.category} for t in technologies
        ]
        endpoint_refs = [f"endpoint:{e.url}" for e in endpoints]
        parameter_refs = [
            f"param:{parameter}"
            for e in endpoints
            for parameter in (e.parameters or [])[:5]
        ]
        js_refs = [f"js:{e.url}" for e in endpoints if e.source in {"js", "spa"}]
        context["refs"] = context["refs"] + endpoint_refs + parameter_refs + js_refs
        urls |= {e.url for e in endpoints}
        raw_recon = scan.recon or {}
        context["js"] = raw_recon.get("js_intel") or {}
        if kind == "api_analysis":
            context["auth_map"] = raw_recon.get("auth_map") or {}
            context["bola_matrix"] = raw_recon.get("bola_matrix") or []

    provider, provider_name, model_name = _provider_and_labels(db)
    key, reused = _reuse(
        db,
        kind=kind,
        context=context,
        provider=provider,
        provider_name=provider_name,
        model_name=model_name,
        scan_id=scan.id,
    )
    started = time.perf_counter()
    if reused is not None:
        result = reused
        meta = {"cache_key": key, "cached": True}
    else:
        result = await analyze(
            kind,
            context,
            provider=provider,
            allowed_urls=urls,
            allowed_cves=cves,
            allowed_refs=context["refs"],
            provider_name=provider_name,
            model_name=model_name,
        )
        meta = {
            "cache_key": key,
            "cached": False,
            "duration_ms": int((time.perf_counter() - started) * 1000),
        }
    row = _persist(db, result, scan_id=scan.id, finding_id=None, meta=meta)
    db.commit()
    db.refresh(row)
    return row


REPORT_SCAN_KINDS = ("summary", "next_steps")
REPORT_FINDING_LIMIT = 5


async def ensure_report_analyses(
    db: Session, scan: Scan, *, finding_limit: int = REPORT_FINDING_LIMIT
) -> list[AiAnalysis]:
    """Fill the report AI section at creation time; existing rows are reused.

    The deterministic fallback keeps this offline-safe, and each scan keeps one
    row per kind so repeated report generation never duplicates analyses.
    """
    if not get_settings().ai_report_autofill:
        return []
    existing = set(
        db.scalars(
            select(AiAnalysis.kind).where(
                AiAnalysis.scan_id == scan.id, AiAnalysis.finding_id.is_(None)
            )
        ).all()
    )
    created: list[AiAnalysis] = []
    for kind in REPORT_SCAN_KINDS:
        if kind not in existing:
            created.append(await run_scan(db, scan, kind))

    findings = db.scalars(
        select(Finding)
        .where(Finding.scan_id == scan.id)
        .order_by(Finding.risk_score.desc())
        .limit(finding_limit * 3)
    ).all()
    pending = [finding for finding in findings if not finding.ai_summary][:finding_limit]
    for finding in pending:
        created.append(await run_finding(db, finding, "explanation"))
    return created


async def triage_scan(db: Session, scan: Scan, *, limit: int = 40) -> AiAnalysis | None:
    """Batch false-positive triage; deterministic when no provider is configured."""
    findings = list(
        db.scalars(
            select(Finding)
            .where(Finding.scan_id == scan.id)
            .order_by(Finding.risk_score.desc())
            .limit(limit)
        ).all()
    )
    if not findings:
        return None
    context: dict[str, Any] = {
        "scan": _scan_dict(scan),
        "findings": [_finding_dict(f) for f in findings],
        "refs": [f"scan:{scan.id}", *[f"finding:{f.id}" for f in findings]],
    }
    provider, provider_name, model_name = _provider_and_labels(db)
    key, reused = _reuse(
        db,
        kind="fp_triage",
        context=context,
        provider=provider,
        provider_name=provider_name,
        model_name=model_name,
        scan_id=scan.id,
    )
    started = time.perf_counter()
    if reused is not None:
        result = reused
        meta = {"cache_key": key, "cached": True, "automatic": True}
    else:
        result = await analyze(
            "fp_triage",
            context,
            provider=provider,
            allowed_urls=(),
            allowed_cves=(),
            allowed_refs=context["refs"],
            provider_name=provider_name,
            model_name=model_name,
        )
        meta = {
            "cache_key": key,
            "cached": False,
            "automatic": True,
            "duration_ms": int((time.perf_counter() - started) * 1000),
        }
    row = _persist(db, result, scan_id=scan.id, finding_id=None, meta=meta)
    by_id = {finding.id: finding for finding in findings}
    for review in getattr(result.payload, "reviews", []):
        finding = by_id.get(str(review.finding_id))
        if finding is None:
            continue
        finding.ai_false_positive_likelihood = float(review.fp_likelihood)
        if review.recommendation in {"review", "dismiss"}:
            finding.ai_priority = review.recommendation
    db.commit()
    db.refresh(row)
    return row


async def auto_triage_scan(scan_id: str) -> None:
    """Pipeline hook: called after a scan is persisted; never blocks completion."""
    if not get_settings().ai_auto_triage:
        return
    with session_factory()() as db:
        scan = db.get(Scan, scan_id)
        if scan is not None:
            await triage_scan(db, scan)


async def ask(db: Session, scan: Scan, question: str) -> AiAnalysis:
    findings = list(
        db.scalars(
            select(Finding)
            .where(Finding.scan_id == scan.id)
            .order_by(Finding.risk_score.desc())
            .limit(60)
        ).all()
    )
    endpoints = list(
        db.scalars(select(Endpoint).where(Endpoint.scan_id == scan.id).limit(200)).all()
    )
    refs = [f"scan:{scan.id}", *[f"finding:{f.id}" for f in findings]]
    urls = {scan.target.url if scan.target else ""}
    for finding in findings:
        urls |= _finding_urls(finding)
    recon = recon_digest(scan.recon)
    context: dict[str, Any] = {
        "scan": _scan_dict(scan),
        "findings": [_finding_dict(f) for f in findings],
        "endpoints": [{"url": e.url, "method": e.method, "source": e.source} for e in endpoints],
        "refs": refs,
        "question": question,
    }
    if recon:
        context["recon"] = recon
        context["refs"] = refs + recon_refs(recon)
        urls |= recon_urls(recon)
    provider, provider_name, model_name = _provider_and_labels(db)
    key, reused = _reuse(
        db,
        kind="assistant",
        context=context,
        provider=provider,
        provider_name=provider_name,
        model_name=model_name,
        scan_id=scan.id,
    )
    started = time.perf_counter()
    if reused is not None:
        result = reused
        meta = {"cache_key": key, "cached": True}
    else:
        result = await answer(
            question,
            context,
            provider=provider,
            allowed_hosts={scan.target.host if scan.target else ""},
            allowed_urls=urls,
            allowed_refs=context["refs"],
            provider_name=provider_name,
            model_name=model_name,
        )
        meta = {
            "cache_key": key,
            "cached": False,
            "duration_ms": int((time.perf_counter() - started) * 1000),
        }
    row = _persist(db, result, scan_id=scan.id, finding_id=None, meta=meta)
    db.commit()
    db.refresh(row)
    return row


async def test_provider(db: Session) -> dict[str, Any]:
    """One tiny structured call against the configured provider; no target traffic."""
    provider, provider_name, model_name = _provider_and_labels(db)
    if provider is None:
        return {
            "configured": False,
            "reachable": False,
            "provider": provider_name,
            "model": model_name,
            "latency_ms": 0,
            "error": "No provider configured; analyses run on the deterministic fallback.",
        }
    started = time.perf_counter()
    try:
        payload = await provider.complete(
            system="You are a connectivity probe. Reply with the requested JSON only.",
            user='Return exactly {"ok": true, "note": "pong"} as a JSON object.',
            schema=ProbePayload,
            max_tokens=40,
        )
        latency = int((time.perf_counter() - started) * 1000)
        ok = bool(getattr(payload, "ok", False))
        return {
            "configured": True,
            "reachable": ok,
            "provider": provider_name,
            "model": model_name,
            "latency_ms": latency,
            "error": "" if ok else "Provider answered but did not confirm the probe.",
        }
    except Exception as exc:  # noqa: BLE001 - the self-test reports failures, never raises
        return {
            "configured": True,
            "reachable": False,
            "provider": provider_name,
            "model": model_name,
            "latency_ms": int((time.perf_counter() - started) * 1000),
            "error": (str(exc) or exc.__class__.__name__)[:300],
        }
