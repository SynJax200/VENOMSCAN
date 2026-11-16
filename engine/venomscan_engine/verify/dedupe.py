from __future__ import annotations

from venomscan_engine.models import Finding


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Keep the highest-risk instance per dedup key, ordered by risk descending."""
    best: dict[str, Finding] = {}
    for finding in findings:
        finding.finalize()
        existing = best.get(finding.dedup_key)
        if existing is None or finding.risk_score > existing.risk_score:
            best[finding.dedup_key] = finding
    return sorted(best.values(), key=lambda f: (-f.risk_score, f.check_id, f.url))
