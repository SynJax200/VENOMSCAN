from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import Any

from venomscan_engine.correlate.rules import RULES, CorrelationRule
from venomscan_engine.models import Finding, severity_from_risk

MAX_TRIGGERS_PER_CHAIN = 5


@dataclass
class CorrelationChain:
    rule_id: str
    title: str
    multiplier: float
    surface: str
    narrative: str
    gate: Finding
    triggers: list[Finding] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "multiplier": self.multiplier,
            "surface": self.surface,
            "narrative": self.narrative,
            "gate": _finding_ref(self.gate),
            "triggers": [_finding_ref(f) for f in self.triggers],
        }


@dataclass
class CorrelationReport:
    chains: list[CorrelationChain] = field(default_factory=list)
    boosted: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "chains": [chain.as_dict() for chain in self.chains],
            "boosted_findings": self.boosted,
            "max_multiplier": max((c.multiplier for c in self.chains), default=1.0),
        }


def _finding_ref(finding: Finding) -> dict[str, Any]:
    return {
        "check_id": finding.check_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "url": finding.url,
        "parameter": finding.parameter,
        "risk_score": finding.risk_score,
        "dedup_key": finding.dedup_key,
    }


def _matches(finding: Finding, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch(finding.check_id, pattern) for pattern in patterns)


def _sort_key(finding: Finding) -> tuple[float, str, str]:
    return (-finding.risk_score, finding.check_id, finding.url)


def _select_triggers(rule: CorrelationRule, findings: list[Finding]) -> list[Finding]:
    hits = [f for f in findings if _matches(f, rule.trigger)]
    if rule.url_fragments:
        hits = [
            f
            for f in hits
            if any(fragment in f.url.lower() for fragment in rule.url_fragments)
        ]
    hits.sort(key=_sort_key)
    return hits[:MAX_TRIGGERS_PER_CHAIN]


def correlate_findings(findings: list[Finding]) -> CorrelationReport:
    """Detect documented attack-path combinations and re-score the trigger findings.

    A rule fires only when both its gate and its trigger were actually observed,
    so the narrative stays evidence-backed. Each finding is boosted at most once,
    using the strongest multiplier among the chains it participates in.
    """
    report = CorrelationReport()
    boosts: dict[int, float] = {}
    for rule in RULES:
        gates = [f for f in findings if _matches(f, rule.gate)]
        if not gates:
            continue
        triggers = _select_triggers(rule, findings)
        if not triggers:
            continue
        gates.sort(key=_sort_key)
        gate = gates[0]
        narrative = rule.narrative.format(gate=gate.title, trigger=triggers[0].title)
        report.chains.append(
            CorrelationChain(
                rule_id=rule.id,
                title=rule.title,
                multiplier=rule.multiplier,
                surface=rule.surface,
                narrative=narrative,
                gate=gate,
                triggers=triggers,
            )
        )
        for trigger in triggers:
            boosts[id(trigger)] = max(boosts.get(id(trigger), 1.0), rule.multiplier)

    boosted = 0
    for finding in findings:
        multiplier = boosts.get(id(finding))
        if multiplier is None or finding.risk_score <= 0:
            continue
        finding.risk_score = round(min(finding.risk_score * multiplier, 10.0), 2)
        finding.severity = severity_from_risk(finding.risk_score)
        boosted += 1
    report.boosted = boosted
    return report


__all__ = ["CorrelationChain", "CorrelationReport", "correlate_findings"]
