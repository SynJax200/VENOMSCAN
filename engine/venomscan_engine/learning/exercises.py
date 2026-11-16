from __future__ import annotations

import random
from typing import Any

STEP_TITLES = [
    "Confirm scope",
    "Reproduce once",
    "Read the signal",
    "Judge the evidence",
    "Remediate and re-test",
]

DECOY_EVIDENCE_KEYS = [
    "status_code",
    "content_length",
    "redirect_chain",
    "dns_records",
    "x-frame-options",
    "response_time_ms",
]

_CLIP = 200


def _clip(text: Any, limit: int = _CLIP) -> str:
    value = " ".join(str(text or "").split())
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _rng(finding_id: str, kind: str) -> random.Random:
    return random.Random(f"{finding_id}:{kind}")


def _evidence_exercise(finding: dict, rng: random.Random) -> dict | None:
    evidence = finding.get("response_evidence") or {}
    keys = sorted(str(key) for key in evidence)
    if not keys:
        return None
    correct = keys[0]
    decoys = [key for key in DECOY_EVIDENCE_KEYS if key not in evidence][:3]
    if len(decoys) < 3:
        return None
    options = [correct, *decoys]
    rng.shuffle(options)
    return {
        "id": f"{finding['id']}:evidence",
        "type": "evidence_read",
        "prompt": "Which evidence key was actually captured in this finding's response?",
        "options": options,
        "answer": [correct],
        "multi": False,
        "explanation": f"The recorded response evidence keys are: {', '.join(keys)}.",
    }


def _verify_exercise(finding: dict, learning: dict, catalog: list[dict], rng: random.Random) -> dict | None:
    correct = _clip(learning.get("verify"))
    if not correct:
        return None
    others = [
        _clip(entry.get("learning", {}).get("verify"))
        for entry in catalog
        if entry.get("id") != finding.get("check_id") and entry.get("learning", {}).get("verify")
    ]
    others = list(dict.fromkeys(others))
    if len(others) < 2:
        return None
    rng.shuffle(others)
    options = [correct, *others[:2]]
    rng.shuffle(options)
    return {
        "id": f"{finding['id']}:verify",
        "type": "verify_path",
        "prompt": "Which manual verification belongs to this check?",
        "options": options,
        "answer": [correct],
        "multi": False,
        "explanation": f"This check is \"{finding.get('title', '')}\"; the other options verify different checks.",
    }


def _order_exercise(finding: dict, rng: random.Random) -> dict:
    options = list(STEP_TITLES)
    rng.shuffle(options)
    return {
        "id": f"{finding['id']}:order",
        "type": "step_order",
        "prompt": "Put the verification walkthrough back into the correct order.",
        "options": options,
        "answer": list(STEP_TITLES),
        "multi": True,
        "explanation": "Scope first, then one reproduction, then read the signal, judge it, and only then remediate.",
    }


def _triage_exercise(finding: dict, siblings: list[dict], rng: random.Random) -> dict | None:
    pool = [finding]
    seen = {finding.get("id")}
    for row in siblings:
        if row.get("id") in seen:
            continue
        pool.append(row)
        seen.add(row.get("id"))
        if len(pool) == 3:
            break
    if len(pool) < 2:
        return None
    ordered = sorted(pool, key=lambda row: (-float(row.get("risk_score") or 0), str(row.get("id"))))
    options = [_clip(row.get("title"), 120) for row in pool]
    rng.shuffle(options)
    return {
        "id": f"{finding['id']}:triage",
        "type": "risk_triage",
        "prompt": "Order these findings from highest to lowest risk score.",
        "options": options,
        "answer": [_clip(row.get("title"), 120) for row in ordered],
        "multi": True,
        "explanation": "; ".join(
            f"{_clip(row.get('title'), 80)} = {float(row.get('risk_score') or 0):.1f}" for row in ordered
        ),
    }


def build_exercises(
    finding: dict,
    learning: dict,
    catalog: list[dict],
    siblings: list[dict] | None = None,
) -> list[dict]:
    """Deterministic practice questions grounded in this finding's stored evidence."""
    finding_id = str(finding.get("id") or "finding")
    candidates = [
        _evidence_exercise(finding, _rng(finding_id, "evidence")),
        _verify_exercise(finding, learning, catalog, _rng(finding_id, "verify")),
        _order_exercise(finding, _rng(finding_id, "order")),
        _triage_exercise(finding, siblings or [], _rng(finding_id, "triage")),
    ]
    return [exercise for exercise in candidates if exercise is not None]
