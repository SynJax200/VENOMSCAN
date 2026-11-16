from __future__ import annotations

import json

import pytest
from venomscan_engine.checks import check_catalog
from venomscan_engine.learning import build_exercises, build_walkthrough, curriculum
from venomscan_engine.learning import paths as paths_module
from venomscan_engine.learning.exercises import STEP_TITLES


def _catalog() -> list[dict]:
    return check_catalog()


def _catalog_map() -> dict[str, dict]:
    return {entry["id"]: entry for entry in _catalog()}


def _finding(**overrides) -> dict:
    base = {
        "id": "finding-1",
        "scan_id": "scan-1",
        "check_id": "venom.info.server",
        "title": "Server banner discloses nginx version",
        "category": "disclosure",
        "severity": "low",
        "verification_status": "verified",
        "confidence": 8,
        "risk_score": 3.42,
        "url": "https://demo.local/app?token=secret",
        "method": "GET",
        "remediation": "Suppress the version token in the Server header.",
        "references": ["https://nginx.org/en/docs/http/server_names.html"],
        "request_evidence": {
            "method": "GET",
            "url": "https://demo.local/app",
            "headers": {
                "Authorization": "Bearer super-secret-token",
                "Cookie": "session=abc123",
                "Accept": "text/html",
            },
        },
        "response_evidence": {
            "servers": ["nginx/1.18.0"],
            "status_code": 200,
            "headers": {"Server": "nginx/1.18.0", "Set-Cookie": "session=abc123; HttpOnly"},
        },
    }
    base.update(overrides)
    return base


def test_curriculum_covers_every_registered_check_once():
    data = curriculum()
    catalog = _catalog_map()
    assert data["check_count"] == len(catalog) == 34
    assert [track["id"] for track in data["tracks"]] == [
        "surface",
        "transport",
        "browser",
        "access",
        "discovery",
        "injection",
    ]
    covered: list[str] = []
    for track in data["tracks"]:
        assert track["level"] in {"beginner", "intermediate", "advanced"}
        assert track["focus"] and track["outcome"]
        assert track["check_ids"] == [lesson["id"] for lesson in track["lessons"]]
        for lesson in track["lessons"]:
            assert lesson["objective"]
            assert lesson["what"] and lesson["why"] and lesson["verify"]
            assert lesson["category"] == catalog[lesson["id"]]["category"]
            covered.append(lesson["id"])
    assert sorted(covered) == sorted(catalog)


def test_curriculum_maps_levels_to_scan_profiles_with_consent():
    data = curriculum()
    expected = {
        "beginner": "passive",
        "intermediate": "safe",
        "advanced": "active",
    }
    assert paths_module.LEVEL_PROFILES.keys() == expected.keys()
    for track in data["tracks"]:
        assert track["scan_profile"] == expected[track["level"]]
        assert track["consent"]
        if track["scan_profile"] == "active":
            assert "authoriz" in track["consent"].lower()


def test_curriculum_rejects_unknown_check_ids(monkeypatch):
    broken = (
        {
            "id": "broken",
            "title": "Broken",
            "level": "beginner",
            "focus": "f",
            "outcome": "o",
            "lessons": {"venom.does.not_exist": "objective"},
        },
    )
    monkeypatch.setattr(paths_module, "TRACKS", broken)
    with pytest.raises(ValueError, match="unknown check"):
        curriculum()


def test_curriculum_flags_duplicate_lessons(monkeypatch):
    catalog = _catalog_map()
    duplicate_id = sorted(catalog)[0]
    broken = (
        {
            "id": "one",
            "title": "One",
            "level": "beginner",
            "focus": "f",
            "outcome": "o",
            "lessons": {duplicate_id: "a"},
        },
        {
            "id": "two",
            "title": "Two",
            "level": "beginner",
            "focus": "f",
            "outcome": "o",
            "lessons": {duplicate_id: "b"},
        },
    )
    monkeypatch.setattr(paths_module, "TRACKS", broken)
    with pytest.raises(ValueError, match="duplicates"):
        curriculum()


def _clip(text: str, limit: int = 200) -> str:
    value = " ".join(str(text).split())
    return value if len(value) <= limit else value[: limit - 1] + "…"


def test_walkthrough_steps_are_grounded_and_redacted():
    walkthrough = build_walkthrough(_finding(), _catalog_map()["venom.info.server"]["learning"])
    assert [step["key"] for step in walkthrough["steps"]] == [
        "scope",
        "reproduce",
        "signal",
        "judge",
        "fix",
    ]
    assert walkthrough["steps"][0]["evidence"] == {
        "method": "GET",
        "url": "https://demo.local/app?token=[redacted]",
    }
    reproduce = walkthrough["steps"][1]["evidence"]
    assert reproduce["headers.Authorization"] == "[redacted]"
    assert reproduce["headers.Cookie"] == "[redacted]"
    assert reproduce["headers.Accept"] == "text/html"
    signal = walkthrough["steps"][2]["evidence"]
    assert signal["servers"] == "nginx/1.18.0"
    assert signal["headers.Set-Cookie"] == "[redacted]"
    assert walkthrough["learning"]["what"]
    assert "Stay inside the authorization" in walkthrough["safety"]
    assert walkthrough["questions"]
    dumped = json.dumps(walkthrough)
    assert "super-secret-token" not in dumped
    assert "session=abc123" not in dumped


def test_walkthrough_handles_missing_evidence():
    finding = _finding(request_evidence={}, response_evidence={}, references=None)
    walkthrough = build_walkthrough(finding, {})
    assert walkthrough["steps"][1]["evidence"] == {}
    assert walkthrough["steps"][2]["evidence"] == {}
    assert walkthrough["references"] == []
    assert walkthrough["learning"] == {}


def test_exercises_are_deterministic_and_answerable():
    entry = _catalog_map()["venom.info.server"]
    siblings = [
        {"id": "finding-2", "title": "Missing HSTS", "risk_score": 6.1},
        {"id": "finding-3", "title": "Open redirect", "risk_score": 4.0},
    ]
    first = build_exercises(_finding(), entry["learning"], _catalog(), siblings)
    second = build_exercises(_finding(), entry["learning"], _catalog(), siblings)
    assert first == second
    assert [item["type"] for item in first] == [
        "evidence_read",
        "verify_path",
        "step_order",
        "risk_triage",
    ]
    for item in first:
        assert item["answer"], item["explanation"]
        assert set(item["answer"]) <= set(item["options"])
    verify = next(item for item in first if item["type"] == "verify_path")
    assert verify["answer"] == [_clip(entry["learning"]["verify"])]
    order = next(item for item in first if item["type"] == "step_order")
    assert order["answer"] == STEP_TITLES
    assert sorted(order["options"]) == sorted(STEP_TITLES)
    triage = next(item for item in first if item["type"] == "risk_triage")
    assert triage["answer"] == [
        "Missing HSTS",
        "Open redirect",
        "Server banner discloses nginx version",
    ]


def test_exercises_skip_unavailable_types():
    finding = _finding(response_evidence={})
    exercises = build_exercises(finding, _catalog_map()["venom.info.server"]["learning"], _catalog())
    types = [item["type"] for item in exercises]
    assert "evidence_read" not in types
    assert "risk_triage" not in types
    assert types == ["verify_path", "step_order"]
