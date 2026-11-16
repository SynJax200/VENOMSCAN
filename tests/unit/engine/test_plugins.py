from __future__ import annotations

import time

import pytest
from venomscan_engine.plugins import PluginError, discover_plugins, run_plugin
from venomscan_engine.safety.scope import Scope

SCOPE = Scope.from_target("https://demo.example.test/")

PLUGIN = '''
CHECK_ID = "venom.plugin.demo"
NAME = "Demo plugin"
CATEGORY = "demo"
SEVERITY = "low"
PROFILE = "safe"
TIMEOUT_SECONDS = 5
raise RuntimeError("discovery must not execute this module")

def run(payload):
    return []
'''


def _write(tmp_path, name: str, source: str):
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    return path


def test_discovery_reads_metadata_without_executing(tmp_path) -> None:
    _write(tmp_path, "demo.py", PLUGIN)
    specs, problems = discover_plugins([str(tmp_path)])
    assert problems == []
    assert len(specs) == 1
    spec = specs[0]
    assert spec.check_id == "venom.plugin.demo"
    assert spec.profile == "safe"
    assert spec.timeout_seconds == 5


def test_discovery_reports_invalid_contract(tmp_path) -> None:
    _write(
        tmp_path,
        "bad_id.py",
        'CHECK_ID = "demo"\nNAME = "x"\nCATEGORY = "c"\nSEVERITY = "low"\nPROFILE = "safe"\n'
        "def run(payload):\n    return []\n",
    )
    _write(
        tmp_path,
        "bad_sev.py",
        'CHECK_ID = "venom.plugin.bad"\nNAME = "x"\nCATEGORY = "c"\nSEVERITY = "oops"\n'
        'PROFILE = "safe"\ndef run(payload):\n    return []\n',
    )
    _write(tmp_path, "_skip.py", PLUGIN)
    specs, problems = discover_plugins([str(tmp_path)])
    assert specs == []
    assert any("CHECK_ID" in problem for problem in problems)
    assert any("SEVERITY" in problem for problem in problems)
    assert len(problems) == 2


def test_discovery_flags_duplicate_ids(tmp_path) -> None:
    clean = PLUGIN.replace('raise RuntimeError("discovery must not execute this module")', "pass")
    _write(tmp_path, "one.py", clean)
    _write(tmp_path, "two.py", clean)
    specs, problems = discover_plugins([str(tmp_path)])
    assert len(specs) == 1
    assert any("duplicate" in problem for problem in problems)


async def test_plugin_runs_isolated_and_drops_out_of_scope_findings(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("LLM_API_KEY", "leak-secret-value")
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@db/venom")
    source = '''
import os

CHECK_ID = "venom.plugin.demo"
NAME = "Demo plugin"
CATEGORY = "demo"
SEVERITY = "low"
PROFILE = "safe"
TIMEOUT_SECONDS = 10

def run(payload):
    return [
        {
            "title": "In-scope observation",
            "description": "env token=" + os.environ.get("LLM_API_KEY", "missing"),
            "impact": "impact",
            "remediation": "fix",
            "url": payload["target_url"],
            "confidence": 7,
        },
        {
            "title": "Out-of-scope observation",
            "description": "should be dropped",
            "impact": "impact",
            "remediation": "fix",
            "url": "https://evil.example.com/admin",
        },
    ]
'''
    _write(tmp_path, "demo.py", source)
    specs, problems = discover_plugins([str(tmp_path)])
    assert problems == []
    findings = await run_plugin(
        specs[0],
        {"target_url": "https://demo.example.test/app", "scan_id": "s1", "profile": "safe"},
        SCOPE,
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.check_id == "venom.plugin.demo"
    assert finding.risk_score > 0
    assert "leak-secret-value" not in finding.description
    assert "missing" in finding.description


async def test_plugin_timeout_is_enforced(tmp_path) -> None:
    source = '''
CHECK_ID = "venom.plugin.spin"
NAME = "Spin"
CATEGORY = "demo"
SEVERITY = "info"
PROFILE = "safe"
TIMEOUT_SECONDS = 1

def run(payload):
    while True:
        pass
'''
    _write(tmp_path, "spin.py", source)
    specs, _ = discover_plugins([str(tmp_path)])
    started = time.monotonic()
    with pytest.raises(PluginError):
        await run_plugin(
            specs[0],
            {"target_url": "https://demo.example.test/", "scan_id": "s1", "profile": "safe"},
            SCOPE,
        )
    assert time.monotonic() - started < 8


async def test_plugin_with_invalid_output_fails_cleanly(tmp_path) -> None:
    source = '''
CHECK_ID = "venom.plugin.broken"
NAME = "Broken"
CATEGORY = "demo"
SEVERITY = "info"
PROFILE = "safe"

def run(payload):
    return "not a list"
'''
    _write(tmp_path, "broken.py", source)
    specs, _ = discover_plugins([str(tmp_path)])
    with pytest.raises(PluginError):
        await run_plugin(
            specs[0],
            {"target_url": "https://demo.example.test/", "scan_id": "s1", "profile": "safe"},
            SCOPE,
        )
