from __future__ import annotations

import json
from pathlib import Path

import pytest
from venomscan_engine.integrations import (
    BurpImportError,
    NucleiConfig,
    NucleiError,
    export_burp_xml,
    import_burp,
    run_nuclei,
)
from venomscan_engine.integrations.nuclei import parse_nuclei_output
from venomscan_engine.safety.http import validate_proxy_url
from venomscan_engine.safety.scope import Scope

SCOPE = Scope.from_target("https://demo.example.test/")


def _nuclei_config(tmp_path: Path) -> NucleiConfig:
    binary = tmp_path / "nuclei"
    binary.write_text("#!/bin/sh\necho\n")
    binary.chmod(0o755)
    return NucleiConfig(
        binary=str(binary),
        templates=str(tmp_path),
        severities=("info", "low", "medium"),
        rate_limit=5,
        timeout=30,
    )


def test_nuclei_config_validates_caps(tmp_path) -> None:
    config = _nuclei_config(tmp_path)
    config.validate()
    with pytest.raises(NucleiError):
        NucleiConfig(binary="nuclei").validate()
    with pytest.raises(NucleiError):
        NucleiConfig(binary=config.binary, severities=("unknown",)).validate()
    with pytest.raises(NucleiError):
        NucleiConfig(binary=config.binary, rate_limit=50).validate()
    with pytest.raises(NucleiError):
        NucleiConfig(binary=config.binary, timeout=2).validate()


def test_nuclei_argv_and_clean_env(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("LLM_API_KEY", "should-not-leak")
    monkeypatch.setenv("DATABASE_URL", "postgresql://secret")
    config = _nuclei_config(tmp_path)
    argv = config.argv("https://demo.example.test/")
    assert argv[0] == config.binary
    assert "-severity" in argv and argv[argv.index("-severity") + 1] == "info,low,medium"
    assert argv[argv.index("-rate-limit") + 1] == "5"
    assert "https://demo.example.test/" == argv[argv.index("-target") + 1]
    env = config.clean_env()
    assert "LLM_API_KEY" not in env
    assert "DATABASE_URL" not in env


def test_parse_nuclei_output_maps_and_filters_scope() -> None:
    lines = [
        {
            "template-id": "exposed-panel",
            "info": {
                "name": "Exposed admin panel",
                "severity": "medium",
                "description": "An admin panel is reachable.",
                "reference": ["https://example.test/ref"],
                "classification": {"cwe-id": ["CWE-284"], "cvss-score": 5.3},
            },
            "matched-at": "https://demo.example.test/admin",
            "matcher-name": "status-200",
            "type": "http",
            "request": "GET /admin HTTP/1.1\nAuthorization: Bearer abcdefghijklmnop",
            "response": "HTTP/1.1 200 OK\n\ndashboard",
        },
        {
            "template-id": "out-of-scope",
            "info": {"name": "Other host", "severity": "high"},
            "matched-at": "https://evil.example.com/",
        },
    ]
    payload = "\n".join(json.dumps(line) for line in lines).encode()
    findings = parse_nuclei_output(payload, SCOPE)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.check_id == "nuclei.exposed-panel"
    assert finding.severity.value == "medium"
    assert finding.cwe == ["CWE-284"]
    assert finding.cvss_score == 5.3
    assert finding.method == "GET"
    assert "«redacted»" in finding.request_evidence["request"]
    assert finding.risk_score > 0


async def test_run_nuclei_times_out_and_kills_process(tmp_path, monkeypatch) -> None:
    config = _nuclei_config(tmp_path)
    killed = {"value": False}

    class FakeProcess:
        returncode = None
        stdout = object()
        stderr = object()

        async def wait(self):
            return 0

        def kill(self):
            killed["value"] = True

    async def fake_exec(*args, **kwargs):
        return FakeProcess()

    async def fake_wait_for(awaitable, timeout=None):  # noqa: ASYNC109
        raise TimeoutError

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
    monkeypatch.setattr("venomscan_engine.integrations.nuclei.asyncio.wait_for", fake_wait_for)
    with pytest.raises(NucleiError):
        await run_nuclei(config, "https://demo.example.test/", SCOPE)
    assert killed["value"] is True


def test_burp_xml_import_maps_fields_and_rejects_out_of_scope() -> None:
    xml = b"""<?xml version="1.0"?>
    <issues burpVersion="2024.1">
      <issue>
        <name><![CDATA[SQL injection]]></name>
        <host ip="127.0.0.1">demo.example.test</host>
        <path><![CDATA[/search]]></path>
        <location><![CDATA[https://demo.example.test/search]]></location>
        <severity>High</severity>
        <confidence>Certain</confidence>
        <issueDetail><![CDATA[Quote parameter returns SQL error.]]></issueDetail>
        <remediationDetail><![CDATA[Use parameterised queries.]]></remediationDetail>
        <references><![CDATA[https://owasp.org/sqli]]></references>
      </issue>
    </issues>"""
    imported = import_burp(xml, fmt="xml", scope=SCOPE)
    assert len(imported.findings) == 1
    finding = imported.findings[0]
    assert finding.severity.value == "high"
    assert finding.confidence == 9
    assert finding.check_id == "burp.import.sql_injection"
    assert finding.references == ["https://owasp.org/sqli"]

    hostile = xml.replace(b"https://demo.example.test/search", b"https://evil.example.com/")
    with pytest.raises(BurpImportError):
        import_burp(hostile, fmt="xml", scope=SCOPE)


def test_burp_json_import_and_export_roundtrip() -> None:
    payload = json.dumps(
        [
            {
                "name": "Missing security headers",
                "severity": "Low",
                "confidence": "Firm",
                "url": "https://demo.example.test/",
                "detail": "No CSP.",
                "remediation": "Add CSP.",
                "references": ["https://owasp.org/headers"],
            }
        ]
    ).encode()
    imported = import_burp(payload, fmt="json", scope=SCOPE)
    assert len(imported.findings) == 1
    exported = export_burp_xml(imported.findings)
    again = import_burp(exported, fmt="xml", scope=SCOPE)
    assert len(again.findings) == 1
    assert again.findings[0].title == "Missing security headers"
    assert again.findings[0].severity.value == "low"
    assert again.findings[0].url == "https://demo.example.test/"
    assert "Add CSP." in again.findings[0].remediation


def test_proxy_url_validation() -> None:
    assert validate_proxy_url("http://127.0.0.1:8080") == "http://127.0.0.1:8080"
    assert validate_proxy_url("") is None
    assert validate_proxy_url(None) is None
    with pytest.raises(ValueError):
        validate_proxy_url("socks5://127.0.0.1:1080")
    with pytest.raises(ValueError):
        validate_proxy_url("file:///etc/passwd")


def test_nuclei_templates_must_be_absolute_directory(tmp_path) -> None:
    binary = tmp_path / "nuclei.bin"
    binary.write_text("")
    with pytest.raises(NucleiError):
        NucleiConfig(binary=str(binary), templates="templates").validate()
    with pytest.raises(NucleiError):
        NucleiConfig(binary="nuclei", templates=str(tmp_path)).validate()
