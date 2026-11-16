from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
import tempfile

from venomscan_engine.models import Finding, Severity, VerificationStatus
from venomscan_engine.plugins.spec import PluginSpec
from venomscan_engine.safety.scope import Scope, ScopeViolation

_MAX_STDOUT_BYTES = 1_000_000
_MAX_PAYLOAD_BYTES = 300_000
_SYSTEM_ENV = {
    "PATH",
    "HOME",
    "USERPROFILE",
    "LANG",
    "LC_ALL",
    "TMP",
    "TEMP",
    "TMPDIR",
    "SYSTEMROOT",
    "WINDIR",
    "SYSTEMDRIVE",
    "PATHEXT",
}
_SEVERITIES = {item.value for item in Severity}


class PluginError(RuntimeError):
    pass


def clean_env() -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if key in _SYSTEM_ENV}


async def _read_capped(stream: asyncio.StreamReader, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            chunks.append(chunk[: limit - (total - len(chunk))])
            break
        chunks.append(chunk)
    return b"".join(chunks)


def _kill(process: asyncio.subprocess.Process) -> None:
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        else:
            process.kill()
    except (ProcessLookupError, PermissionError, AttributeError):
        pass


def _to_finding(spec: PluginSpec, item: dict, scope: Scope) -> Finding | None:
    url = str(item.get("url") or "")
    try:
        scope.check(url)
    except ScopeViolation:
        return None
    severity = str(item.get("severity") or spec.severity).lower()
    if severity not in _SEVERITIES:
        severity = spec.severity
    return Finding(
        check_id=spec.check_id,
        title=str(item.get("title"))[:300],
        category=str(item.get("category") or spec.category)[:60],
        severity=Severity(severity),
        confidence=int(item.get("confidence") or 5),
        verification_status=VerificationStatus.SUSPECTED,
        url=url,
        method="GET",
        parameter=item.get("parameter"),
        payload=item.get("payload"),
        description=str(item.get("description")),
        impact=str(item.get("impact")),
        remediation=str(item.get("remediation")),
        references=list(item.get("references") or []),
        cwe=list(item.get("cwe") or []),
        request_evidence={"source": "plugin", "plugin": spec.check_id},
        response_evidence={"url": url},
    ).finalize()


async def run_plugin(spec: PluginSpec, payload: dict, scope: Scope) -> list[Finding]:
    """Execute one plugin in a subprocess; findings are re-scoped and re-scored here."""
    request = json.dumps(
        {
            "path": spec.path,
            "payload": payload,
            "memory_mb": spec.memory_mb,
            "timeout_seconds": spec.timeout_seconds,
        }
    ).encode()
    if len(request) > _MAX_PAYLOAD_BYTES:
        raise PluginError("plugin payload exceeds 300 KB")

    kwargs: dict = {}
    if os.name == "posix":
        kwargs["start_new_session"] = True
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-I",
        "-m",
        "venomscan_engine.plugins.worker",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=clean_env(),
        cwd=tempfile.gettempdir(),
        **kwargs,
    )
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    try:
        process.stdin.write(request)
        await process.stdin.drain()
        process.stdin.close()
        stdout, stderr = await asyncio.wait_for(
            asyncio.gather(
                _read_capped(process.stdout, _MAX_STDOUT_BYTES),
                _read_capped(process.stderr, 16_000),
            ),
            timeout=spec.timeout_seconds,
        )
        await asyncio.wait_for(process.wait(), timeout=2)
    except TimeoutError as exc:
        _kill(process)
        await process.wait()
        raise PluginError(
            f"plugin {spec.check_id} exceeded {spec.timeout_seconds}s and was stopped"
        ) from exc

    try:
        response = json.loads(stdout.decode("utf-8", "replace") or "{}")
    except json.JSONDecodeError as exc:
        detail = stderr.decode("utf-8", "replace").strip()[-300:]
        raise PluginError(
            f"plugin {spec.check_id} returned invalid output"
            + (f": {detail}" if detail else "")
        ) from exc
    if response.get("error"):
        raise PluginError(f"plugin {spec.check_id} failed: {response['error']}")

    findings: list[Finding] = []
    for item in response.get("findings") or []:
        if not isinstance(item, dict):
            continue
        finding = _to_finding(spec, item, scope)
        if finding is not None:
            findings.append(finding)
        if len(findings) >= 25:
            break
    return findings


def plugin_payload(ctx, *, endpoints: int = 200, findings: int = 100) -> dict:
    """Build the read-only analysis payload handed to an isolated plugin."""
    root = ctx.root.evidence() if ctx.root is not None else {}
    return {
        "scan_id": ctx.scan_id,
        "target_url": ctx.target_url,
        "profile": ctx.profile,
        "root": root,
        "technologies": [tech.model_dump(mode="json") for tech in ctx.technologies],
        "endpoints": [
            {
                "url": endpoint.url,
                "method": endpoint.method,
                "status_code": endpoint.status_code,
                "source": endpoint.source,
                "state": endpoint.state,
            }
            for endpoint in ctx.endpoints[:endpoints]
        ],
        "findings": [
            {
                "check_id": finding.check_id,
                "title": finding.title,
                "severity": finding.severity.value,
                "url": finding.url,
                "verification_status": finding.verification_status.value,
            }
            for finding in ctx.findings[:findings]
        ],
    }


def plugin_dirs_from_env(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())
