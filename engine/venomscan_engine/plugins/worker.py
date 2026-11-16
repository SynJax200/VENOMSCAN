"""Isolated plugin executor.

Launched by ``runner.run_plugin`` as ``python -I -m venomscan_engine.plugins.worker``
with a scrubbed environment. Plugins receive a read-only analysis payload and may
not perform network requests; any finding URL is re-validated by the parent.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import inspect
import json
import sys
from pathlib import Path

_MAX_ITEMS = 25


def _limit_resources(memory_mb: int, timeout_seconds: int) -> None:
    try:
        import resource
    except ImportError:  # Windows has no POSIX resource limits
        return
    limit = memory_mb * 1024 * 1024
    with contextlib.suppress(ValueError, OSError):
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    with contextlib.suppress(ValueError, OSError):
        resource.setrlimit(
            resource.RLIMIT_CPU, (timeout_seconds + 1, timeout_seconds + 2)
        )


def _text(value, limit: int, default: str = "") -> str:
    if not isinstance(value, str):
        return default
    return value[:limit]


def _list(value, limit: int = 10) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_text(item, 500) for item in value if isinstance(item, str)][:limit]


def _clean_findings(result) -> list[dict]:
    if not isinstance(result, list):
        raise ValueError("run(payload) must return a list of finding dicts")
    findings: list[dict] = []
    for item in result[:_MAX_ITEMS]:
        if not isinstance(item, dict):
            continue
        title = _text(item.get("title"), 300)
        description = _text(item.get("description"), 4000)
        impact = _text(item.get("impact"), 4000)
        remediation = _text(item.get("remediation"), 4000)
        url = _text(item.get("url"), 2048)
        if not (title and description and impact and remediation and url):
            continue
        confidence = item.get("confidence", 5)
        if not isinstance(confidence, int) or not 0 <= confidence <= 10:
            confidence = 5
        findings.append(
            {
                "title": title,
                "description": description,
                "impact": impact,
                "remediation": remediation,
                "url": url,
                "severity": _text(item.get("severity"), 16).lower(),
                "category": _text(item.get("category"), 60),
                "confidence": confidence,
                "parameter": _text(item.get("parameter"), 200) or None,
                "payload": _text(item.get("payload"), 1000) or None,
                "cwe": _list(item.get("cwe")),
                "references": _list(item.get("references")),
            }
        )
    return findings


def _run_plugin(path: str, payload: dict, memory_mb: int, timeout_seconds: int) -> list[dict]:
    _limit_resources(memory_mb, timeout_seconds)
    spec = importlib.util.spec_from_file_location("venomscan_external_plugin", Path(path))
    if spec is None or spec.loader is None:
        raise ValueError("plugin could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    run = getattr(module, "run", None)
    if not callable(run):
        raise ValueError("plugin has no callable run(payload)")
    with contextlib.redirect_stdout(sys.stderr):
        result = run(payload)
    if inspect.isawaitable(result):
        with contextlib.redirect_stdout(sys.stderr):
            result = asyncio.run(result)
    return _clean_findings(result)


def main() -> int:
    stdout = sys.stdout
    try:
        request = json.loads(sys.stdin.read())
        findings = _run_plugin(
            str(request["path"]),
            request.get("payload") or {},
            int(request.get("memory_mb", 256)),
            int(request.get("timeout_seconds", 10)),
        )
        response = {"findings": findings}
    except BaseException as exc:  # a broken plugin must report, not crash the scan
        response = {"error": f"{type(exc).__name__}: {str(exc)[:500]}"}
    stdout.write(json.dumps(response))
    stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
