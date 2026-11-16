"""External plugin discovery.

Plugin metadata is read with the ``ast`` module: discovery never imports or runs
third-party code in the API/worker process. Execution happens in
``venomscan_engine.plugins.worker`` with a scrubbed environment and hard limits.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from venomscan_engine.models import PROFILE_ORDER, Severity

_ID_PATTERN = re.compile(r"^venom\.plugin\.[a-z0-9_]{2,60}$")
_REQUIRED = ("CHECK_ID", "NAME", "CATEGORY", "SEVERITY", "PROFILE")
_MAX_FILE_BYTES = 200_000


class PluginSpecError(ValueError):
    pass


@dataclass(frozen=True)
class PluginSpec:
    path: str
    check_id: str
    name: str
    category: str
    severity: str
    profile: str
    timeout_seconds: int = 10
    memory_mb: int = 256

    def as_dict(self) -> dict[str, object]:
        return {
            "check_id": self.check_id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "profile": self.profile,
            "timeout_seconds": self.timeout_seconds,
            "memory_mb": self.memory_mb,
            "file": Path(self.path).name,
        }


def _literal_assignments(tree: ast.Module) -> dict[str, object]:
    values: dict[str, object] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name):
                try:
                    values[target.id] = ast.literal_eval(node.value)
                except (ValueError, SyntaxError):
                    continue
    return values


def load_spec(path: Path) -> PluginSpec:
    if path.stat().st_size > _MAX_FILE_BYTES:
        raise PluginSpecError(f"{path.name}: plugin file exceeds 200 KB")
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise PluginSpecError(f"{path.name}: could not parse: {exc}") from exc
    if not any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "run"
        for node in tree.body
    ):
        raise PluginSpecError(f"{path.name}: must define a run(payload) function")
    values = _literal_assignments(tree)
    missing = [name for name in _REQUIRED if not isinstance(values.get(name), str)]
    if missing:
        raise PluginSpecError(f"{path.name}: missing string constants: {', '.join(missing)}")
    check_id = str(values["CHECK_ID"])
    if not _ID_PATTERN.match(check_id):
        raise PluginSpecError(
            f"{path.name}: CHECK_ID must look like 'venom.plugin.<name>' (lowercase)"
        )
    severity = str(values["SEVERITY"]).lower()
    if severity not in {item.value for item in Severity}:
        raise PluginSpecError(f"{path.name}: unsupported SEVERITY {severity!r}")
    profile = str(values["PROFILE"]).lower()
    if profile not in PROFILE_ORDER:
        raise PluginSpecError(f"{path.name}: PROFILE must be one of {sorted(PROFILE_ORDER)}")
    timeout = values.get("TIMEOUT_SECONDS", 10)
    memory = values.get("MEMORY_MB", 256)
    if not isinstance(timeout, int) or not 1 <= timeout <= 30:
        raise PluginSpecError(f"{path.name}: TIMEOUT_SECONDS must be an int in 1..30")
    if not isinstance(memory, int) or not 64 <= memory <= 512:
        raise PluginSpecError(f"{path.name}: MEMORY_MB must be an int in 64..512")
    return PluginSpec(
        path=str(path.resolve()),
        check_id=check_id,
        name=str(values["NAME"])[:160],
        category=str(values["CATEGORY"])[:60],
        severity=severity,
        profile=profile,
        timeout_seconds=timeout,
        memory_mb=memory,
    )


def discover_plugins(dirs: Iterable[str]) -> tuple[list[PluginSpec], list[str]]:
    """Return valid plugin specs plus human-readable problems, never raising."""
    specs: list[PluginSpec] = []
    problems: list[str] = []
    seen: set[str] = set()
    for raw in dirs:
        directory = Path(raw.strip())
        if not raw.strip():
            continue
        if not directory.is_dir():
            problems.append(f"{raw}: plugin directory not found")
            continue
        for path in sorted(directory.glob("*.py")):
            if path.name.startswith("_"):
                continue
            try:
                spec = load_spec(path)
            except OSError as exc:
                problems.append(f"{path.name}: {exc}")
                continue
            except PluginSpecError as exc:
                problems.append(str(exc))
                continue
            if spec.check_id in seen:
                problems.append(f"{path.name}: duplicate CHECK_ID {spec.check_id}")
                continue
            seen.add(spec.check_id)
            specs.append(spec)
    return specs, problems
