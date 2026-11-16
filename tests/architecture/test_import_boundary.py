from __future__ import annotations

import pathlib
import re

ENGINE_ROOT = pathlib.Path(__file__).resolve().parents[2] / "engine" / "venomscan_engine"
FORBIDDEN = re.compile(r"^\s*(?:from|import)\s+(venomscan_api|venomscan_workers)\b", re.MULTILINE)


def test_engine_never_imports_application_packages():
    offenders = [
        str(path.relative_to(ENGINE_ROOT))
        for path in ENGINE_ROOT.rglob("*.py")
        if FORBIDDEN.search(path.read_text(encoding="utf-8"))
    ]
    assert offenders == [], f"engine must stay standalone; found imports in {offenders}"
