from __future__ import annotations

import importlib
import inspect
import pkgutil
import re
from collections.abc import Iterable

from venomscan_engine.models import PROFILE_ORDER, Severity

_ID_PATTERN = re.compile(r"^venom(\.[a-z0-9_]+){1,}$")
_SKIP_MODULES = {"base", "registry", "learning"}

_REGISTRY: dict[str, type] = {}
_discovered = False


def validate_check(cls: type) -> None:
    """Enforce the check contract before a class joins the registry."""
    missing = [
        attribute
        for attribute in ("id", "name", "category", "default_severity", "profile")
        if not getattr(cls, attribute, None)
    ]
    if missing:
        raise TypeError(f"{cls.__name__} is missing check attributes: {', '.join(missing)}")
    if not _ID_PATTERN.match(cls.id):
        raise ValueError(
            f"{cls.__name__}.id={cls.id!r} must look like 'venom.category.name' "
            "(lowercase segments separated by dots)"
        )
    if cls.profile not in PROFILE_ORDER:
        raise ValueError(
            f"{cls.__name__}.profile={cls.profile!r} must be one of {sorted(PROFILE_ORDER)}"
        )
    if not isinstance(cls.default_severity, Severity):
        raise TypeError(f"{cls.__name__}.default_severity must be a Severity value")
    run = getattr(cls, "run", None)
    if run is None or not inspect.iscoroutinefunction(run):
        raise TypeError(f"{cls.__name__}.run must be an async method")


def register(cls: type) -> type:
    validate_check(cls)
    if cls.id in _REGISTRY:
        raise ValueError(
            f"duplicate check id {cls.id!r}: registered by "
            f"{_REGISTRY[cls.id].__name__} and {cls.__name__}"
        )
    _REGISTRY[cls.id] = cls
    return cls


def discover_checks() -> list[str]:
    """Import every module in this package so decorators register their checks."""
    global _discovered
    if _discovered:
        return sorted(_REGISTRY)
    package = importlib.import_module("venomscan_engine.checks")
    for module in pkgutil.iter_modules(package.__path__):
        if module.name in _SKIP_MODULES or module.name.startswith("_"):
            continue
        importlib.import_module(f"{package.__name__}.{module.name}")
    _discovered = True
    return all_check_ids()


def checks_for_profile(profile: str, disabled: Iterable[str] | None = None) -> list[type]:
    discover_checks()
    limit = PROFILE_ORDER.get(profile, 0)
    off = set(disabled or ())
    selected = [
        cls
        for cls in _REGISTRY.values()
        if PROFILE_ORDER.get(cls.profile, 0) <= limit and cls.id not in off
    ]
    return sorted(selected, key=lambda cls: cls.id)


def all_check_ids() -> list[str]:
    discover_checks()
    return sorted(_REGISTRY)


def check_catalog() -> list[dict]:
    """Machine-readable catalogue consumed by the settings page and learning mode."""
    from venomscan_engine.checks.learning import learning_for

    discover_checks()
    return [
        {
            "id": cls.id,
            "name": cls.name,
            "category": cls.category,
            "profile": cls.profile,
            "severity": cls.default_severity.value,
            "learning": learning_for(cls.id),
        }
        for cls in sorted(_REGISTRY.values(), key=lambda item: item.id)
    ]
