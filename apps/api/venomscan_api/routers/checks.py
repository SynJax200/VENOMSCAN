from __future__ import annotations

from fastapi import APIRouter, Depends

from venomscan_api.config import Settings, get_settings
from venomscan_api.deps import get_current_user
from venomscan_api.models import User
from venomscan_api.schemas import CheckOut, PluginCatalogOut, PluginOut

router = APIRouter(prefix="/api/checks", tags=["checks"])


@router.get("", response_model=list[CheckOut])
def list_checks(user: User = Depends(get_current_user)) -> list[CheckOut]:
    from venomscan_engine.checks import check_catalog

    return [CheckOut(**entry) for entry in check_catalog()]


@router.get("/plugins", response_model=PluginCatalogOut)
def list_plugins(
    settings: Settings = Depends(get_settings),
    user: User = Depends(get_current_user),
) -> PluginCatalogOut:
    from venomscan_engine.plugins import discover_plugins
    from venomscan_engine.plugins.runner import plugin_dirs_from_env

    specs, problems = discover_plugins(plugin_dirs_from_env(settings.plugin_dirs))
    return PluginCatalogOut(
        plugins=[PluginOut(**spec.as_dict()) for spec in specs],
        problems=problems,
    )
