from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from venomscan_api.config import get_settings
from venomscan_api.crypto import decrypt, encrypt
from venomscan_api.db import get_db
from venomscan_api.deps import client_ip, get_current_user, require_csrf
from venomscan_api.models import AiSetting, TestCredential, User
from venomscan_api.schemas import (
    AiProviderTestOut,
    AiSettingsIn,
    AiSettingsOut,
    CredentialIn,
    CredentialOut,
    ScanDefaults,
    SettingsIn,
    SettingsOut,
)
from venomscan_api.services import ai_service, audit, workspace

router = APIRouter(prefix="/api/settings", tags=["settings"])


def _out(row) -> SettingsOut:
    defaults = row.scan_defaults or {}
    return SettingsOut(
        scan_defaults=ScanDefaults(profile=defaults.get("profile", workspace.DEFAULT_PROFILE)),
        disabled_checks=list(row.disabled_checks or []),
        updated_at=row.updated_at,
    )


def _credential_out(row: TestCredential, secret: str) -> CredentialOut:
    try:
        names = sorted(json.loads(decrypt(secret, row.headers_encrypted) or "{}"))
    except json.JSONDecodeError:
        names = []
    return CredentialOut(
        id=row.id,
        label=row.label,
        role=row.role,
        identity=row.identity,
        header_names=names,
        created_at=row.created_at,
    )


def _ai_row(db: Session) -> AiSetting:
    row = db.get(AiSetting, "default")
    if row is None:
        row = AiSetting(id="default")
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def _ai_out(row: AiSetting) -> AiSettingsOut:
    return AiSettingsOut(
        provider=row.provider,
        model=row.model,
        base_url=row.base_url,
        key_configured=bool(row.api_key_encrypted),
        updated_at=row.updated_at,
    )


@router.get("", response_model=SettingsOut)
def read_settings(
    db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> SettingsOut:
    return _out(workspace.get_row(db))


@router.put("", response_model=SettingsOut, dependencies=[Depends(require_csrf)])
def update_settings(
    payload: SettingsIn,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> SettingsOut:
    from venomscan_engine.checks import all_check_ids

    known = set(all_check_ids())
    unknown = sorted(set(payload.disabled_checks) - known)
    if unknown:
        raise HTTPException(
            status_code=422, detail=f"Unknown check ids: {', '.join(unknown)}"
        )
    row = workspace.get_row(db)
    row.scan_defaults = {"profile": payload.scan_defaults.profile}
    row.disabled_checks = sorted(set(payload.disabled_checks))
    audit.record(
        db,
        "settings.updated",
        actor=user,
        target_type="settings",
        target_id=workspace.ROW_ID,
        detail={
            "profile": payload.scan_defaults.profile,
            "disabled_checks": row.disabled_checks,
        },
        ip=client_ip(request),
    )
    db.commit()
    db.refresh(row)
    return _out(row)


@router.get("/credentials", response_model=list[CredentialOut])
def list_credentials(
    db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> list[CredentialOut]:
    secret = get_settings().secret_key
    rows = db.scalars(select(TestCredential).order_by(TestCredential.created_at)).all()
    return [_credential_out(row, secret) for row in rows]


@router.post(
    "/credentials",
    response_model=CredentialOut,
    status_code=201,
    dependencies=[Depends(require_csrf)],
)
def create_credential(
    payload: CredentialIn,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> CredentialOut:
    if db.scalar(select(TestCredential).where(TestCredential.label == payload.label)):
        raise HTTPException(status_code=409, detail="A test account with that label already exists")
    if len(db.scalars(select(TestCredential)).all()) >= 3:
        raise HTTPException(
            status_code=422, detail="At most three test accounts can be configured"
        )
    secret = get_settings().secret_key
    row = TestCredential(
        label=payload.label,
        role=payload.role,
        identity=payload.identity,
        headers_encrypted=encrypt(secret, json.dumps(payload.headers)),
    )
    db.add(row)
    audit.record(
        db,
        "credential.created",
        actor=user,
        target_type="credential",
        target_id=row.id,
        detail={"label": payload.label, "role": payload.role, "headers": sorted(payload.headers)},
        ip=client_ip(request),
    )
    db.commit()
    db.refresh(row)
    return _credential_out(row, secret)


@router.delete(
    "/credentials/{credential_id}",
    status_code=204,
    dependencies=[Depends(require_csrf)],
)
def delete_credential(
    credential_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    row = db.get(TestCredential, credential_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Test account not found")
    audit.record(
        db,
        "credential.deleted",
        actor=user,
        target_type="credential",
        target_id=row.id,
        detail={"label": row.label},
        ip=client_ip(request),
    )
    db.delete(row)
    db.commit()
    return Response(status_code=204)


@router.get("/ai", response_model=AiSettingsOut)
def read_ai_settings(
    db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> AiSettingsOut:
    return _ai_out(_ai_row(db))


@router.put("/ai", response_model=AiSettingsOut, dependencies=[Depends(require_csrf)])
def update_ai_settings(
    payload: AiSettingsIn,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> AiSettingsOut:
    secret = get_settings().secret_key
    row = _ai_row(db)
    row.provider = payload.provider
    row.model = payload.model
    row.base_url = payload.base_url.strip()
    if payload.api_key is not None:
        row.api_key_encrypted = encrypt(secret, payload.api_key) if payload.api_key else ""
    audit.record(
        db,
        "ai.settings_updated",
        actor=user,
        target_type="settings",
        target_id="ai",
        detail={
            "provider": row.provider,
            "model": row.model,
            "key_configured": bool(row.api_key_encrypted),
        },
        ip=client_ip(request),
    )
    db.commit()
    db.refresh(row)
    return _ai_out(row)


@router.post(
    "/ai/test", response_model=AiProviderTestOut, dependencies=[Depends(require_csrf)]
)
async def test_ai_provider(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> AiProviderTestOut:
    result = await ai_service.test_provider(db)
    audit.record(
        db,
        "ai.provider_test",
        actor=user,
        target_type="settings",
        target_id="ai",
        detail={
            "provider": result["provider"],
            "model": result["model"],
            "reachable": result["reachable"],
        },
        ip=client_ip(request),
    )
    db.commit()
    return AiProviderTestOut(**result)
