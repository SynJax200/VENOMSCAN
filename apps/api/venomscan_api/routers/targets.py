from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from venomscan_api.config import Settings
from venomscan_api.db import get_db, utcnow
from venomscan_api.deps import client_ip, get_current_user, require_csrf, settings_dep
from venomscan_api.models import Authorization, Scan, Target, User
from venomscan_api.schemas import AttestIn, TargetCreate, TargetOut
from venomscan_api.services import audit, verification
from venomscan_api.services.serializers import target_out

router = APIRouter(prefix="/api/targets", tags=["targets"])


def _owned_target(db: Session, target_id: str, user: User) -> Target:
    target = db.get(Target, target_id)
    if target is None or target.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


def _active_authorization(target: Target, db: Session) -> Authorization:
    auth = target.latest_authorization
    if auth is not None:
        return auth
    auth = Authorization(
        target_id=target.id,
        method="pending",
        token=verification.new_verification_token(),
    )
    db.add(auth)
    db.flush()
    target.authorizations.insert(0, auth)
    return auth


@router.get("", response_model=list[TargetOut])
def list_targets(
    db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> list[TargetOut]:
    targets = db.scalars(
        select(Target)
        .options(selectinload(Target.authorizations))
        .where(Target.owner_id == user.id)
        .order_by(Target.created_at.desc())
    ).all()
    counts: dict[str, int] = {}
    if targets:
        counts = {
            target_id: int(count)
            for target_id, count in db.execute(
                select(Scan.target_id, func.count(Scan.id))
                .where(Scan.target_id.in_([target.id for target in targets]))
                .group_by(Scan.target_id)
            ).all()
        }
    return [target_out(target, counts.get(target.id, 0)) for target in targets]


@router.post("", response_model=TargetOut, status_code=201, dependencies=[Depends(require_csrf)])
def create_target(
    payload: TargetCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> TargetOut:
    try:
        host = verification.host_from_url(payload.url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    target = Target(
        owner_id=user.id,
        name=payload.name.strip(),
        url=payload.url.strip(),
        host=host,
        scope_notes=payload.scope_notes.strip(),
    )
    db.add(target)
    db.flush()
    db.add(
        Authorization(
            target_id=target.id,
            method="pending",
            token=verification.new_verification_token(),
        )
    )
    audit.record(
        db,
        "target.created",
        actor=user,
        target_type="target",
        target_id=target.id,
        detail={"url": target.url, "host": target.host},
        ip=client_ip(request),
    )
    db.commit()
    db.refresh(target)
    return target_out(target)


@router.get("/{target_id}", response_model=TargetOut)
def get_target(
    target_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> TargetOut:
    return target_out(_owned_target(db, target_id, user))


@router.delete("/{target_id}", status_code=204, dependencies=[Depends(require_csrf)])
def delete_target(
    target_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> None:
    target = _owned_target(db, target_id, user)
    audit.record(
        db,
        "target.deleted",
        actor=user,
        target_type="target",
        target_id=target.id,
        detail={"url": target.url},
        ip=client_ip(request),
    )
    db.delete(target)
    db.commit()


@router.post(
    "/{target_id}/verify/dns", response_model=TargetOut, dependencies=[Depends(require_csrf)]
)
async def verify_dns(
    target_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> TargetOut:
    target = _owned_target(db, target_id, user)
    auth = _active_authorization(target, db)
    ok, message = await verification.check_dns(target.host, auth.token)
    if not ok:
        db.commit()
        raise HTTPException(status_code=400, detail=message)
    auth.method = "dns_txt"
    auth.verified_at = utcnow()
    auth.expires_at = verification.verified_until()
    audit.record(
        db,
        "target.verified",
        actor=user,
        target_type="target",
        target_id=target.id,
        detail={"method": "dns_txt", "message": message},
        ip=client_ip(request),
    )
    db.commit()
    db.refresh(target)
    return target_out(target)


@router.post(
    "/{target_id}/verify/well-known",
    response_model=TargetOut,
    dependencies=[Depends(require_csrf)],
)
async def verify_well_known(
    target_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    settings: Settings = Depends(settings_dep),
) -> TargetOut:
    target = _owned_target(db, target_id, user)
    auth = _active_authorization(target, db)
    ok, message = await verification.check_well_known(
        target.url, auth.token, allow_private=settings.allow_private_targets
    )
    if not ok:
        db.commit()
        raise HTTPException(status_code=400, detail=message)
    auth.method = "well_known"
    auth.verified_at = utcnow()
    auth.expires_at = verification.verified_until()
    audit.record(
        db,
        "target.verified",
        actor=user,
        target_type="target",
        target_id=target.id,
        detail={"method": "well_known", "message": message},
        ip=client_ip(request),
    )
    db.commit()
    db.refresh(target)
    return target_out(target)


@router.post(
    "/{target_id}/verify/attest", response_model=TargetOut, dependencies=[Depends(require_csrf)]
)
def verify_attest(
    target_id: str,
    payload: AttestIn,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> TargetOut:
    if not payload.accepted:
        raise HTTPException(status_code=422, detail="You must accept the authorization statement")
    target = _owned_target(db, target_id, user)
    auth = _active_authorization(target, db)
    auth.method = "manual_attestation"
    auth.attestation = payload.attestation.strip()
    auth.verified_at = utcnow()
    auth.expires_at = verification.verified_until()
    audit.record(
        db,
        "target.verified",
        actor=user,
        target_type="target",
        target_id=target.id,
        detail={"method": "manual_attestation", "expires_in_days": verification.AUTHORIZATION_DAYS},
        ip=client_ip(request),
    )
    db.commit()
    db.refresh(target)
    return target_out(target)
