from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from venomscan_api import security
from venomscan_api.config import Settings
from venomscan_api.db import get_db
from venomscan_api.deps import client_ip, get_current_user, require_csrf, settings_dep
from venomscan_api.models import User
from venomscan_api.schemas import AuthOut, CsrfOut, LoginIn, RegisterIn, UserOut
from venomscan_api.services import audit

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _user_out(user: User) -> UserOut:
    return UserOut(
        id=user.id,
        email=user.email,
        name=user.name,
        role=user.role,
        created_at=user.created_at,
    )


def _auth_response(response: Response, user: User, settings: Settings) -> AuthOut:
    csrf = security.set_auth_cookies(response, user.id, settings)
    return AuthOut(user=_user_out(user), csrf_token=csrf)


@router.get("/csrf", response_model=CsrfOut)
def csrf_token(
    request: Request, response: Response, settings: Settings = Depends(settings_dep)
) -> CsrfOut:
    token = request.cookies.get(security.CSRF_COOKIE) or security.issue_csrf_token()
    security.set_csrf_cookie(response, token, settings)
    return CsrfOut(csrf_token=token)


@router.post("/register", response_model=AuthOut, status_code=status.HTTP_201_CREATED)
def register(
    payload: RegisterIn,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> AuthOut:
    require_csrf(request)
    if not settings.allow_registration:
        raise HTTPException(status_code=403, detail="Registration is closed on this installation")
    if db.scalar(select(User).where(User.email == payload.email)):
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    first_user = db.scalar(select(User.id).limit(1)) is None
    user = User(
        email=payload.email,
        name=payload.name.strip() or payload.email.split("@")[0],
        role="admin" if first_user else "user",
        password_hash=security.hash_password(payload.password),
    )
    db.add(user)
    db.flush()
    audit.record(
        db,
        "auth.register",
        actor=user,
        target_type="user",
        target_id=user.id,
        ip=client_ip(request),
    )
    db.commit()
    return _auth_response(response, user, settings)


@router.post("/login", response_model=AuthOut)
def login(
    payload: LoginIn,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> AuthOut:
    require_csrf(request)
    ip = client_ip(request)
    email = payload.email.strip().lower()
    guard = request.app.state.login_guard
    retry = guard.retry_after(email, ip)
    if retry:
        audit.record(
            db,
            "auth.login.blocked",
            target_type="user",
            detail={"email": email},
            ip=ip,
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed sign-in attempts. Retry in {retry}s.",
            headers={"Retry-After": str(retry)},
        )

    user = db.scalar(select(User).where(User.email == email))
    if user is None or not security.verify_password(payload.password, user.password_hash):
        locked_for = guard.record_failure(email, ip)
        audit.record(
            db,
            "auth.login.failed",
            actor=user,
            target_type="user",
            target_id=user.id if user else "",
            detail={"email": email, "locked": bool(locked_for)},
            ip=ip,
        )
        db.commit()
        if locked_for:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Account temporarily locked after repeated failures. Retry in {locked_for}s.",
                headers={"Retry-After": str(locked_for)},
            )
        raise HTTPException(status_code=401, detail="Invalid email or password")
    guard.record_success(email)
    audit.record(db, "auth.login", actor=user, target_type="user", target_id=user.id, ip=ip)
    db.commit()
    return _auth_response(response, user, settings)


@router.post("/refresh", response_model=AuthOut)
def refresh(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> AuthOut:
    require_csrf(request)
    token = request.cookies.get(security.REFRESH_COOKIE)
    user_id = security.decode_token(token, settings, "refresh") if token else None
    user = db.get(User, user_id) if user_id else None
    if user is None:
        raise HTTPException(status_code=401, detail="Refresh session expired; sign in again")
    return _auth_response(response, user, settings)


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> dict[str, bool]:
    require_csrf(request)
    user = None
    token = request.cookies.get(security.ACCESS_COOKIE)
    if token:
        user_id = security.decode_token(token, settings, "access")
        user = db.get(User, user_id) if user_id else None
    audit.record(db, "auth.logout", actor=user, ip=client_ip(request))
    db.commit()
    security.clear_auth_cookies(response)
    return {"ok": True}


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> UserOut:
    return _user_out(user)
