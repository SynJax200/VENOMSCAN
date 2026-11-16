from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from venomscan_api import security
from venomscan_api.config import Settings, get_settings
from venomscan_api.db import get_db
from venomscan_api.models import User


def settings_dep(request: Request) -> Settings:
    app_settings = getattr(request.app.state, "settings", None)
    return app_settings if isinstance(app_settings, Settings) else get_settings()


def require_csrf(request: Request) -> None:
    if not security.csrf_cookie_matches(request):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token missing or invalid. Fetch /api/auth/csrf and resend with the X-CSRF-Token header.",
        )


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_dep),
) -> User:
    token = request.cookies.get(security.ACCESS_COOKIE)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    user_id = security.decode_token(token, settings, "access")
    user = db.get(User, user_id) if user_id else None
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired")
    return user


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""
