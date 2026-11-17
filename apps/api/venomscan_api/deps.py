from __future__ import annotations

import ipaddress

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


def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator access is required for this operation",
        )
    return user


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


def _is_internal_peer(value: str) -> bool:
    """Peers inside the deployment (Caddy/Render proxy) are the only trusted forwarders."""
    address = _parse_ip(value)
    return bool(
        address
        and (address.is_loopback or address.is_private or address.is_link_local)
    )


def client_ip(request: Request) -> str:
    peer = request.client.host if request.client else ""
    if not peer:
        return ""
    settings = getattr(request.app.state, "settings", None) or get_settings()
    trusted = peer in settings.trusted_proxy_list or _is_internal_peer(peer)
    forwarded = request.headers.get("x-forwarded-for")
    if trusted and forwarded:
        # The nearest hop appends the address it observed, so the last entry is the
        # client. Earlier entries can be supplied by the caller and are ignored.
        for candidate in reversed(forwarded.split(",")):
            address = _parse_ip(candidate)
            if address is not None:
                return str(address)
    return peer
