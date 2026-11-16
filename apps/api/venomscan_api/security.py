from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from datetime import timedelta
from typing import Literal

import jwt
from fastapi import Request, Response

from venomscan_api.config import Settings
from venomscan_api.db import utcnow

ACCESS_COOKIE = "vs_access"
REFRESH_COOKIE = "vs_refresh"
CSRF_COOKIE = "vs_csrf"
CSRF_HEADER = "x-csrf-token"

# scrypt from the stdlib: memory-hard, no compiled dependency (host policy blocks
# argon2-cffi's native DLL). Parameters follow OWASP's minimum for scrypt.
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_SCRYPT_MAXMEM = 64 * 1024 * 1024


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
        maxmem=_SCRYPT_MAXMEM,
    )
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, digest_b64 = password_hash.split("$")
        if scheme != "scrypt":
            return False
        expected = _unb64(digest_b64)
        candidate = hashlib.scrypt(
            password.encode("utf-8"),
            salt=_unb64(salt_b64),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
            maxmem=_SCRYPT_MAXMEM,
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(candidate, expected)


def _token(
    subject: str, kind: Literal["access", "refresh"], settings: Settings, lifetime: timedelta
) -> str:
    now = utcnow()
    payload = {"sub": subject, "typ": kind, "iat": now, "exp": now + lifetime}
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")


def create_access_token(user_id: str, settings: Settings) -> str:
    return _token(user_id, "access", settings, timedelta(minutes=settings.access_token_minutes))


def create_refresh_token(user_id: str, settings: Settings) -> str:
    return _token(user_id, "refresh", settings, timedelta(days=settings.refresh_token_days))


def decode_token(
    token: str, settings: Settings, expected_type: Literal["access", "refresh"]
) -> str | None:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    if payload.get("typ") != expected_type:
        return None
    subject = payload.get("sub")
    return str(subject) if subject else None


def issue_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def set_csrf_cookie(response: Response, token: str, settings: Settings) -> None:
    response.set_cookie(
        CSRF_COOKIE,
        token,
        httponly=False,
        samesite="lax",
        secure=settings.cookie_secure,
        path="/",
        max_age=settings.access_token_minutes * 60,
    )


def set_auth_cookies(response: Response, user_id: str, settings: Settings) -> str:
    response.set_cookie(
        ACCESS_COOKIE,
        create_access_token(user_id, settings),
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        path="/",
        max_age=settings.access_token_minutes * 60,
    )
    response.set_cookie(
        REFRESH_COOKIE,
        create_refresh_token(user_id, settings),
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        path="/",
        max_age=settings.refresh_token_days * 86400,
    )
    csrf = issue_csrf_token()
    set_csrf_cookie(response, csrf, settings)
    return csrf


def clear_auth_cookies(response: Response) -> None:
    for name in (ACCESS_COOKIE, REFRESH_COOKIE, CSRF_COOKIE):
        response.delete_cookie(name, path="/")


def csrf_cookie_matches(request: Request) -> bool:
    header = request.headers.get(CSRF_HEADER)
    cookie = request.cookies.get(CSRF_COOKIE)
    if not header or not cookie:
        return False
    return secrets.compare_digest(header, cookie)
