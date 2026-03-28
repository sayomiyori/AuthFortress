import uuid
from datetime import datetime, timedelta, timezone

import jwt

from app.config import Settings


def create_access_token(
    settings: Settings,
    *,
    user_id: str,
    email: str,
    role: str,
    session_id: str,
) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=settings.access_token_expire_minutes)
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "sid": session_id,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": exp,
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def create_refresh_token(
    settings: Settings,
    *,
    user_id: str,
    session_id: str,
    refresh_jti: str,
) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=settings.refresh_token_expire_days)
    payload = {
        "sub": user_id,
        "sid": session_id,
        "jti": refresh_jti,
        "type": "refresh",
        "iat": int(now.timestamp()),
        "exp": exp,
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_token(settings: Settings, token: str) -> dict:
    return jwt.decode(
        token,
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm],
    )


def new_refresh_jti() -> str:
    return str(uuid.uuid4())
