import hashlib
from datetime import UTC, datetime, timedelta
from uuid import UUID

import jwt
from sqlalchemy.orm import Session

from app.config import Settings
from app.models.session import UserSession
from app.models.user import User, UserRole
from app.services import jwt_service
from app.services.password import hash_password, validate_password_strength, verify_password


def _hash_refresh_jti(jti: str) -> str:
    return hashlib.sha256(jti.encode()).hexdigest()


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def register_user(
    db: Session,
    *,
    email: str,
    password: str,
    username: str,
) -> User:
    ok, err = validate_password_strength(password)
    if not ok:
        raise ValueError(err or "Invalid password")

    if db.query(User).filter(User.email == email.lower()).first():
        raise ValueError("Email already registered")

    user = User(
        email=email.lower(),
        hashed_password=hash_password(password),
        username=username,
        role=UserRole.user,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def authenticate_user(db: Session, *, email: str, password: str) -> User | None:
    user = db.query(User).filter(User.email == email.lower()).first()
    if not user or not user.is_active:
        return None
    if user.hashed_password is None:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


def create_session_and_tokens(
    db: Session,
    settings: Settings,
    redis_client,
    *,
    user: User,
    device_info: str | None,
    ip: str | None,
) -> tuple[str, str, UserSession]:
    now = datetime.now(UTC)
    expires_at = now + timedelta(days=settings.refresh_token_expire_days)
    jti = jwt_service.new_refresh_jti()
    token_hash = _hash_refresh_jti(jti)

    session = UserSession(
        user_id=user.id,
        refresh_token_hash=token_hash,
        device_info=device_info,
        ip=ip,
        expires_at=expires_at,
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    sid_str = str(session.id)
    ttl_seconds = settings.refresh_token_expire_days * 24 * 60 * 60
    redis_client.setex(f"session:{sid_str}", ttl_seconds, "1")

    access = jwt_service.create_access_token(
        settings,
        user_id=str(user.id),
        email=user.email,
        role=user.role.value,
        session_id=sid_str,
    )
    refresh = jwt_service.create_refresh_token(
        settings,
        user_id=str(user.id),
        session_id=sid_str,
        refresh_jti=jti,
    )
    return access, refresh, session


def refresh_tokens(
    db: Session,
    settings: Settings,
    redis_client,
    *,
    refresh_token: str,
) -> tuple[str, str]:
    try:
        payload = jwt_service.decode_token(settings, refresh_token)
    except jwt.PyJWTError as e:
        raise ValueError("Invalid refresh token") from e

    if payload.get("type") != "refresh":
        raise ValueError("Invalid token type")

    sid = payload.get("sid")
    jti = payload.get("jti")
    if not sid or not jti:
        raise ValueError("Invalid refresh token payload")

    session = db.query(UserSession).filter(UserSession.id == UUID(sid)).first()
    if not session:
        raise ValueError("Session not found")
    if session.revoked_at is not None:
        raise ValueError("Session revoked")
    if _as_utc(session.expires_at) < datetime.now(UTC):
        raise ValueError("Session expired")

    expected = _hash_refresh_jti(str(jti))
    if session.refresh_token_hash != expected:
        raise ValueError("Refresh token mismatch")

    if not redis_client.exists(f"session:{sid}"):
        raise ValueError("Session not active")

    new_jti = jwt_service.new_refresh_jti()
    session.refresh_token_hash = _hash_refresh_jti(new_jti)
    db.commit()

    user = db.query(User).filter(User.id == session.user_id).first()
    if not user or not user.is_active:
        raise ValueError("User inactive")

    access = jwt_service.create_access_token(
        settings,
        user_id=str(user.id),
        email=user.email,
        role=user.role.value,
        session_id=sid,
    )
    new_refresh = jwt_service.create_refresh_token(
        settings,
        user_id=str(user.id),
        session_id=sid,
        refresh_jti=new_jti,
    )
    return access, new_refresh


def logout_session(
    db: Session,
    redis_client,
    *,
    session_id: str,
) -> bool:
    session = db.query(UserSession).filter(UserSession.id == UUID(session_id)).first()
    if not session:
        return False
    if session.revoked_at is None:
        session.revoked_at = datetime.now(UTC)
        db.commit()
    redis_client.delete(f"session:{session_id}")
    return True
