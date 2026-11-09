import hashlib
import math
from datetime import UTC, datetime, timedelta
from uuid import UUID

import jwt
from redis.exceptions import RedisError
from sqlalchemy.exc import IntegrityError
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
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        if db.query(User).filter(User.email == email.lower()).first():
            raise ValueError("Email already registered") from None
        raise
    db.refresh(user)
    return user


def authenticate_user(db: Session, *, email: str, password: str) -> User | None:
    user = (
        db.query(User)
        .filter(User.email == email.lower())
        .with_for_update()
        .first()
    )
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

    session = db.query(UserSession).filter(UserSession.id == UUID(sid)).with_for_update().first()
    if not session:
        raise ValueError("Session not found")
    if session.revoked_at is not None:
        raise ValueError("Session revoked")
    if _as_utc(session.expires_at) < datetime.now(UTC):
        raise ValueError("Session expired")

    if payload.get("sub") != str(session.user_id):
        raise ValueError("Refresh token subject mismatch")

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


def session_is_active(
    db: Session,
    redis_client,
    *,
    user_id: UUID,
    session_id: str,
) -> bool:
    """Re-check the caller's own session after waiting on the user-row lock."""
    try:
        sid = UUID(str(session_id))
    except ValueError:
        return False
    session = (
        db.query(UserSession)
        .filter(UserSession.id == sid, UserSession.user_id == user_id)
        # The identity map may still hold the pre-lock row; re-read it.
        .populate_existing()
        .first()
    )
    if session is None or session.revoked_at is not None:
        return False
    if _as_utc(session.expires_at) < datetime.now(UTC):
        return False
    return bool(redis_client.exists(f"session:{sid}"))


def revoke_session_rows(
    sessions,
    redis_client,
    *,
    except_session_id: str | None = None,
) -> int:
    now = datetime.now(UTC)
    revoked = 0
    for session in sessions:
        if except_session_id and str(session.id) == str(except_session_id):
            continue
        if session.revoked_at is None:
            session.revoked_at = now
            revoked += 1
        try:
            redis_client.delete(f"session:{session.id}")
        except RedisError:
            pass
    return revoked


def revoke_user_sessions(
    db: Session,
    redis_client,
    *,
    user_id: UUID,
    except_session_id: str | None = None,
) -> int:
    sessions = db.query(UserSession).filter(UserSession.user_id == user_id).all()
    revoked = revoke_session_rows(
        sessions, redis_client, except_session_id=except_session_id
    )
    db.commit()
    return revoked


def logout_session(
    db: Session,
    redis_client,
    *,
    session_id: str,
) -> bool:
    """Revoke one session while holding its own row lock.

    Refresh rotation takes the same lock, so a rotation that is already in
    flight either commits first (and its freshly issued token is then dead) or
    waits here and observes ``revoked_at`` after this revocation commits.
    """
    try:
        sid = UUID(str(session_id))
    except ValueError:
        return False
    session = (
        db.query(UserSession)
        .filter(UserSession.id == sid)
        # Re-read a cached instance and serialize with refresh rotation.
        .populate_existing()
        .with_for_update()
        .first()
    )
    if not session:
        return False
    if session.revoked_at is None:
        session.revoked_at = datetime.now(UTC)
    db.commit()
    try:
        redis_client.delete(f"session:{sid}")
    except RedisError:
        # The database row is authoritative; cache eviction is best-effort.
        pass
    return True


def logout_session_with_refresh_token(
    db: Session,
    settings: Settings,
    redis_client,
    *,
    refresh_token: str,
) -> tuple[UUID, str]:
    """Revoke the session named by a signed refresh token.

    An older, already-rotated refresh token can still end its own session, so a
    client whose access token expired can log out with a stale refresh cookie.
    The token is never used to authenticate, and its ``sid`` can only select the
    session it is bound to, so it can never revoke a different session. The
    stored hash of the current jti is deliberately not required here.
    """
    try:
        payload = jwt_service.decode_token(settings, refresh_token)
    except (jwt.PyJWTError, TypeError, ValueError, OverflowError) as e:
        raise ValueError("Invalid refresh token") from e

    # ``decode_token`` validates ``exp`` only when the claim is present. Logout
    # requires an explicit finite expiry, so reject a missing or malformed
    # value locally instead of treating it as an unbounded credential. PyJWT
    # still enforces that a present expiry is in the future.
    exp = payload.get("exp")
    if isinstance(exp, bool) or not isinstance(exp, int | float):
        raise ValueError("Invalid refresh token expiry")
    try:
        finite_exp = math.isfinite(exp)
    except OverflowError:
        # ``math.isfinite`` converts to float, so an arbitrarily large integer
        # ``exp`` overflows that conversion. Such a claim cannot be a real
        # refresh expiry; reject it as malformed rather than raising a 500.
        raise ValueError("Invalid refresh token expiry") from None
    if not finite_exp:
        raise ValueError("Invalid refresh token expiry")

    if payload.get("type") != "refresh":
        raise ValueError("Invalid token type")

    sid = payload.get("sid")
    sub = payload.get("sub")
    jti = payload.get("jti")
    if not sid or not sub or not jti:
        raise ValueError("Invalid refresh token payload")
    try:
        session_uuid = UUID(str(sid))
        user_uuid = UUID(str(sub))
    except ValueError as e:
        raise ValueError("Invalid refresh token payload") from e

    session = (
        db.query(UserSession)
        .filter(UserSession.id == session_uuid)
        # Re-read and serialize with refresh rotation and access-token logout.
        .populate_existing()
        .with_for_update()
        .first()
    )
    if session is None:
        raise ValueError("Session not found")
    if session.user_id != user_uuid:
        # The token's subject must match the session it names; a token for one
        # account cannot be used to revoke another account's session.
        raise ValueError("Refresh token subject mismatch")

    if session.revoked_at is None:
        session.revoked_at = datetime.now(UTC)
    db.commit()
    try:
        redis_client.delete(f"session:{session_uuid}")
    except RedisError:
        pass
    return user_uuid, str(session_uuid)
