from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import jwt
import pytest
from app.config import Settings
from app.core.rbac import can_manage_user
from app.core.security import get_current_user
from app.models.session import UserSession
from app.models.user import User, UserRole
from app.services.auth_service import revoke_session_rows, revoke_user_sessions
from app.services.oauth.account_service import find_or_link_oauth_user
from app.services.oauth.base import OAuthUserProfile
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import ValidationError
from redis.exceptions import ConnectionError as RedisConnectionError

SECRET = "unit-test-secret-key-with-enough-unique-characters-123"


class _First:
    def __init__(self, value):
        self.value = value

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self.value


class _FakeDB:
    def __init__(self, session, user):
        self.session = session
        self.user = user

    def query(self, model):
        if model is UserSession:
            return _First(self.session)
        return _First(self.user)


class _OAuthDB:
    def __init__(self, user):
        self.user = user

    def query(self, model):
        return _First(self.user if model is User else None)


def _user(role: UserRole = UserRole.user) -> User:
    return User(
        id=uuid.uuid4(),
        email=f"{uuid.uuid4().hex}@example.com",
        username="unit",
        role=role,
        is_active=True,
    )


def _session(user: User) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        user_id=user.id,
        revoked_at=None,
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def _token(user: User, session: SimpleNamespace, *, secret: str = SECRET) -> str:
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "sub": str(user.id),
            "sid": str(session.id),
            "type": "access",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
        },
        secret,
        algorithm="HS256",
    )


def _settings(secret: str = SECRET) -> SimpleNamespace:
    return SimpleNamespace(jwt_secret_key=secret, jwt_algorithm="HS256")


def _credentials(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def test_placeholder_and_low_entropy_jwt_secrets_are_rejected(monkeypatch):
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    for secret in ("replace_with_random_secret_at_least_32_characters", "a" * 32):
        with pytest.raises(ValidationError, match="JWT_SECRET_KEY"):
            Settings(_env_file=None, JWT_SECRET_KEY=secret)


def test_session_subject_must_match_access_token_subject():
    user = _user()
    session = _session(user)
    token = _token(user, session)
    db = _FakeDB(session, user)
    redis = SimpleNamespace(exists=lambda key: True)

    assert get_current_user(_credentials(token), db, _settings(), redis) is user

    other = _user()
    session.user_id = other.id
    with pytest.raises(HTTPException) as caught:
        get_current_user(_credentials(token), db, _settings(), redis)
    assert caught.value.status_code == 401


def test_revoked_or_expired_session_is_rejected():
    user = _user()
    session = _session(user)
    token = _token(user, session)
    db = _FakeDB(session, user)
    redis = SimpleNamespace(exists=lambda key: True)

    session.revoked_at = datetime.now(UTC)
    with pytest.raises(HTTPException):
        get_current_user(_credentials(token), db, _settings(), redis)

    session.revoked_at = None
    session.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    with pytest.raises(HTTPException):
        get_current_user(_credentials(token), db, _settings(), redis)


def test_missing_session_or_redis_key_is_rejected():
    user = _user()
    session = _session(user)
    token = _token(user, session)

    with pytest.raises(HTTPException):
        get_current_user(
            _credentials(token),
            _FakeDB(None, user),
            _settings(),
            SimpleNamespace(exists=lambda key: True),
        )

    with pytest.raises(HTTPException):
        get_current_user(
            _credentials(token),
            _FakeDB(session, user),
            _settings(),
            SimpleNamespace(exists=lambda key: False),
        )


def test_malformed_session_id_is_rejected():
    user = _user()
    session = _session(user)
    token = jwt.encode(
        {
            "sub": str(user.id),
            "sid": "not-a-uuid",
            "type": "access",
            "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
        },
        SECRET,
        algorithm="HS256",
    )
    with pytest.raises(HTTPException):
        get_current_user(
            _credentials(token),
            _FakeDB(session, user),
            _settings(),
            SimpleNamespace(exists=lambda key: True),
        )


def test_forged_subject_with_another_valid_session_is_rejected():
    owner = _user()
    attacker = _user()
    session = _session(owner)
    token = _token(attacker, session)
    db = _FakeDB(session, attacker)
    redis = SimpleNamespace(exists=lambda key: True)
    with pytest.raises(HTTPException):
        get_current_user(_credentials(token), db, _settings(), redis)


def test_revoke_session_rows_skips_current_and_clears_redis():
    first = SimpleNamespace(id=uuid.uuid4(), revoked_at=None)
    second = SimpleNamespace(id=uuid.uuid4(), revoked_at=None)

    class Redis:
        def __init__(self):
            self.deleted = []

        def delete(self, key):
            self.deleted.append(key)

    redis = Redis()
    revoked = revoke_session_rows(
        [first, second], redis, except_session_id=str(first.id)
    )
    assert revoked == 1
    assert first.revoked_at is None
    assert second.revoked_at is not None
    assert redis.deleted == [f"session:{second.id}"]


class _AllSessions:
    def __init__(self, sessions):
        self.sessions = sessions

    def filter(self, *args, **kwargs):
        return self

    def all(self):
        return self.sessions


class _SessionDB:
    def __init__(self, sessions):
        self.sessions = sessions
        self.commits = 0

    def query(self, model):
        return _AllSessions(self.sessions)

    def commit(self):
        self.commits += 1


def test_revoke_user_sessions_keeps_db_revocation_when_redis_delete_fails():
    first = SimpleNamespace(id=uuid.uuid4(), revoked_at=None)
    second = SimpleNamespace(id=uuid.uuid4(), revoked_at=None)
    db = _SessionDB([first, second])

    class FailingRedis:
        def __init__(self):
            self.delete_requests = []

        def delete(self, key):
            self.delete_requests.append(key)
            raise RedisConnectionError("simulated cache outage")

    redis = FailingRedis()
    revoked = revoke_user_sessions(
        db, redis, user_id=uuid.uuid4(), except_session_id=str(first.id)
    )

    # A cache outage must not abort or skip the DB-authoritative revocation.
    assert revoked == 1
    assert db.commits == 1
    assert first.revoked_at is None
    assert second.revoked_at is not None
    assert redis.delete_requests == [f"session:{second.id}"]


def test_can_manage_user_rules():
    admin = _user(UserRole.admin)
    peer = _user(UserRole.admin)
    normal = _user(UserRole.user)
    superadmin = _user(UserRole.superadmin)

    assert can_manage_user(admin, admin)
    assert can_manage_user(admin, normal)
    assert not can_manage_user(admin, peer)
    assert not can_manage_user(admin, superadmin)
    assert can_manage_user(superadmin, admin)


def test_oauth_existing_email_requires_explicit_link():
    user = User(
        id=uuid.uuid4(),
        email="victim@example.com",
        hashed_password="hash",
        username="victim",
        role=UserRole.user,
        is_active=True,
    )
    db = _OAuthDB(user)
    profile = OAuthUserProfile(
        provider_user_id="provider-1",
        email="victim@example.com",
        name="Victim",
        avatar_url=None,
    )
    settings = SimpleNamespace(
        jwt_secret_key=SECRET,
        oauth_token_encryption_key="",
    )
    with pytest.raises(ValueError, match="sign in to link"):
        find_or_link_oauth_user(
            db,
            settings,
            provider="google",
            profile=profile,
            raw_access_token="token",
        )
