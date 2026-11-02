"""The OAuth callback re-reads account state under a row lock before issuance.

Linking commits inside ``find_or_link_oauth_user``, so the instance held by the
request can predate a deactivation performed by an independent transaction. The
shared savepoint fixture cannot expose that to another connection, so this test
wires the application to a committed session factory and deactivates the account
from a separate connection between linking and issuance.
"""

from uuid import uuid4

import pytest
from app.api.v1 import oauth as oauth_module
from app.config import Settings, get_settings
from app.core.redis_client import get_redis
from app.db.session import get_db
from app.main import app
from app.models.audit import AuditLog
from app.models.oauth_account import OAuthAccount
from app.models.session import UserSession
from app.models.user import User
from app.services.oauth.base import OAuthProvider, OAuthUserProfile
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker


class CommittedEnv:
    """Committed-data harness: every app request gets its own transaction."""

    def __init__(self, session_factory):
        self.session = session_factory
        self.emails: list[str] = []


@pytest.fixture
def committed_env(db_engine, redis_client, test_settings, monkeypatch):
    session_factory = sessionmaker(bind=db_engine)

    def override_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    monkeypatch.setattr("app.middleware.audit.SessionLocal", session_factory)
    get_settings.cache_clear()
    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_redis] = lambda: redis_client
    app.dependency_overrides[get_settings] = lambda: test_settings
    env = CommittedEnv(session_factory)
    try:
        yield env
    finally:
        app.dependency_overrides.clear()
        get_settings.cache_clear()
        # Remove only rows this test owns; this file makes no /api/v1/auth call,
        # so every audit row it writes is attributable to its own user.
        with session_factory() as db:
            owned_ids = []
            if env.emails:
                owned_ids = [
                    row[0]
                    for row in db.query(User.id).filter(User.email.in_(env.emails)).all()
                ]
            if owned_ids:
                db.query(AuditLog).filter(
                    AuditLog.user_id.in_(owned_ids)
                ).delete(synchronize_session=False)
                db.query(User).filter(
                    User.id.in_(owned_ids)
                ).delete(synchronize_session=False)
            db.commit()


class MockGoogleProvider(OAuthProvider):
    name = "google"

    def __init__(self, settings: Settings, profile: OAuthUserProfile):
        super().__init__(settings)
        self._profile = profile

    @property
    def client_id(self) -> str:
        return "mock-id"

    @property
    def client_secret(self) -> str:
        return "mock-secret"

    def create_authorization_url(self, state: str) -> str:
        return f"https://accounts.google.com/o/oauth2/v2/auth?state={state}&mock=1"

    async def exchange_code(self, authorization_response: str, client):
        return {"access_token": "mock-access-token", "token_type": "Bearer"}

    async def fetch_profile(self, token: dict, client):
        return self._profile


def _patch_google_factory(monkeypatch, profile: OAuthUserProfile) -> None:
    def _get(name: str, settings: Settings):
        if name.lower() == "google":
            return MockGoogleProvider(settings, profile)
        raise KeyError(name)

    monkeypatch.setattr("app.api.v1.oauth.OAuthFactory.get_provider", _get)


def test_callback_rechecks_account_deactivated_after_linking(
    committed_env, db_engine, monkeypatch
):
    email = f"oauth-boundary-{uuid4().hex}@example.com"
    committed_env.emails.append(email)
    with committed_env.session() as db:
        user = User(email=email, username="oauth-boundary", is_active=True)
        db.add(user)
        db.flush()
        db.add(
            OAuthAccount(
                user_id=user.id,
                provider="google",
                provider_user_id="google-sub-boundary",
                email=email,
                access_token_encrypted="x",
            )
        )
        db.commit()
        user_id = user.id

    profile = OAuthUserProfile(
        provider_user_id="google-sub-boundary",
        email=email,
        name="OAuth Boundary",
        avatar_url=None,
    )
    _patch_google_factory(monkeypatch, profile)

    real_link = oauth_module.find_or_link_oauth_user

    def link_then_deactivate(*args, **kwargs):
        result = real_link(*args, **kwargs)
        # Independent connection: the request session keeps its cached instance.
        with db_engine.begin() as connection:
            connection.execute(
                text("UPDATE users SET is_active = false WHERE id = :user_id"),
                {"user_id": user_id},
            )
        return result

    monkeypatch.setattr(oauth_module, "find_or_link_oauth_user", link_then_deactivate)

    client = TestClient(app)
    authorize = client.get("/api/v1/oauth/google/authorize", follow_redirects=False)
    assert authorize.status_code == 302
    state = client.cookies.get("oauth_state")
    assert state

    response = client.get(
        "/api/v1/oauth/google/callback", params={"code": "test", "state": state}
    )

    assert response.status_code == 403
    assert "access_token" not in response.json()
    with committed_env.session() as db:
        assert (
            db.query(UserSession).filter(UserSession.user_id == user_id).count() == 0
        )
