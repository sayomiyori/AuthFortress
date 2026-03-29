import json

import pytest
from app.config import Settings
from app.models.oauth_account import OAuthAccount
from app.models.user import User
from app.services.oauth.account_service import find_or_link_oauth_user
from app.services.oauth.base import OAuthProvider, OAuthUserProfile
from sqlalchemy.orm import Session


class MockGoogleProvider(OAuthProvider):
    name = "google"

    def __init__(self, settings: Settings, profile: OAuthUserProfile | None = None):
        super().__init__(settings)
        self._profile = profile or OAuthUserProfile(
            provider_user_id="google-sub-1",
            email="oauth_new@example.com",
            name="OAuth User",
            avatar_url="https://example.com/a.png",
        )

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


def _patch_google_factory(monkeypatch, profile: OAuthUserProfile | None = None):
    def _get(name: str, s: Settings):
        if name.lower() == "google":
            return MockGoogleProvider(s, profile=profile)
        raise KeyError(name)

    monkeypatch.setattr("app.api.v1.oauth.OAuthFactory.get_provider", _get)


def test_oauth_authorize_redirect_and_state_in_redis(client, redis_client, monkeypatch, test_settings):
    _patch_google_factory(monkeypatch)
    r = client.get("/api/v1/oauth/google/authorize", follow_redirects=False)
    assert r.status_code == 302
    assert "accounts.google.com" in r.headers["location"]
    keys = [k for k in redis_client.keys() if str(k).startswith("oauth:state:")]
    assert len(keys) == 1
    raw = redis_client.get(keys[0])
    meta = json.loads(raw)
    assert meta["provider"] == "google"
    assert meta["response_mode"] == "json"


def test_oauth_callback_creates_user_and_tokens(client, redis_client, db_session: Session, monkeypatch, test_settings):
    _patch_google_factory(monkeypatch)
    client.get("/api/v1/oauth/google/authorize", follow_redirects=False)
    keys = [k for k in redis_client.keys() if str(k).startswith("oauth:state:")]
    state_key = keys[0]
    state = state_key.replace("oauth:state:", "")
    r = client.get(f"/api/v1/oauth/google/callback?code=test-code&state={state}")
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer"
    assert "access_token" in body and "refresh_token" in body

    u = db_session.query(User).filter(User.email == "oauth_new@example.com").one()
    assert u.hashed_password is None
    assert u.oauth_provider == "google"
    acc = db_session.query(OAuthAccount).filter(OAuthAccount.user_id == u.id).one()
    assert acc.provider == "google"
    assert acc.provider_user_id == "google-sub-1"
    assert acc.access_token_encrypted


def test_oauth_callback_links_existing_password_user(
    client, redis_client, db_session: Session, monkeypatch, test_settings
):
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "same@example.com",
            "password": "Secure1pass",
            "username": "sameuser",
        },
    )
    profile = OAuthUserProfile(
        provider_user_id="google-sub-99",
        email="same@example.com",
        name="Linked",
        avatar_url=None,
    )
    _patch_google_factory(monkeypatch, profile=profile)
    client.get("/api/v1/oauth/google/authorize", follow_redirects=False)
    keys = [k for k in redis_client.keys() if str(k).startswith("oauth:state:")]
    state = keys[0].replace("oauth:state:", "")
    r = client.get(f"/api/v1/oauth/google/callback?code=c2&state={state}")
    assert r.status_code == 200

    users = db_session.query(User).filter(User.email == "same@example.com").all()
    assert len(users) == 1
    assert users[0].hashed_password is not None
    acc = (
        db_session.query(OAuthAccount)
        .filter(OAuthAccount.user_id == users[0].id, OAuthAccount.provider == "google")
        .one()
    )
    assert acc.provider_user_id == "google-sub-99"


def test_find_or_link_raises_if_user_already_has_provider(db_session: Session, test_settings: Settings):
    u = User(
        email="dup@example.com",
        hashed_password=None,
        username="dup",
        oauth_provider="google",
    )
    db_session.add(u)
    db_session.flush()
    db_session.add(
        OAuthAccount(
            user_id=u.id,
            provider="google",
            provider_user_id="old-id",
            email="dup@example.com",
            access_token_encrypted="x",
        ),
    )
    db_session.commit()

    profile = OAuthUserProfile(
        provider_user_id="new-id",
        email="dup@example.com",
        name="X",
        avatar_url=None,
    )
    with pytest.raises(ValueError, match="already linked"):
        find_or_link_oauth_user(
            db_session,
            test_settings,
            provider="google",
            profile=profile,
            raw_access_token="t",
        )
