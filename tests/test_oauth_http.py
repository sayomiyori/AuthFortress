from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from app.models.oauth_account import OAuthAccount
from app.models.session import UserSession
from app.models.user import User
from app.services.oauth.factory import OAuthFactory
from app.services.oauth.token_crypto import decrypt_token


@pytest.fixture
def oauth_http(monkeypatch):
    original = httpx.AsyncClient

    def install(handler):
        monkeypatch.setattr(
            "app.api.v1.oauth.httpx.AsyncClient",
            lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs),
        )

    return install


def _profile_response(name, path):
    if name == "google":
        return {"sub": "remote-17", "email": "boundary@example.com", "email_verified": True, "name": "Boundary"}
    if name == "github":
        if path == "/user/emails":
            return [{"email": "boundary@example.com", "primary": True, "verified": True}]
        return {"id": 17, "email": None, "login": "boundary", "name": "Boundary"}
    return {"id": "remote-17", "default_email": "boundary@example.com", "display_name": "Boundary"}


def _state(client, name):
    response = client.get(f"/api/v1/oauth/{name}/authorize", follow_redirects=False)
    assert response.status_code == 302
    return parse_qs(urlparse(response.headers["location"]).query)["state"][0]


@pytest.mark.parametrize("name", ["google", "github", "yandex"])
@pytest.mark.parametrize("existing_user", [False, True])
def test_real_adapter_callback_registers_links_and_reuses_identity(
    name, existing_user, client, db_session, test_settings, oauth_http
):
    provider = OAuthFactory.get_provider(name, test_settings)
    if existing_user:
        db_session.add(
            User(email="boundary@example.com", username="existing", hashed_password="existing-password-hash")
        )
        db_session.commit()

    def handle(request):
        if str(request.url) == provider._TOKEN:
            return httpx.Response(200, json={"access_token": "external-boundary-token", "token_type": "Bearer"})
        assert request.headers["Authorization"] == (
            "OAuth external-boundary-token" if name == "yandex" else "Bearer external-boundary-token"
        )
        return httpx.Response(200, json=_profile_response(name, request.url.path))

    oauth_http(handle)
    for _ in range(2):
        state = _state(client, name)
        response = client.get(f"/api/v1/oauth/{name}/callback", params={"code": "boundary-code", "state": state})
        assert response.status_code == 200
        user = db_session.query(User).filter(User.email == "boundary@example.com").one()
        access = response.json()["access_token"]
        identity = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {access}"})
        assert identity.status_code == 200
        assert identity.json()["id"] == str(user.id)
    assert db_session.query(User).count() == 1
    account = db_session.query(OAuthAccount).one()
    assert account.user_id == user.id
    assert decrypt_token(test_settings, account.access_token_encrypted) == "external-boundary-token"
    assert account.access_token_encrypted != "external-boundary-token"
    assert user.hashed_password == ("existing-password-hash" if existing_user else None)


@pytest.mark.parametrize("name", ["google", "github", "yandex"])
@pytest.mark.parametrize("stage,failure,expected", [
    ("token", "401", 502), ("token", "429", 502), ("token", "503", 502),
    ("token", "timeout", 502), ("token", "malformed", 400), ("token", "oauth_error", 400),
    ("token", "missing_access", 400),
    ("profile", "401", 502), ("profile", "429", 502), ("profile", "503", 502),
    ("profile", "timeout", 502), ("profile", "malformed", 400), ("profile", "missing_identity", 400),
])
def test_real_adapter_callback_failures_do_not_issue_or_link_accounts(
    name, stage, failure, expected, client, db_session, redis_client, test_settings, oauth_http
):
    provider = OAuthFactory.get_provider(name, test_settings)

    def handle(request):
        is_token = str(request.url) == provider._TOKEN
        if (stage == "token") == is_token:
            if failure.isdigit():
                return httpx.Response(int(failure), json={"error": "provider_failure"})
            if failure == "timeout":
                raise httpx.ReadTimeout("Boundary timeout", request=request)
            if failure == "malformed":
                return httpx.Response(200, text="not-json")
            if failure == "oauth_error":
                return httpx.Response(200, json={"error": "invalid_grant", "error_description": "DO_NOT_EXPOSE"})
            return httpx.Response(200, json={})
        if is_token:
            return httpx.Response(200, json={"access_token": "external-boundary-token", "token_type": "Bearer"})
        return httpx.Response(200, json=_profile_response(name, request.url.path))

    oauth_http(handle)
    state = _state(client, name)
    response = client.get(f"/api/v1/oauth/{name}/callback", params={"code": "boundary-code", "state": state})
    assert response.status_code == expected
    assert "access_token" not in response.json()
    assert "DO_NOT_EXPOSE" not in response.text
    assert db_session.query(User).count() == 0
    assert db_session.query(OAuthAccount).count() == 0
    assert db_session.query(UserSession).count() == 0
    assert redis_client.get(f"oauth:state:{state}") is None
    replay = client.get(f"/api/v1/oauth/{name}/callback", params={"code": "boundary-code", "state": state})
    assert replay.status_code == 400
