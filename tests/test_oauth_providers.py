from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from app.services.oauth.factory import OAuthFactory


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def provider_transport(monkeypatch):
    async def forbid_network(*args, **kwargs):
        raise AssertionError("OAuth adapter bypassed supplied HTTP transport")

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", forbid_network)


@pytest.mark.parametrize("name", ["google", "github", "yandex"])
def test_authorization_url_contains_callback_scope_and_state(name, test_settings):
    provider = OAuthFactory.get_provider(name, test_settings)
    params = parse_qs(urlparse(provider.create_authorization_url("browser-state")).query)
    assert params["state"] == ["browser-state"]
    assert params["redirect_uri"] == [f"http://testserver/api/v1/oauth/{name}/callback"]
    assert params["response_type"] == ["code"]
    assert params["scope"]


@pytest.mark.anyio
@pytest.mark.parametrize("name", ["google", "github", "yandex"])
async def test_exchange_uses_supplied_http_boundary(name, test_settings, provider_transport):
    provider = OAuthFactory.get_provider(name, test_settings)
    requests = []

    def handle(request):
        requests.append(request)
        return httpx.Response(200, json={"access_token": "boundary-token", "token_type": "Bearer"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        token = await provider.exchange_code(
            f"http://testserver/api/v1/oauth/{name}/callback?code=boundary-code&state=browser-state", client
        )
    assert token["access_token"] == "boundary-token"
    assert len(requests) == 1
    request = requests[0]
    assert request.method == "POST"
    assert str(request.url) == provider._TOKEN
    data = parse_qs(request.content.decode())
    assert data["grant_type"] == ["authorization_code"]
    assert data["code"] == ["boundary-code"]
    assert data["redirect_uri"] == [provider.redirect_uri()]


@pytest.mark.anyio
@pytest.mark.parametrize("profile", [
    {"sub": "google-id", "email": "victim@example.com"},
    {"sub": "google-id", "email": "victim@example.com", "email_verified": None},
    {"sub": "google-id", "email": "victim@example.com", "email_verified": False},
])
async def test_google_requires_positive_email_verification(profile, test_settings, provider_transport):
    provider = OAuthFactory.get_provider("google", test_settings)
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=profile))) as client:
        with pytest.raises(ValueError, match="not verified"):
            await provider.fetch_profile({"access_token": "boundary-token"}, client)


@pytest.mark.anyio
async def test_github_public_email_requires_verified_emails_endpoint(test_settings, provider_transport):
    provider = OAuthFactory.get_provider("github", test_settings)

    def handle(request):
        if request.url.path == "/user":
            return httpx.Response(200, json={"id": 17, "email": "victim@example.com", "login": "test"})
        assert request.url.path == "/user/emails"
        return httpx.Response(200, json=[{"email": "victim@example.com", "verified": False, "primary": True}])

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        with pytest.raises(ValueError, match="verified email"):
            await provider.fetch_profile({"access_token": "boundary-token"}, client)


@pytest.mark.anyio
@pytest.mark.parametrize("name,payload", [
    ("google", {"sub": "google-id", "email": "invalid", "email_verified": True}),
    ("google", {"sub": "g" * 256, "email": "valid@example.com", "email_verified": True}),
    ("github", {"id": "", "login": "test"}),
    ("yandex", {"id": "", "default_email": "valid@example.com"}),
    ("yandex", {"id": "yandex-id", "default_email": "invalid"}),
    ("yandex", {"id": "yandex-id", "emails": []}),
])
async def test_provider_rejects_invalid_profile(name, payload, test_settings, provider_transport):
    provider = OAuthFactory.get_provider(name, test_settings)

    def handle(request):
        if request.url.path == "/user/emails":
            return httpx.Response(200, json=[{"email": "valid@example.com", "verified": True, "primary": True}])
        return httpx.Response(200, json=payload)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        with pytest.raises(ValueError):
            await provider.fetch_profile({"access_token": "boundary-token"}, client)


@pytest.mark.anyio
@pytest.mark.parametrize("name", ["google", "github", "yandex"])
@pytest.mark.parametrize("token", [{}, {"access_token": 17}, {"error": "invalid_grant"}, []])
async def test_exchange_rejects_invalid_token_response(name, token, test_settings, provider_transport):
    provider = OAuthFactory.get_provider(name, test_settings)
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=token))) as client:
        with pytest.raises(ValueError, match="access token"):
            await provider.exchange_code(f"{provider.redirect_uri()}?code=boundary-code", client)
