import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client

from app.config import Settings
from app.services.oauth.base import OAuthProvider, OAuthUserProfile


class YandexOAuthProvider(OAuthProvider):
    name = "yandex"
    _AUTH = "https://oauth.yandex.ru/authorize"
    _TOKEN = "https://oauth.yandex.ru/token"
    _INFO = "https://login.yandex.ru/info"

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self._scope = "login:email login:info"

    @property
    def client_id(self) -> str:
        return self.settings.yandex_client_id

    @property
    def client_secret(self) -> str:
        return self.settings.yandex_client_secret

    def create_authorization_url(self, state: str) -> str:
        oauth = AsyncOAuth2Client(
            self.client_id,
            self.client_secret,
            scope=self._scope,
            redirect_uri=self.redirect_uri(),
        )
        uri, _ = oauth.create_authorization_url(self._AUTH, state=state)
        return uri

    async def exchange_code(self, authorization_response: str, client: httpx.AsyncClient) -> dict:
        oauth = AsyncOAuth2Client(
            self.client_id,
            self.client_secret,
            redirect_uri=self.redirect_uri(),
            client=client,
        )
        return await oauth.fetch_token(
            self._TOKEN,
            authorization_response=authorization_response,
        )

    async def fetch_profile(self, token: dict, client: httpx.AsyncClient) -> OAuthUserProfile:
        access = token.get("access_token")
        if not access:
            raise ValueError("No access_token from Yandex")
        r = await client.get(
            self._INFO,
            params={"format": "json"},
            headers={"Authorization": f"OAuth {access}"},
        )
        r.raise_for_status()
        d = r.json()
        yid = d.get("id")
        if yid is None:
            raise ValueError("Yandex did not return id")
        email = d.get("default_email") or d.get("emails", [None])[0]
        if not email:
            raise ValueError("Yandex did not return email")
        return OAuthUserProfile(
            provider_user_id=str(yid),
            email=str(email).lower(),
            name=d.get("display_name") or d.get("real_name") or d.get("login"),
            avatar_url=None,
        )
