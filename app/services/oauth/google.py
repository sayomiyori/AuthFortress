import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client

from app.config import Settings
from app.services.oauth.base import OAuthProvider, OAuthUserProfile


class GoogleOAuthProvider(OAuthProvider):
    name = "google"
    _AUTH = "https://accounts.google.com/o/oauth2/v2/auth"
    _TOKEN = "https://oauth2.googleapis.com/token"
    _USERINFO = "https://www.googleapis.com/oauth2/v3/userinfo"

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self._scope = "openid email profile"

    @property
    def client_id(self) -> str:
        return self.settings.google_client_id

    @property
    def client_secret(self) -> str:
        return self.settings.google_client_secret

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
            raise ValueError("No access_token from Google")
        r = await client.get(
            self._USERINFO,
            headers={"Authorization": f"Bearer {access}"},
        )
        r.raise_for_status()
        d = r.json()
        ev = d.get("email_verified", True)
        if ev is False or str(ev).lower() in ("false", "0", ""):
            raise ValueError("Google email not verified")
        email = d.get("email")
        if not email:
            raise ValueError("Google did not return email")
        sub = d.get("sub")
        if not sub:
            raise ValueError("Google did not return sub")
        return OAuthUserProfile(
            provider_user_id=str(sub),
            email=email.lower(),
            name=d.get("name"),
            avatar_url=d.get("picture"),
        )
