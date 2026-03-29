import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client

from app.config import Settings
from app.services.oauth.base import OAuthProvider, OAuthUserProfile


class GitHubOAuthProvider(OAuthProvider):
    name = "github"
    _AUTH = "https://github.com/login/oauth/authorize"
    _TOKEN = "https://github.com/login/oauth/access_token"
    _API_USER = "https://api.github.com/user"
    _API_EMAILS = "https://api.github.com/user/emails"

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self._scope = "read:user user:email"

    @property
    def client_id(self) -> str:
        return self.settings.github_client_id

    @property
    def client_secret(self) -> str:
        return self.settings.github_client_secret

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
            raise ValueError("No access_token from GitHub")
        headers = {
            "Authorization": f"Bearer {access}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        r = await client.get(self._API_USER, headers=headers)
        r.raise_for_status()
        u = r.json()
        uid = u.get("id")
        if uid is None:
            raise ValueError("GitHub did not return id")
        email = u.get("email")
        if not email:
            er = await client.get(self._API_EMAILS, headers=headers)
            er.raise_for_status()
            for row in er.json():
                if row.get("primary") and row.get("verified"):
                    email = row.get("email")
                    break
            if not email:
                for row in er.json():
                    if row.get("verified") and row.get("email"):
                        email = row.get("email")
                        break
        if not email:
            raise ValueError("GitHub did not return a verified email")
        return OAuthUserProfile(
            provider_user_id=str(uid),
            email=str(email).lower(),
            name=u.get("name") or u.get("login"),
            avatar_url=u.get("avatar_url"),
        )
