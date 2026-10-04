from abc import ABC, abstractmethod
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

import httpx
from pydantic import EmailStr, TypeAdapter, ValidationError

from app.config import Settings


@dataclass
class OAuthUserProfile:
    provider_user_id: str
    email: str
    name: str | None
    avatar_url: str | None

    def __post_init__(self) -> None:
        if not self.provider_user_id.strip() or len(self.provider_user_id) > 255:
            raise ValueError("OAuth provider returned invalid user id")
        try:
            self.email = str(TypeAdapter(EmailStr).validate_python(self.email)).lower()
        except ValidationError:
            raise ValueError("OAuth provider returned invalid email") from None


class OAuthProvider(ABC):
    name: str

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @property
    @abstractmethod
    def client_id(self) -> str:
        raise NotImplementedError

    @property
    @abstractmethod
    def client_secret(self) -> str:
        raise NotImplementedError

    def redirect_uri(self) -> str:
        base = self.settings.oauth_redirect_base_url.rstrip("/")
        return f"{base}/api/v1/oauth/{self.name}/callback"

    def configured(self) -> bool:
        return bool(self.client_id and self.client_secret)

    async def _exchange_code(self, token_url: str, authorization_response: str, client: httpx.AsyncClient) -> dict:
        code = parse_qs(urlparse(authorization_response).query).get("code", [""])[0]
        if not code:
            raise ValueError("Missing OAuth authorization code")
        response = await client.post(
            token_url,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.redirect_uri(),
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
            headers={"Accept": "application/json"},
        )
        response.raise_for_status()
        token = response.json()
        if (
            not isinstance(token, dict)
            or token.get("error")
            or not isinstance(token.get("access_token"), str)
            or not token["access_token"].strip()
        ):
            raise ValueError("OAuth provider did not return an access token")
        return token

    @abstractmethod
    def create_authorization_url(self, state: str) -> str:
        """Build provider authorize URL (client redirects user here)."""

    @abstractmethod
    async def exchange_code(
        self,
        authorization_response: str,
        client: httpx.AsyncClient,
    ) -> dict:
        """Exchange authorization_response URL for token dict (access_token, ...)."""

    @abstractmethod
    async def fetch_profile(self, token: dict, client: httpx.AsyncClient) -> OAuthUserProfile:
        """Load user profile using token from exchange_code."""
