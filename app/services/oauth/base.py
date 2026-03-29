from abc import ABC, abstractmethod
from dataclasses import dataclass

import httpx

from app.config import Settings


@dataclass
class OAuthUserProfile:
    provider_user_id: str
    email: str
    name: str | None
    avatar_url: str | None


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
