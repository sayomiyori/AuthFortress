from app.config import Settings
from app.services.oauth.base import OAuthProvider
from app.services.oauth.github import GitHubOAuthProvider
from app.services.oauth.google import GoogleOAuthProvider
from app.services.oauth.yandex import YandexOAuthProvider


class OAuthFactory:
    _registry: dict[str, type[OAuthProvider]] = {
        "google": GoogleOAuthProvider,
        "github": GitHubOAuthProvider,
        "yandex": YandexOAuthProvider,
    }

    @classmethod
    def get_provider(cls, name: str, settings: Settings) -> OAuthProvider:
        key = (name or "").lower().strip()
        impl = cls._registry.get(key)
        if not impl:
            raise KeyError(f"Unknown OAuth provider: {name}")
        return impl(settings)

    @classmethod
    def provider_names(cls) -> tuple[str, ...]:
        return tuple(sorted(cls._registry.keys()))
