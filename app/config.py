from functools import lru_cache

from pydantic import Field, SecretStr, ValidationInfo, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        hide_input_in_errors=True,
    )

    app_name: str = "AuthFortress"
    debug: bool = False

    database_url: str = Field(
        default="postgresql://authfortress:authfortress@localhost:5432/authfortress",
        alias="DATABASE_URL",
    )
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")

    jwt_secret_key: str = Field(default="change-me-in-production-use-long-random", alias="JWT_SECRET_KEY")

    @field_validator("jwt_secret_key")
    @classmethod
    def validate_jwt_secret(cls, value: str) -> str:
        if len(value.encode()) < 32 or value == "change-me-in-production-use-long-random":
            raise ValueError("JWT_SECRET_KEY must be explicitly set to a random secret of at least 32 bytes")
        return value

    jwt_algorithm: str = "HS256"
    authfortress_webhook_service_key: SecretStr | None = Field(default=None, alias="AUTHFORTRESS_WEBHOOK_SERVICE_KEY")

    @field_validator("authfortress_webhook_service_key")
    @classmethod
    def validate_service_key(cls, value: SecretStr | None, info: ValidationInfo) -> SecretStr | None:
        if value is None:
            return None
        key = value.get_secret_value()
        if not key.isascii() or not 32 <= len(key) <= 256 or key == info.data.get("jwt_secret_key"):
            raise ValueError("AUTHFORTRESS_WEBHOOK_SERVICE_KEY must be independent ASCII secret of 32 to 256 bytes")
        return value

    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 30

    google_client_id: str = Field(default="", alias="GOOGLE_CLIENT_ID")
    google_client_secret: str = Field(default="", alias="GOOGLE_CLIENT_SECRET")
    github_client_id: str = Field(default="", alias="GITHUB_CLIENT_ID")
    github_client_secret: str = Field(default="", alias="GITHUB_CLIENT_SECRET")
    yandex_client_id: str = Field(default="", alias="YANDEX_CLIENT_ID")
    yandex_client_secret: str = Field(default="", alias="YANDEX_CLIENT_SECRET")
    oauth_redirect_base_url: str = Field(
        default="http://localhost:8000",
        alias="OAUTH_REDIRECT_BASE_URL",
    )
    oauth_token_encryption_key: str = Field(default="", alias="OAUTH_TOKEN_ENCRYPTION_KEY")


@lru_cache
def get_settings() -> Settings:
    return Settings()
