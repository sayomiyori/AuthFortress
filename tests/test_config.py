import pytest
from app.config import Settings
from pydantic import ValidationError


@pytest.mark.parametrize("secret", ["", "short", "change-me-in-production-use-long-random"])
def test_known_or_weak_jwt_secret_is_rejected(secret, monkeypatch):
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    with pytest.raises(ValidationError, match="JWT_SECRET_KEY"):
        Settings(_env_file=None, JWT_SECRET_KEY=secret)


def test_default_jwt_secret_is_rejected(monkeypatch):
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    with pytest.raises(ValidationError, match="JWT_SECRET_KEY"):
        Settings(_env_file=None)


@pytest.mark.parametrize("key", ["", "short", "é" * 32, "x" * 257, "test-jwt-secret-key-min-32-characters-long"])
def test_invalid_service_key_is_rejected(key):
    with pytest.raises(ValidationError, match="AUTHFORTRESS_WEBHOOK_SERVICE_KEY") as caught:
        Settings(_env_file=None, JWT_SECRET_KEY="test-jwt-secret-key-min-32-characters-long",
                 AUTHFORTRESS_WEBHOOK_SERVICE_KEY=key)
    assert "input_value=" not in str(caught.value)


@pytest.mark.parametrize("key", [None, "s" * 32, "s" * 256])
def test_optional_service_key_accepts_boundaries_and_hides_repr(key):
    settings = Settings(_env_file=None, JWT_SECRET_KEY="test-jwt-secret-key-min-32-characters-long",
                        AUTHFORTRESS_WEBHOOK_SERVICE_KEY=key)
    if key is not None:
        assert settings.authfortress_webhook_service_key.get_secret_value() == key
        assert key not in repr(settings)
