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
