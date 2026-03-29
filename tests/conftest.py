import pytest
from app.config import Settings, get_settings
from app.core.redis_client import get_redis
from app.db.session import Base, get_db
from app.main import app
from fakeredis import FakeStrictRedis
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


@pytest.fixture
def redis_client():
    return FakeStrictRedis(decode_responses=True)


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture
def test_settings(monkeypatch) -> Settings:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    for key in (
        "GOOGLE_CLIENT_ID",
        "GOOGLE_CLIENT_SECRET",
        "GITHUB_CLIENT_ID",
        "GITHUB_CLIENT_SECRET",
        "YANDEX_CLIENT_ID",
        "YANDEX_CLIENT_SECRET",
        "OAUTH_REDIRECT_BASE_URL",
        "OAUTH_TOKEN_ENCRYPTION_KEY",
    ):
        monkeypatch.delenv(key, raising=False)
    return Settings(
        database_url="sqlite://",
        redis_url="redis://fake",
        jwt_secret_key="test-jwt-secret-key-min-32-characters-long",
        access_token_expire_minutes=15,
        refresh_token_expire_days=30,
        oauth_redirect_base_url="http://testserver",
        google_client_id="test-google-id",
        google_client_secret="test-google-secret",
        github_client_id="test-github-id",
        github_client_secret="test-github-secret",
        yandex_client_id="test-yandex-id",
        yandex_client_secret="test-yandex-secret",
    )


@pytest.fixture
def client(db_session, redis_client, test_settings, monkeypatch):
    def override_db():
        try:
            yield db_session
        finally:
            pass

    def override_settings():
        return test_settings

    get_settings.cache_clear()

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_redis] = lambda: redis_client
    app.dependency_overrides[get_settings] = override_settings

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()
