import os

import pytest
from alembic import command
from alembic.config import Config
from app.config import Settings, get_settings
from app.core.redis_client import get_redis
from app.db.session import get_db
from app.main import app
from fastapi.testclient import TestClient
from redis import Redis
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker


@pytest.fixture
def redis_client():
    url = os.environ.get("TEST_REDIS_URL")
    if not url or not url.endswith("/15"):
        pytest.fail("Set TEST_REDIS_URL to the isolated verification Redis database /15")
    client = Redis.from_url(url, decode_responses=True, socket_timeout=3)
    client.ping()
    existing = set(client.scan_iter())
    yield client
    created = set(client.scan_iter()) - existing
    if created:
        client.delete(*created)
    client.close()


@pytest.fixture(scope="session")
def db_engine():
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.fail("Set TEST_DATABASE_URL to a disposable PostgreSQL database")
    parsed = make_url(url)
    if parsed.get_backend_name() != "postgresql" or not (parsed.database or "").endswith("test"):
        pytest.fail("TEST_DATABASE_URL must identify a PostgreSQL database ending in 'test'")
    engine = create_engine(url, connect_args={"connect_timeout": 3})
    get_settings.cache_clear()
    previous = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = url
    try:
        command.upgrade(Config("alembic.ini"), "head")
    finally:
        if previous is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous
        get_settings.cache_clear()
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(db_engine, monkeypatch):
    connection = db_engine.connect()
    transaction = connection.begin()
    SessionLocal = sessionmaker(bind=connection, join_transaction_mode="create_savepoint")
    monkeypatch.setattr("app.middleware.audit.SessionLocal", SessionLocal)
    session = SessionLocal()
    yield session
    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def test_settings(monkeypatch) -> Settings:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    for key in (
        "AUTHFORTRESS_WEBHOOK_SERVICE_KEY",
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
        _env_file=None,
        DATABASE_URL=os.environ["TEST_DATABASE_URL"],
        REDIS_URL=os.environ["TEST_REDIS_URL"],
        JWT_SECRET_KEY="test-jwt-secret-key-min-32-characters-long",
        access_token_expire_minutes=15,
        refresh_token_expire_days=30,
        OAUTH_REDIRECT_BASE_URL="http://testserver",
        GOOGLE_CLIENT_ID="test-google-id",
        GOOGLE_CLIENT_SECRET="test-google-secret",
        GITHUB_CLIENT_ID="test-github-id",
        GITHUB_CLIENT_SECRET="test-github-secret",
        YANDEX_CLIENT_ID="test-yandex-id",
        YANDEX_CLIENT_SECRET="test-yandex-secret",
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

    try:
        with TestClient(app) as c:
            yield c
    finally:
        app.dependency_overrides.clear()
        get_settings.cache_clear()
