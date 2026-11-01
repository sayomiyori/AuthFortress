"""2FA state changes end every other session and keep the caller's own.

The shared ``client`` fixture runs every request in one outer transaction, which
is correct for sequential assertions but cannot model two independent PostgreSQL
transactions. Race tests use ``committed_env``: the application is wired to a
real session factory on the test engine, so each request opens and commits its
own transaction and both threads actually contend for the user row lock.
"""

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from uuid import uuid4

import pyotp
import pytest
from app.config import Settings, get_settings
from app.core.redis_client import get_redis
from app.core.security import get_current_user, security_scheme
from app.db.session import get_db
from app.main import app
from app.models.audit import AuditLog
from app.models.user import User
from app.services.auth_service import create_session_and_tokens
from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.testclient import TestClient
from redis import Redis
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

AUDIT_PATHS = {
    "/api/v1/auth/register",
    "/api/v1/auth/login",
    "/api/v1/auth/2fa/setup",
    "/api/v1/auth/2fa/verify",
    "/api/v1/auth/login/2fa",
    "/api/v1/auth/2fa/disable",
    "/api/v1/auth/me",
}


class CommittedEnv:
    """Committed-data harness: every app request gets its own transaction."""

    def __init__(self, session_factory):
        self.session = session_factory
        self.emails: list[str] = []
        self.audit_paths: set[str] = set(AUDIT_PATHS)


@pytest.fixture
def committed_env(db_engine, redis_client, test_settings, monkeypatch):
    session_factory = sessionmaker(bind=db_engine)
    started = datetime.now(UTC)

    def override_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    monkeypatch.setattr("app.middleware.audit.SessionLocal", session_factory)
    get_settings.cache_clear()
    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_redis] = lambda: redis_client
    app.dependency_overrides[get_settings] = lambda: test_settings
    env = CommittedEnv(session_factory)
    try:
        yield env
    finally:
        app.dependency_overrides.clear()
        get_settings.cache_clear()
        # Remove only rows this test owns: its users, their audits, and the
        # transport-level audit rows for its own paths (no user attribution).
        with session_factory() as db:
            owned_ids = []
            if env.emails:
                owned_ids = [
                    row[0]
                    for row in db.query(User.id).filter(User.email.in_(env.emails)).all()
                ]
            if owned_ids:
                db.query(AuditLog).filter(
                    AuditLog.user_id.in_(owned_ids)
                ).delete(synchronize_session=False)
                db.query(User).filter(
                    User.id.in_(owned_ids)
                ).delete(synchronize_session=False)
            if env.audit_paths:
                db.query(AuditLog).filter(
                    AuditLog.created_at >= started,
                    AuditLog.user_id.is_(None),
                    AuditLog.details["path"].as_string().in_(sorted(env.audit_paths)),
                ).delete(synchronize_session=False)
            db.commit()


def _credentials() -> dict[str, str]:
    return {
        "email": f"boundary-{uuid4().hex}@example.com",
        "password": "Secure1pass",
        "username": "boundary",
    }


def _login(client, credentials: dict[str, str]) -> dict[str, str]:
    response = client.post("/api/v1/auth/login", json=credentials)
    assert response.status_code == 200
    assert "access_token" in response.json()
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _enable_twofa(client, headers: dict[str, str], password: str) -> tuple[str, list[str]]:
    setup = client.post(
        "/api/v1/auth/2fa/setup", json={"current_password": password}, headers=headers
    )
    assert setup.status_code == 200
    secret = setup.json()["secret"]
    verify = client.post(
        "/api/v1/auth/2fa/verify",
        json={"code": pyotp.TOTP(secret).now(), "current_password": password},
        headers=headers,
    )
    assert verify.status_code == 200
    return secret, list(verify.json()["backup_codes"])


def _twofa_login(client, credentials: dict[str, str], code: str):
    challenge = client.post("/api/v1/auth/login", json=credentials)
    assert challenge.status_code == 200
    assert challenge.json()["requires_2fa"]
    return client.post(
        "/api/v1/auth/login/2fa",
        json={"temp_token": challenge.json()["temp_token"], "code": code},
    )


@pytest.fixture
def two_sessions(client):
    credentials = _credentials()
    assert client.post("/api/v1/auth/register", json=credentials).status_code == 200
    first = _login(client, credentials)
    second = _login(client, credentials)
    return credentials, first, second


def test_enable_revokes_other_sessions_and_keeps_caller(client, two_sessions):
    credentials, first, second = two_sessions
    _enable_twofa(client, first, credentials["password"])

    assert client.get("/api/v1/auth/me", headers=first).status_code == 200
    assert client.get("/api/v1/auth/me", headers=second).status_code == 401


def test_disable_revokes_other_sessions_and_keeps_caller(client, two_sessions):
    credentials, first, _ = two_sessions
    _, backup_codes = _enable_twofa(client, first, credentials["password"])

    other = _twofa_login(client, credentials, backup_codes[0])
    assert other.status_code == 200
    other_headers = {"Authorization": f"Bearer {other.json()['access_token']}"}
    assert client.get("/api/v1/auth/me", headers=other_headers).status_code == 200

    disabled = client.post(
        "/api/v1/auth/2fa/disable",
        json={"code": backup_codes[1]},
        headers=first,
    )
    assert disabled.status_code == 204

    assert client.get("/api/v1/auth/me", headers=first).status_code == 200
    assert client.get("/api/v1/auth/me", headers=other_headers).status_code == 401


def test_setup_and_failed_code_do_not_revoke(client, two_sessions):
    credentials, first, second = two_sessions

    setup_body = {"current_password": credentials["password"]}
    assert client.post(
        "/api/v1/auth/2fa/setup", json=setup_body, headers=first
    ).status_code == 200
    assert client.get("/api/v1/auth/me", headers=second).status_code == 200

    assert client.post(
        "/api/v1/auth/2fa/verify",
        json={"code": "000000", "current_password": credentials["password"]},
        headers=first,
    ).status_code == 400
    assert client.get("/api/v1/auth/me", headers=second).status_code == 200

    _, backup_codes = _enable_twofa(client, first, credentials["password"])
    other = _twofa_login(client, credentials, backup_codes[0])
    assert other.status_code == 200
    other_headers = {"Authorization": f"Bearer {other.json()['access_token']}"}

    assert client.post(
        "/api/v1/auth/2fa/disable", json={"code": "000000"}, headers=first
    ).status_code == 400
    assert client.get("/api/v1/auth/me", headers=other_headers).status_code == 200


def test_backup_code_is_not_consumed_when_issuance_fails(client, db_session):
    credentials = _credentials()
    assert client.post("/api/v1/auth/register", json=credentials).status_code == 200
    headers = _login(client, credentials)
    _, backup_codes = _enable_twofa(client, headers, credentials["password"])
    code = backup_codes[0]

    challenge = client.post("/api/v1/auth/login", json=credentials).json()["temp_token"]

    def fail_issuance(*args, **kwargs):
        raise RuntimeError("issuance failed")

    # Scope the patch to this request only. Never call undo() on the fixture's
    # monkeypatch: it also rebinds app.middleware.audit.SessionLocal, and losing
    # that binding makes audit writes escape the outer test transaction.
    with pytest.MonkeyPatch.context() as scoped:
        scoped.setattr(
            "app.api.v1.auth.auth_service.create_session_and_tokens", fail_issuance
        )
        with pytest.raises(RuntimeError):
            client.post(
                "/api/v1/auth/login/2fa",
                json={"temp_token": challenge, "code": code},
            )

    # Production closes the request session, which rolls back uncommitted work.
    db_session.rollback()

    retry = _twofa_login(client, credentials, code)
    assert retry.status_code == 200


def test_concurrent_enable_leaves_exactly_one_session(committed_env):
    credentials = _credentials()
    committed_env.emails.append(credentials["email"])
    bootstrap = TestClient(app)
    assert bootstrap.post("/api/v1/auth/register", json=credentials).status_code == 200
    first = _login(bootstrap, credentials)
    second = _login(bootstrap, credentials)

    setup = bootstrap.post(
        "/api/v1/auth/2fa/setup",
        json={"current_password": credentials["password"]},
        headers=first,
    )
    assert setup.status_code == 200
    code = pyotp.TOTP(setup.json()["secret"]).now()

    barrier = threading.Barrier(2)

    def attempt(headers):
        client = TestClient(app)
        barrier.wait(timeout=10)
        return client.post(
            "/api/v1/auth/2fa/verify",
            json={"code": code, "current_password": credentials["password"]},
            headers=headers,
        ).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(attempt, [first, second]))

    assert sorted(statuses) == [200, 401], statuses
    survivors = [
        headers
        for headers in (first, second)
        if TestClient(app).get("/api/v1/auth/me", headers=headers).status_code == 200
    ]
    assert len(survivors) == 1


def test_concurrent_backup_login_cannot_survive_disable(committed_env):
    credentials = _credentials()
    committed_env.emails.append(credentials["email"])
    bootstrap = TestClient(app)
    assert bootstrap.post("/api/v1/auth/register", json=credentials).status_code == 200
    headers = _login(bootstrap, credentials)
    secret, backup_codes = _enable_twofa(bootstrap, headers, credentials["password"])

    challenge = bootstrap.post("/api/v1/auth/login", json=credentials).json()["temp_token"]
    totp_code = pyotp.TOTP(secret).now()
    barrier = threading.Barrier(2)

    def login_with_backup_code():
        client = TestClient(app)
        barrier.wait(timeout=10)
        return client.post(
            "/api/v1/auth/login/2fa",
            json={"temp_token": challenge, "code": backup_codes[0]},
        )

    def disable_twofa():
        client = TestClient(app)
        barrier.wait(timeout=10)
        return client.post(
            "/api/v1/auth/2fa/disable", json={"code": totp_code}, headers=headers
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        login_future = pool.submit(login_with_backup_code)
        disable_future = pool.submit(disable_twofa)
        login_response = login_future.result(timeout=30)
        disable_response = disable_future.result(timeout=30)

    assert disable_response.status_code == 204
    assert login_response.status_code in (200, 401), login_response.status_code
    if login_response.status_code == 200:
        issued = {"Authorization": f"Bearer {login_response.json()['access_token']}"}
        assert TestClient(app).get("/api/v1/auth/me", headers=issued).status_code == 401


def test_stepup_required_for_setup_and_verify(client, two_sessions):
    credentials, first, second = two_sessions

    # A bearer alone is not enough: the field is part of the contract now.
    assert client.post("/api/v1/auth/2fa/setup", headers=first).status_code == 422
    wrong = client.post(
        "/api/v1/auth/2fa/setup",
        json={"current_password": "Wrong1pass"},
        headers=first,
    )
    assert wrong.status_code == 400
    assert "Wrong1pass" not in wrong.text

    # Nothing was enabled and the other session is untouched.
    assert client.get("/api/v1/auth/me", headers=second).status_code == 200

    secret, backup_codes = _enable_twofa(client, first, credentials["password"])
    assert len(backup_codes) == 10
    assert secret


def test_stepup_failure_does_not_revoke_or_enroll(client, two_sessions, db_session):
    credentials, first, second = two_sessions
    response = client.post(
        "/api/v1/auth/2fa/setup",
        json={"current_password": "Wrong1pass"},
        headers=first,
    )
    assert response.status_code == 400

    assert client.get("/api/v1/auth/me", headers=first).status_code == 200
    assert client.get("/api/v1/auth/me", headers=second).status_code == 200
    stored = db_session.query(User).filter(User.email == credentials["email"]).one()
    assert stored.totp_enabled is False
    assert stored.totp_secret_encrypted is None


def test_stolen_session_cannot_complete_enrollment_without_password(client, two_sessions):
    credentials, owner, stolen = two_sessions
    setup = client.post(
        "/api/v1/auth/2fa/setup",
        json={"current_password": credentials["password"]},
        headers=owner,
    )
    assert setup.status_code == 200
    code = pyotp.TOTP(setup.json()["secret"]).now()

    assert client.post(
        "/api/v1/auth/2fa/verify", json={"code": code}, headers=stolen
    ).status_code == 422
    assert client.post(
        "/api/v1/auth/2fa/verify",
        json={"code": code, "current_password": "Wrong1pass"},
        headers=stolen,
    ).status_code == 400
    # The owner can still finish, and the stolen session ends with enrollment.
    assert client.post(
        "/api/v1/auth/2fa/verify",
        json={"code": code, "current_password": credentials["password"]},
        headers=owner,
    ).status_code == 200
    assert client.get("/api/v1/auth/me", headers=stolen).status_code == 401


def test_stepup_budget_is_shared_between_setup_and_verify(client, two_sessions):
    credentials, first, _ = two_sessions
    for _ in range(3):
        assert client.post(
            "/api/v1/auth/2fa/setup",
            json={"current_password": "Wrong1pass"},
            headers=first,
        ).status_code == 400
    for _ in range(2):
        assert client.post(
            "/api/v1/auth/2fa/verify",
            json={"code": "000000", "current_password": "Wrong1pass"},
            headers=first,
        ).status_code == 400

    blocked = client.post(
        "/api/v1/auth/2fa/verify",
        json={"code": "000000", "current_password": credentials["password"]},
        headers=first,
    )
    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) > 0


def test_oauth_only_account_cannot_enroll(client, db_session, redis_client, test_settings):
    user = User(
        email=f"oauthonly-{uuid4().hex}@example.com",
        username="oauthonly",
        hashed_password=None,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    access, _, _ = create_session_and_tokens(
        db_session, test_settings, redis_client, user=user, device_info=None, ip=None
    )
    headers = {"Authorization": f"Bearer {access}"}
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200

    assert client.post(
        "/api/v1/auth/2fa/setup", json={"current_password": "anything"}, headers=headers
    ).status_code == 400
    assert client.post(
        "/api/v1/auth/2fa/verify",
        json={"code": "000000", "current_password": "anything"},
        headers=headers,
    ).status_code == 400

    db_session.refresh(user)
    assert user.totp_enabled is False
    assert user.totp_secret_encrypted is None


def test_malformed_unicode_current_password_is_denied(client, two_sessions):
    credentials, first, _ = two_sessions
    setup = client.post(
        "/api/v1/auth/2fa/setup",
        json={"current_password": credentials["password"]},
        headers=first,
    )
    assert setup.status_code == 200
    code = pyotp.TOTP(setup.json()["secret"]).now()

    # Sent as an escaped JSON surrogate: httpx cannot encode a lone surrogate
    # client-side, but the server must still deny it instead of crashing.
    payload = '{"code": "' + code + '", "current_password": "\\ud800"}'
    response = client.post(
        "/api/v1/auth/2fa/verify",
        content=payload.encode("ascii"),
        headers={"content-type": "application/json", **first},
    )
    assert response.status_code == 400


def test_validation_error_does_not_echo_current_password(client, two_sessions):
    _, first, _ = two_sessions
    marker = "Synthetic-Stepup-Marker-9!"
    response = client.post(
        "/api/v1/auth/2fa/verify", json={"current_password": marker}, headers=first
    )
    assert response.status_code == 422
    assert marker not in response.text


def test_deactivating_account_while_waiting_is_rejected(committed_env, db_engine):
    credentials = _credentials()
    committed_env.emails.append(credentials["email"])
    client = TestClient(app)
    assert client.post("/api/v1/auth/register", json=credentials).status_code == 200
    headers = _login(client, credentials)

    def deactivate_then_return(
        credentials: HTTPAuthorizationCredentials | None = Depends(security_scheme),
        db: Session = Depends(get_db),
        settings: Settings = Depends(get_settings),
        redis_client: Redis = Depends(get_redis),
    ) -> User:
        # Call the real dependency directly (no Depends recursion), then commit
        # a deactivation between its active check and _lock_caller's row lock.
        user = get_current_user(
            credentials=credentials,
            db=db,
            settings=settings,
            redis_client=redis_client,
        )
        with db_engine.begin() as connection:
            connection.execute(
                text("UPDATE users SET is_active = false WHERE id = :id"),
                {"id": user.id},
            )
        return user

    app.dependency_overrides[get_current_user] = deactivate_then_return
    response = client.post(
        "/api/v1/auth/2fa/setup",
        json={"current_password": credentials["password"]},
        headers=headers,
    )
    assert response.status_code == 401
