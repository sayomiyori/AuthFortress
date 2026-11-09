"""Durable session revocation through the separate refresh-credential endpoint.

Sequential HTTP assertions use the shared ``client`` fixture, which runs each
request inside one outer transaction. The race tests use ``committed_env``: the
application is wired to a real session factory on the test engine, so every
request opens and commits its own transaction and two threads really contend
for the same ``sessions`` row lock.

``POST /api/v1/auth/logout`` is deliberately not exercised with a refresh body:
it keeps its original bearer-only, body-agnostic contract. The refresh
credential logout lives at ``POST /api/v1/auth/logout/refresh``.
"""

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import jwt
import pytest
from app.config import get_settings
from app.core.redis_client import get_redis
from app.db.session import get_db
from app.main import app
from app.models.audit import AuditLog
from app.models.session import UserSession
from app.models.user import User
from app.services import auth_service, jwt_service
from fastapi.testclient import TestClient
from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker


def _credentials(prefix: str = "continuity") -> dict[str, str]:
    return {
        "email": f"{prefix}-{uuid4().hex}@example.com",
        "password": "Secure1pass",
        "username": prefix,
    }


def _register_and_login(client, prefix: str = "continuity") -> tuple[dict[str, str], dict]:
    credentials = _credentials(prefix)
    assert client.post("/api/v1/auth/register", json=credentials).status_code == 200
    response = client.post(
        "/api/v1/auth/login",
        json={"email": credentials["email"], "password": credentials["password"]},
    )
    assert response.status_code == 200
    return credentials, response.json()


def _expired_access_token(test_settings, access_token: str) -> str:
    payload = jwt.decode(
        access_token,
        test_settings.jwt_secret_key,
        algorithms=[test_settings.jwt_algorithm],
    )
    payload["exp"] = int((datetime.now(UTC) - timedelta(minutes=5)).timestamp())
    return jwt.encode(payload, test_settings.jwt_secret_key, algorithm=test_settings.jwt_algorithm)


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_logout_refresh_revokes_session_after_access_expiry(client, test_settings):
    _, tokens = _register_and_login(client, "expired-access")
    expired = _expired_access_token(test_settings, tokens["access_token"])

    response = client.post(
        "/api/v1/auth/logout/refresh",
        json={"refresh_token": tokens["refresh_token"]},
        headers=_bearer(expired),
    )

    assert response.status_code == 204
    assert response.content == b""
    assert client.get("/api/v1/auth/me", headers=_bearer(tokens["access_token"])).status_code == 401
    assert (
        client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code
        == 401
    )


def test_older_rotated_refresh_token_still_ends_its_session(client):
    _, tokens = _register_and_login(client, "rotated")
    stale_refresh = tokens["refresh_token"]

    rotated = client.post("/api/v1/auth/refresh", json={"refresh_token": stale_refresh})
    assert rotated.status_code == 200
    current = rotated.json()

    assert (
        client.post("/api/v1/auth/logout/refresh", json={"refresh_token": stale_refresh}).status_code
        == 204
    )
    assert (
        client.post("/api/v1/auth/refresh", json={"refresh_token": current["refresh_token"]}).status_code
        == 401
    )
    assert client.get("/api/v1/auth/me", headers=_bearer(current["access_token"])).status_code == 401


def test_rotated_token_revokes_only_its_own_session(client):
    credentials, first = _register_and_login(client, "own-session")
    second = client.post(
        "/api/v1/auth/login",
        json={"email": credentials["email"], "password": credentials["password"]},
    ).json()

    rotated = client.post("/api/v1/auth/refresh", json={"refresh_token": first["refresh_token"]})
    assert rotated.status_code == 200, rotated.text

    assert (
        client.post(
            "/api/v1/auth/logout/refresh", json={"refresh_token": first["refresh_token"]}
        ).status_code
        == 204
    )
    # The other session of the same account is untouched.
    assert (
        client.post("/api/v1/auth/refresh", json={"refresh_token": second["refresh_token"]}).status_code
        == 200
    )
    # The freshly rotated token of the logged-out session is dead.
    assert (
        client.post("/api/v1/auth/refresh", json={"refresh_token": rotated.json()["refresh_token"]}).status_code
        == 401
    )


def test_refresh_token_still_cannot_authenticate(client):
    _, tokens = _register_and_login(client, "no-auth")
    assert client.get("/api/v1/auth/me", headers=_bearer(tokens["refresh_token"])).status_code == 401
    # The same session is still valid for a protected endpoint via its access token.
    assert client.get("/api/v1/auth/me", headers=_bearer(tokens["access_token"])).status_code == 200


def test_access_token_is_not_a_valid_refresh_logout_credential(client):
    _, tokens = _register_and_login(client, "type-confusion")
    response = client.post(
        "/api/v1/auth/logout/refresh", json={"refresh_token": tokens["access_token"]}
    )
    assert response.status_code == 401
    assert (
        client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code
        == 200
    )


def test_expired_refresh_token_is_rejected_and_session_survives(client, test_settings):
    _, tokens = _register_and_login(client, "expired-refresh")
    payload = jwt.decode(
        tokens["refresh_token"],
        test_settings.jwt_secret_key,
        algorithms=[test_settings.jwt_algorithm],
    )
    payload["exp"] = int((datetime.now(UTC) - timedelta(minutes=5)).timestamp())
    expired = jwt.encode(
        payload, test_settings.jwt_secret_key, algorithm=test_settings.jwt_algorithm
    )

    assert (
        client.post("/api/v1/auth/logout/refresh", json={"refresh_token": expired}).status_code
        == 401
    )
    assert (
        client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code
        == 200
    )


@pytest.mark.parametrize(
    "exp",
    [
        pytest.param("missing", id="missing"),
        pytest.param(None, id="none"),
        pytest.param("not-a-number", id="text"),
        pytest.param(float("inf"), id="infinite"),
        # ``math.isfinite`` converts to float; an integer this large overflows
        # that conversion, which previously escaped as a 500 instead of 401.
        pytest.param(10**400, id="huge-integer"),
    ],
)
def test_refresh_logout_rejects_missing_or_malformed_exp(client, test_settings, exp):
    _, tokens = _register_and_login(client, "bad-expiry")
    payload = jwt.decode(
        tokens["refresh_token"],
        test_settings.jwt_secret_key,
        algorithms=[test_settings.jwt_algorithm],
    )
    if exp == "missing":
        payload.pop("exp", None)
    else:
        payload["exp"] = exp
    forged = jwt.encode(
        payload, test_settings.jwt_secret_key, algorithm=test_settings.jwt_algorithm
    )

    response = client.post("/api/v1/auth/logout/refresh", json={"refresh_token": forged})
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid refresh token"}

    # The malformed credential neither authenticates nor revokes the session.
    assert client.get("/api/v1/auth/me", headers=_bearer(tokens["access_token"])).status_code == 200
    assert (
        client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code
        == 200
    )


def test_refresh_logout_cannot_revoke_another_session(client, test_settings):
    _, attacker = _register_and_login(client, "attacker")
    _, victim = _register_and_login(client, "victim")
    attacker_payload = jwt.decode(
        attacker["refresh_token"],
        test_settings.jwt_secret_key,
        algorithms=[test_settings.jwt_algorithm],
    )
    victim_payload = jwt.decode(
        victim["refresh_token"],
        test_settings.jwt_secret_key,
        algorithms=[test_settings.jwt_algorithm],
    )

    # A token that names the victim's session but claims the attacker's subject.
    wrong_subject = jwt.encode(
        {**victim_payload, "sub": attacker_payload["sub"]},
        test_settings.jwt_secret_key,
        algorithm=test_settings.jwt_algorithm,
    )
    # A token that names no session at all.
    unknown_session = jwt.encode(
        {**victim_payload, "sid": str(uuid4())},
        test_settings.jwt_secret_key,
        algorithm=test_settings.jwt_algorithm,
    )
    # A correctly shaped token signed with a different key.
    wrong_key = jwt.encode(
        victim_payload, "x" * 48, algorithm=test_settings.jwt_algorithm
    )

    for forged in (wrong_subject, unknown_session, wrong_key):
        assert (
            client.post("/api/v1/auth/logout/refresh", json={"refresh_token": forged}).status_code
            == 401
        )

    # Neither account's live session was revoked by the failed attempts.
    assert (
        client.post("/api/v1/auth/refresh", json={"refresh_token": victim["refresh_token"]}).status_code
        == 200
    )
    assert (
        client.post("/api/v1/auth/refresh", json={"refresh_token": attacker["refresh_token"]}).status_code
        == 200
    )


def test_logout_refresh_is_idempotent(client):
    _, tokens = _register_and_login(client, "idempotent")
    body = {"refresh_token": tokens["refresh_token"]}
    assert client.post("/api/v1/auth/logout/refresh", json=body).status_code == 204
    assert client.post("/api/v1/auth/logout/refresh", json=body).status_code == 204
    assert client.post("/api/v1/auth/refresh", json=body).status_code == 401


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(None, id="absent"),
        pytest.param([], id="array"),
        pytest.param("text", id="string"),
        pytest.param(1, id="number"),
        pytest.param({}, id="empty-object"),
        pytest.param({"other": "field"}, id="missing-field"),
    ],
)
def test_logout_refresh_requires_json_object_with_refresh_field(client, body):
    if body is None:
        response = client.post("/api/v1/auth/logout/refresh")
    else:
        response = client.post("/api/v1/auth/logout/refresh", json=body)
    assert response.status_code == 422


def test_logout_refresh_rejects_malformed_json(client):
    response = client.post(
        "/api/v1/auth/logout/refresh",
        content=b'{"refresh_token":',
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422


def test_logout_rejects_malformed_refresh_field_without_echoing_the_token(client):
    _, tokens = _register_and_login(client, "malformed-field")
    response = client.post(
        "/api/v1/auth/logout/refresh",
        json={"refresh_token": {"nested": tokens["refresh_token"]}},
    )

    assert response.status_code == 422
    assert tokens["refresh_token"] not in response.text
    assert (
        client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code
        == 200
    )


def test_logout_refresh_ignores_token_used_as_extra_field_name(client):
    _, tokens = _register_and_login(client, "field-name")
    token = tokens["refresh_token"]

    # The token itself is an extra JSON field name. Unknown fields are ignored,
    # so it is neither rejected nor reflected.
    response = client.post(
        "/api/v1/auth/logout/refresh",
        json={"refresh_token": token, token: "x"},
    )

    assert response.status_code == 204
    assert response.content == b""
    assert token not in response.text
    assert (
        client.post("/api/v1/auth/refresh", json={"refresh_token": token}).status_code
        == 401
    )


def test_token_as_extra_field_name_is_not_reflected_in_validation_error(client):
    _, tokens = _register_and_login(client, "field-name-error")
    token = tokens["refresh_token"]

    # The extra token-named key is ignored even while another supplied field is
    # malformed, so the 422 reports only the real field and never the token.
    response = client.post(
        "/api/v1/auth/logout/refresh",
        json={"refresh_token": 123, token: "x"},
    )

    assert response.status_code == 422
    assert token not in response.text
    assert all(token not in error["loc"] for error in response.json()["detail"])
    assert (
        client.post("/api/v1/auth/refresh", json={"refresh_token": token}).status_code
        == 200
    )


def test_logout_refresh_audit_omits_the_refresh_token(client, db_session, test_settings):
    _, tokens = _register_and_login(client, "audit")
    sid = jwt.decode(
        tokens["refresh_token"],
        test_settings.jwt_secret_key,
        algorithms=[test_settings.jwt_algorithm],
    )["sid"]

    response = client.post(
        "/api/v1/auth/logout/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert response.status_code == 204
    assert response.content == b""

    row = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "logout")
        .order_by(AuditLog.created_at.desc())
        .first()
    )
    assert row is not None
    assert row.details == {"session_id": sid}
    assert tokens["refresh_token"] not in str(row.details)


def test_access_token_logout_path_is_unchanged(client):
    _, tokens = _register_and_login(client, "access-path")
    assert (
        client.post("/api/v1/auth/logout", headers=_bearer(tokens["access_token"])).status_code
        == 204
    )
    assert client.get("/api/v1/auth/me", headers=_bearer(tokens["access_token"])).status_code == 401
    assert (
        client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code
        == 401
    )


@pytest.mark.parametrize(
    "request_kwargs",
    [
        pytest.param({"json": {"unexpected": True}}, id="extra-field"),
        pytest.param({"json": ["unexpected"]}, id="array-body"),
        pytest.param({"json": "unexpected"}, id="string-body"),
        pytest.param({"json": 1}, id="number-body"),
        pytest.param({"content": b'{"malformed":'}, id="malformed-json"),
    ],
)
def test_old_logout_keeps_ignoring_any_request_body(client, request_kwargs):
    _, tokens = _register_and_login(client, "old-body")
    headers = {**_bearer(tokens["access_token"]), "Content-Type": "application/json"}
    response = client.post("/api/v1/auth/logout", headers=headers, **request_kwargs)

    # Backward compatibility: the original endpoint never parsed a body.
    assert response.status_code == 204
    assert response.content == b""
    assert client.get("/api/v1/auth/me", headers=_bearer(tokens["access_token"])).status_code == 401
    assert (
        client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code
        == 401
    )


def test_old_logout_does_not_accept_a_refresh_token_body(client):
    _, tokens = _register_and_login(client, "old-no-bearer")
    response = client.post(
        "/api/v1/auth/logout", json={"refresh_token": tokens["refresh_token"]}
    )

    assert response.status_code == 401
    assert (
        client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code
        == 200
    )


class RedisExistsOutage:
    """Expose a live Redis client whose ``exists`` check is unavailable."""

    def __init__(self, real):
        self._real = real

    def exists(self, *args, **kwargs):
        raise RedisError("synthetic cache outage")

    def __getattr__(self, name):
        return getattr(self._real, name)


def test_refresh_logout_does_not_depend_on_the_access_cache(
    client, db_session, test_settings, redis_client
):
    _, tokens = _register_and_login(client, "redis-fallback")
    sid = jwt.decode(
        tokens["refresh_token"],
        test_settings.jwt_secret_key,
        algorithms=[test_settings.jwt_algorithm],
    )["sid"]

    # The refresh endpoint never performs the access-token Redis existence
    # check, so an access-cache outage cannot block durable revocation.
    app.dependency_overrides[get_redis] = lambda: RedisExistsOutage(redis_client)
    try:
        response = client.post(
            "/api/v1/auth/logout/refresh",
            json={"refresh_token": tokens["refresh_token"]},
        )
    finally:
        app.dependency_overrides[get_redis] = lambda: redis_client

    assert response.status_code == 204
    assert response.content == b""
    db_session.expire_all()
    stored = db_session.query(UserSession).filter(UserSession.id == UUID(sid)).one()
    assert stored.revoked_at is not None
    assert client.get("/api/v1/auth/me", headers=_bearer(tokens["access_token"])).status_code == 401
    assert (
        client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code
        == 401
    )


def test_revocation_is_durable_when_redis_delete_fails(
    db_session, test_settings, redis_client
):
    user = User(
        email=f"durable-{uuid4().hex}@example.com",
        hashed_password=None,
        username="durable",
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    _, refresh, session = auth_service.create_session_and_tokens(
        db_session, test_settings, redis_client, user=user, device_info=None, ip=None
    )

    class BrokenRedis:
        def delete(self, *args, **kwargs):
            raise RedisError("synthetic cache outage")

    user_id, session_id = auth_service.logout_session_with_refresh_token(
        db_session,
        test_settings,
        BrokenRedis(),
        refresh_token=refresh,
    )

    assert user_id == user.id
    assert session_id == str(session.id)
    db_session.expire_all()
    stored = db_session.query(UserSession).filter(UserSession.id == session.id).one()
    assert stored.revoked_at is not None


AUDIT_PATHS = {
    "/api/v1/auth/register",
    "/api/v1/auth/login",
    "/api/v1/auth/refresh",
    "/api/v1/auth/logout",
    "/api/v1/auth/logout/refresh",
    "/api/v1/auth/me",
}


class CommittedEnv:
    """Committed-data harness: every app request gets its own transaction."""

    def __init__(self, session_factory):
        self.session = session_factory
        self.user_ids: list[UUID] = []
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
            if env.user_ids:
                db.query(AuditLog).filter(AuditLog.user_id.in_(env.user_ids)).delete(
                    synchronize_session=False
                )
                db.query(User).filter(User.id.in_(env.user_ids)).delete(
                    synchronize_session=False
                )
            db.query(AuditLog).filter(
                AuditLog.created_at >= started,
                AuditLog.user_id.is_(None),
                AuditLog.details["path"].as_string().in_(sorted(env.audit_paths)),
            ).delete(synchronize_session=False)
            db.commit()


def _seed_session(env: CommittedEnv, test_settings, redis_client, prefix: str):
    credentials = _credentials(prefix)
    assert TestClient(app).post("/api/v1/auth/register", json=credentials).status_code == 200
    with env.session() as db:
        user = db.query(User).filter(User.email == credentials["email"]).one()
        env.user_ids.append(user.id)
        access, refresh, session = auth_service.create_session_and_tokens(
            db, test_settings, redis_client, user=user, device_info=None, ip=None
        )
        return user.id, str(session.id), access, refresh


def _wait_for_row_lock_waiter(db_engine, timeout: float = 10.0) -> bool:
    """Return True once a backend is queued on a ``SELECT ... FOR UPDATE``."""
    statement = text(
        "SELECT count(*) FROM pg_stat_activity "
        "WHERE datname = current_database() "
        "AND wait_event_type = 'Lock' "
        "AND query ILIKE '%FOR UPDATE%'"
    )
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with db_engine.connect() as connection:
            if connection.execute(statement).scalar_one():
                return True
        time.sleep(0.05)
    return False


def test_inflight_refresh_cannot_resurrect_a_logged_out_session(
    committed_env, db_engine, test_settings, redis_client, monkeypatch
):
    user_id, session_id, _, refresh = _seed_session(
        committed_env, test_settings, redis_client, "inflight"
    )

    real_new_jti = jwt_service.new_refresh_jti
    refresh_holds_lock = threading.Event()
    release_refresh = threading.Event()

    def gated_new_jti():
        # refresh_tokens already holds the session row lock at this point.
        refresh_holds_lock.set()
        if not release_refresh.wait(timeout=30):
            raise RuntimeError("refresh gate timed out")
        return real_new_jti()

    monkeypatch.setattr(jwt_service, "new_refresh_jti", gated_new_jti)

    def do_refresh():
        return TestClient(app).post(
            "/api/v1/auth/refresh", json={"refresh_token": refresh}
        )

    def do_logout():
        return TestClient(app).post(
            "/api/v1/auth/logout/refresh", json={"refresh_token": refresh}
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        refresh_future = pool.submit(do_refresh)
        assert refresh_holds_lock.wait(timeout=15)
        logout_future = pool.submit(do_logout)
        assert _wait_for_row_lock_waiter(db_engine), "logout must queue on the session row"
        release_refresh.set()
        refresh_response = refresh_future.result(timeout=30)
        logout_response = logout_future.result(timeout=30)

    assert refresh_response.status_code == 200
    assert logout_response.status_code == 204

    # The refresh actually issued a token pair, and the logout that followed it
    # revoked the session, so that pair can no longer restore access.
    issued = refresh_response.json()
    assert TestClient(app).get("/api/v1/auth/me", headers=_bearer(issued["access_token"])).status_code == 401
    assert (
        TestClient(app)
        .post("/api/v1/auth/refresh", json={"refresh_token": issued["refresh_token"]})
        .status_code
        == 401
    )

    with committed_env.session() as db:
        stored = db.query(UserSession).filter(UserSession.id == UUID(session_id)).one()
        assert stored.user_id == user_id
        assert stored.revoked_at is not None


def test_access_token_logout_queues_behind_refresh_rotation(
    committed_env, db_engine, test_settings, redis_client, monkeypatch
):
    _, session_id, access, refresh = _seed_session(
        committed_env, test_settings, redis_client, "access-race"
    )

    real_new_jti = jwt_service.new_refresh_jti
    refresh_holds_lock = threading.Event()
    release_refresh = threading.Event()

    def gated_new_jti():
        refresh_holds_lock.set()
        if not release_refresh.wait(timeout=30):
            raise RuntimeError("refresh gate timed out")
        return real_new_jti()

    monkeypatch.setattr(jwt_service, "new_refresh_jti", gated_new_jti)

    def do_refresh():
        return TestClient(app).post(
            "/api/v1/auth/refresh", json={"refresh_token": refresh}
        )

    def do_logout():
        return TestClient(app).post("/api/v1/auth/logout", headers=_bearer(access))

    with ThreadPoolExecutor(max_workers=2) as pool:
        refresh_future = pool.submit(do_refresh)
        assert refresh_holds_lock.wait(timeout=15)
        logout_future = pool.submit(do_logout)
        assert _wait_for_row_lock_waiter(db_engine), "logout must queue on the session row"
        release_refresh.set()
        refresh_response = refresh_future.result(timeout=30)
        logout_response = logout_future.result(timeout=30)

    assert refresh_response.status_code == 200
    assert logout_response.status_code == 204

    issued = refresh_response.json()
    assert TestClient(app).get("/api/v1/auth/me", headers=_bearer(issued["access_token"])).status_code == 401
    assert (
        TestClient(app)
        .post("/api/v1/auth/refresh", json={"refresh_token": issued["refresh_token"]})
        .status_code
        == 401
    )

    with committed_env.session() as db:
        stored = db.query(UserSession).filter(UserSession.id == UUID(session_id)).one()
        assert stored.revoked_at is not None
