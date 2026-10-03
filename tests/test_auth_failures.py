from datetime import UTC, datetime, timedelta

import jwt
import pytest
from app.models.audit import AuditLog
from app.models.user import User, UserRole


@pytest.fixture
def registered_user(client):
    body = {"email": "failure@example.com", "password": "Secure1pass", "username": "failure"}
    response = client.post("/api/v1/auth/register", json=body)
    assert response.status_code == 200
    return body


@pytest.fixture
def tokens(client, registered_user):
    response = client.post(
        "/api/v1/auth/login",
        json={"email": registered_user["email"], "password": registered_user["password"]},
    )
    assert response.status_code == 200
    return response.json()


def test_wrong_password_does_not_issue_tokens(client, registered_user):
    response = client.post(
        "/api/v1/auth/login", json={"email": registered_user["email"], "password": "Wrong1pass"}
    )
    assert response.status_code == 401
    assert "access_token" not in response.json()


@pytest.mark.parametrize("authorization", [None, "Bearer malformed", "Basic invalid"])
def test_protected_endpoint_rejects_invalid_authentication(client, authorization):
    headers = {"Authorization": authorization} if authorization else {}
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401


def test_refresh_token_cannot_authenticate_protected_endpoint(client, tokens):
    response = client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {tokens['refresh_token']}"}
    )
    assert response.status_code == 401


def test_expired_access_token_is_rejected(client, tokens, test_settings):
    payload = jwt.decode(tokens["access_token"], test_settings.jwt_secret_key, algorithms=["HS256"])
    payload["exp"] = datetime.now(UTC) - timedelta(seconds=1)
    token = jwt.encode(payload, test_settings.jwt_secret_key, algorithm="HS256")
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_access_token_requires_session_claim(client, tokens, test_settings):
    payload = jwt.decode(tokens["access_token"], test_settings.jwt_secret_key, algorithms=["HS256"])
    del payload["sid"]
    token = jwt.encode(payload, test_settings.jwt_secret_key, algorithm="HS256")
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_inactive_user_cannot_use_existing_tokens(client, tokens, db_session):
    user = db_session.query(User).filter_by(email="failure@example.com").one()
    user.is_active = False
    db_session.commit()
    assert client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"}
    ).status_code == 401
    assert client.post(
        "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    ).status_code == 401


@pytest.mark.parametrize("role, expected", [(UserRole.user, 403), (UserRole.admin, 200), (UserRole.superadmin, 200)])
def test_admin_access_uses_current_database_role(client, tokens, db_session, role, expected):
    user = db_session.query(User).filter_by(email="failure@example.com").one()
    user.role = role
    db_session.commit()
    response = client.get(
        "/api/v1/admin/users", headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )
    assert response.status_code == expected


def test_login_rate_limit_returns_retry_after(client, registered_user):
    body = {"email": registered_user["email"], "password": "Wrong1pass"}
    for _ in range(5):
        assert client.post("/api/v1/auth/login", json=body).status_code == 401
    response = client.post("/api/v1/auth/login", json=body)
    assert response.status_code == 429
    assert int(response.headers["Retry-After"]) > 0


def test_forwarded_header_cannot_bypass_login_rate_limit(client, registered_user):
    body = {"email": registered_user["email"], "password": "Wrong1pass"}
    for attempt in range(5):
        response = client.post(
            "/api/v1/auth/login", json=body, headers={"X-Forwarded-For": f"198.51.100.{attempt}"}
        )
        assert response.status_code == 401
    response = client.post(
        "/api/v1/auth/login", json=body, headers={"X-Forwarded-For": "198.51.100.99"}
    )
    assert response.status_code == 429


def test_registration_rejects_password_beyond_bcrypt_byte_limit(client):
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "long@example.com", "password": "Secure1" + "x" * 72, "username": "long"},
    )
    assert response.status_code == 400


def test_registration_cannot_assign_admin_role(client):
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "role@example.com", "password": "Secure1pass", "username": "role", "role": "superadmin"},
    )
    assert response.status_code == 422


def test_http_audit_is_written_to_test_database(client, db_session):
    assert client.get("/api/v1/auth/me").status_code == 401
    record = db_session.query(AuditLog).filter_by(action="auth.http").one()
    assert record.details["path"] == "/api/v1/auth/me"
    assert record.details["status_code"] == 401
