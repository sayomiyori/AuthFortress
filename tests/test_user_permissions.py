import jwt
import pytest
from app.models.audit import AuditLog
from app.models.session import UserSession
from app.models.user import User, UserRole
from app.services.auth_service import create_session_and_tokens


@pytest.fixture
def actors(db_session, test_settings, redis_client):
    result = {}
    for role in UserRole:
        user = User(email=f"{role.value}@example.com", username=role.value, role=role)
        db_session.add(user)
        db_session.commit()
        access, _, _ = create_session_and_tokens(
            db_session, test_settings, redis_client, user=user, device_info=None, ip=None
        )
        result[role] = (user, {"Authorization": f"Bearer {access}"})
    return result


def test_users_api_serializes_uuid_ids(client, actors):
    user, headers = actors[UserRole.user]
    response = client.get("/api/v1/users/me", headers=headers)
    assert response.status_code == 200
    assert response.json()["id"] == str(user.id)


@pytest.mark.parametrize(
    "body", [{"password": "Takeover1pass"}, {"is_active": False}, {"email": "takeover@example.com"}]
)
def test_admin_cannot_mutate_superadmin(client, actors, body):
    target, _ = actors[UserRole.superadmin]
    _, headers = actors[UserRole.admin]
    response = client.patch(f"/api/v1/users/{target.id}", json=body, headers=headers)
    assert response.status_code == 403


def test_admin_cannot_block_superadmin(client, actors):
    target, _ = actors[UserRole.superadmin]
    _, headers = actors[UserRole.admin]
    response = client.patch(f"/api/v1/admin/users/{target.id}/block", json={"blocked": True}, headers=headers)
    assert response.status_code == 403


def test_admin_cannot_mutate_peer_admin(client, actors, db_session):
    peer = User(email="peer-admin@example.com", username="peer", role=UserRole.admin)
    db_session.add(peer)
    db_session.commit()
    _, headers = actors[UserRole.admin]
    response = client.patch(f"/api/v1/users/{peer.id}", json={"password": "Takeover1pass"}, headers=headers)
    assert response.status_code == 403
    response = client.patch(f"/api/v1/admin/users/{peer.id}/block", json={"blocked": True}, headers=headers)
    assert response.status_code == 403


def test_password_reset_revokes_target_sessions_and_audits(
    client, actors, db_session, test_settings, redis_client
):
    target, _ = actors[UserRole.user]
    access, refresh, _ = create_session_and_tokens(
        db_session, test_settings, redis_client, user=target, device_info=None, ip=None
    )
    _, headers = actors[UserRole.admin]
    response = client.patch(
        f"/api/v1/users/{target.id}", json={"password": "Reset1pass"}, headers=headers
    )
    assert response.status_code == 200
    assert (
        client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {access}"}).status_code
        == 401
    )
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": refresh}).status_code == 401
    audit = db_session.query(AuditLog).filter_by(action="user_updated").one()
    assert audit.details["target_user_id"] == str(target.id)
    assert audit.details["sessions_revoked"] >= 1


@pytest.mark.parametrize("actor_role, expected", [(UserRole.admin, 403), (UserRole.superadmin, 200)])
def test_role_change_requires_superadmin(client, actors, actor_role, expected):
    target, _ = actors[UserRole.user]
    _, headers = actors[actor_role]
    response = client.patch(f"/api/v1/users/{target.id}", json={"role": "admin"}, headers=headers)
    assert response.status_code == expected


def test_superadmin_can_create_admin(client, actors):
    _, headers = actors[UserRole.superadmin]
    response = client.post(
        "/api/v1/users",
        json={"email": "newadmin@example.com", "password": "Secure1pass", "username": "new", "role": "admin"},
        headers=headers,
    )
    assert response.status_code == 201
    assert response.json()["role"] == "admin"


def test_admin_cannot_revoke_superadmin_session(client, actors, test_settings):
    _, target_headers = actors[UserRole.superadmin]
    _, headers = actors[UserRole.admin]
    token = target_headers["Authorization"].removeprefix("Bearer ")
    session_id = jwt.decode(token, test_settings.jwt_secret_key, algorithms=["HS256"])["sid"]
    response = client.delete(f"/api/v1/admin/sessions/{session_id}", headers=headers)
    assert response.status_code == 403
    assert client.get("/api/v1/auth/me", headers=target_headers).status_code == 200


def _register_and_login(client, email: str) -> dict[str, str]:
    credentials = {"email": email, "password": "Secure1pass", "username": email.split("@")[0]}
    assert client.post("/api/v1/auth/register", json=credentials).status_code == 200
    login = client.post(
        "/api/v1/auth/login",
        json={"email": credentials["email"], "password": credentials["password"]},
    )
    assert login.status_code == 200
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def test_block_revokes_sessions_and_unblock_does_not_revive(client, actors, db_session):
    headers = _register_and_login(client, "block-revoke@example.com")
    target = db_session.query(User).filter_by(email="block-revoke@example.com").one()
    _, admin_headers = actors[UserRole.admin]

    blocked = client.patch(
        f"/api/v1/admin/users/{target.id}/block",
        json={"blocked": True},
        headers=admin_headers,
    )
    assert blocked.status_code == 200
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401

    unblocked = client.patch(
        f"/api/v1/admin/users/{target.id}/block",
        json={"blocked": False},
        headers=admin_headers,
    )
    assert unblocked.status_code == 200
    # The pre-block token must not come back to life when the account does.
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401

    fresh = client.post(
        "/api/v1/auth/login",
        json={"email": "block-revoke@example.com", "password": "Secure1pass"},
    )
    assert fresh.status_code == 200
    fresh_headers = {"Authorization": f"Bearer {fresh.json()['access_token']}"}
    assert client.get("/api/v1/auth/me", headers=fresh_headers).status_code == 200


def test_admin_deactivation_patch_revokes_sessions_and_reactivation_does_not_revive(
    client, actors, db_session
):
    headers = _register_and_login(client, "deactivate-revoke@example.com")
    target = db_session.query(User).filter_by(email="deactivate-revoke@example.com").one()
    _, admin_headers = actors[UserRole.admin]

    deactivated = client.patch(
        f"/api/v1/users/{target.id}",
        json={"is_active": False},
        headers=admin_headers,
    )
    assert deactivated.status_code == 200
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401

    reactivated = client.patch(
        f"/api/v1/users/{target.id}",
        json={"is_active": True},
        headers=admin_headers,
    )
    assert reactivated.status_code == 200
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401

    audits = db_session.query(AuditLog).filter_by(action="user_updated").all()
    assert any(audit.details["sessions_revoked"] >= 1 for audit in audits)


def _legacy_inactive_session(
    client, db_session, redis_client, email: str
) -> tuple[User, dict[str, str], UserSession]:
    """Seed an inactive account that still holds a live, unrevoked session.

    This is the state an account could reach before the block endpoint revoked
    sessions, or after an out-of-band deactivation: no session row or Redis key
    was cleared, so flipping ``is_active`` back to true would revive it.
    """
    headers = _register_and_login(client, email)
    target = db_session.query(User).filter_by(email=email).one()
    db_session.query(User).filter(User.id == target.id).update({"is_active": False})
    db_session.commit()
    session = db_session.query(UserSession).filter_by(user_id=target.id).one()
    assert session.revoked_at is None
    assert redis_client.exists(f"session:{session.id}")
    # Inactive already rejects the token; only revocation keeps it dead later.
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
    return target, headers, session


def test_unblocking_account_inactive_before_block_revokes_its_stale_session(
    client, actors, db_session, redis_client
):
    target, headers, session = _legacy_inactive_session(
        client, db_session, redis_client, "legacy-unblock@example.com"
    )
    _, admin_headers = actors[UserRole.admin]

    unblocked = client.patch(
        f"/api/v1/admin/users/{target.id}/block",
        json={"blocked": False},
        headers=admin_headers,
    )
    assert unblocked.status_code == 200

    db_session.refresh(session)
    assert session.revoked_at is not None
    assert not redis_client.exists(f"session:{session.id}")
    # is_active is true again, so only the revocation keeps the token dead.
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401


def test_reactivating_account_inactive_before_patch_revokes_its_stale_session(
    client, actors, db_session, redis_client
):
    target, headers, session = _legacy_inactive_session(
        client, db_session, redis_client, "legacy-reactivate@example.com"
    )
    _, admin_headers = actors[UserRole.admin]

    reactivated = client.patch(
        f"/api/v1/users/{target.id}",
        json={"is_active": True},
        headers=admin_headers,
    )
    assert reactivated.status_code == 200

    db_session.refresh(session)
    assert session.revoked_at is not None
    assert not redis_client.exists(f"session:{session.id}")
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401


def test_active_to_active_state_calls_do_not_revoke(
    client, actors, db_session, test_settings, redis_client
):
    target, _ = actors[UserRole.user]
    access, _, _ = create_session_and_tokens(
        db_session, test_settings, redis_client, user=target, device_info=None, ip=None
    )
    target_headers = {"Authorization": f"Bearer {access}"}
    _, admin_headers = actors[UserRole.admin]

    unblocked = client.patch(
        f"/api/v1/admin/users/{target.id}/block",
        json={"blocked": False},
        headers=admin_headers,
    )
    assert unblocked.status_code == 200
    assert client.get("/api/v1/auth/me", headers=target_headers).status_code == 200

    reactivated = client.patch(
        f"/api/v1/users/{target.id}",
        json={"is_active": True},
        headers=admin_headers,
    )
    assert reactivated.status_code == 200
    assert client.get("/api/v1/auth/me", headers=target_headers).status_code == 200
