import jwt
import pytest
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
