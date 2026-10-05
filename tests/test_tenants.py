from uuid import uuid4

import pytest
from app.models.audit import AuditLog
from app.models.tenant import Tenant, TenantMembership, TenantRole
from app.models.user import User, UserRole
from app.services.auth_service import create_session_and_tokens
from app.services.tenant_service import create_tenant
from sqlalchemy import event, func, select
from sqlalchemy.exc import IntegrityError


@pytest.fixture
def actors(db_session, test_settings, redis_client):
    result = {}
    for role in UserRole:
        user = User(email=f"tenant-{role.value}@example.com", username=role.value, role=role)
        db_session.add(user)
        db_session.commit()
        access, refresh, _ = create_session_and_tokens(
            db_session, test_settings, redis_client, user=user, device_info=None, ip=None
        )
        result[role] = (user, {"Authorization": f"Bearer {access}"}, refresh)
    return result


@pytest.fixture
def owned(client, actors):
    owner, headers, _ = actors[UserRole.user]
    response = client.post("/api/v1/tenants", json={"name": " Example team "}, headers=headers)
    assert response.status_code == 201
    return owner, headers, response.json()


def test_creator_can_create_list_read_and_authorize_tenant(client, owned, db_session):
    owner, headers, tenant = owned
    assert tenant["name"] == "Example team" and tenant["role"] == "owner"
    assert tenant["created_at"].endswith("Z")
    assert client.get("/api/v1/tenants", headers=headers).json() == [tenant]
    assert client.get("/api/v1/tenants/" + tenant["id"], headers=headers).json() == tenant
    audit = db_session.scalar(select(AuditLog).where(AuditLog.action == "tenant.created"))
    assert audit.user_id == owner.id and audit.details == {"tenant_id": tenant["id"]}


@pytest.mark.parametrize("permission", ["tenant.read", "bot.read", "ai.read", "tenant.manage",
                                        "bot.manage", "ai.configure"])
def test_owner_can_authorize_every_declared_permission(client, owned, permission):
    owner, headers, tenant = owned
    response = client.post(f"/api/v1/tenants/{tenant['id']}/authorize",
                           json={"permission": permission}, headers=headers)
    assert response.status_code == 200
    assert response.json() == {"user_id": str(owner.id), "tenant_id": tenant["id"],
                               "role": "owner", "permission": permission, "allowed": True}


@pytest.mark.parametrize("role", [UserRole.admin, UserRole.superadmin])
def test_global_role_does_not_grant_tenant_access(client, owned, actors, role):
    _, _, tenant = owned
    _, headers, _ = actors[role]
    assert client.get("/api/v1/tenants", headers=headers).json() == []
    for tenant_id in [tenant["id"], str(uuid4())]:
        response = client.get(f"/api/v1/tenants/{tenant_id}", headers=headers)
        assert response.status_code == 404 and response.json() == {"detail": "Tenant not found"}
        assert client.post(f"/api/v1/tenants/{tenant_id}/authorize",
                           json={"permission": "tenant.read"}, headers=headers).status_code == 404
    own = client.post("/api/v1/tenants", json={"name": "Other tenant"}, headers=headers)
    assert own.status_code == 201
    assert [item["id"] for item in client.get("/api/v1/tenants", headers=headers).json()] == [own.json()["id"]]


@pytest.mark.parametrize("permission, expected", [("tenant.read", 200), ("bot.read", 200), ("ai.read", 200),
                                                  ("tenant.manage", 403), ("bot.manage", 403), ("ai.configure", 403)])
def test_member_permissions_are_limited_even_for_superadmin(client, owned, actors, db_session, permission, expected):
    _, _, tenant = owned
    member, headers, _ = actors[UserRole.superadmin]
    db_session.add(TenantMembership(tenant_id=tenant["id"], user_id=member.id, role=TenantRole.member))
    db_session.commit()
    assert client.get(f"/api/v1/tenants/{tenant['id']}", headers=headers).json()["role"] == "member"
    response = client.post(f"/api/v1/tenants/{tenant['id']}/authorize",
                           json={"permission": permission}, headers=headers)
    assert response.status_code == expected
    if expected == 200:
        assert response.json()["role"] == "member" and response.json()["user_id"] == str(member.id)


@pytest.mark.parametrize("inactive", ["tenant", "membership"])
def test_inactive_context_is_hidden(client, owned, db_session, inactive):
    _, headers, tenant = owned
    model = Tenant if inactive == "tenant" else TenantMembership
    row = db_session.scalar(select(model))
    row.is_active = False
    db_session.commit()
    assert client.get("/api/v1/tenants", headers=headers).json() == []
    assert client.get(f"/api/v1/tenants/{tenant['id']}", headers=headers).status_code == 404
    assert client.post(f"/api/v1/tenants/{tenant['id']}/authorize",
                       json={"permission": "tenant.manage"}, headers=headers).status_code == 404


@pytest.mark.parametrize("body", [{}, {"name": " "}, {"name": "x" * 129}, {"name": None}, {"name": 10},
                                   {"name": "ok", "created_by": str(uuid4())},
                                   {"name": "ok", "role": "owner"}])
def test_invalid_creation_does_not_write_tenants(client, actors, db_session, body):
    _, headers, _ = actors[UserRole.user]
    assert client.post("/api/v1/tenants", json=body, headers=headers).status_code == 422
    assert db_session.scalar(select(func.count()).select_from(Tenant)) == 0
    assert db_session.scalar(select(func.count()).select_from(TenantMembership)) == 0


@pytest.mark.parametrize("query", ["offset=-1", "limit=0", "limit=101", "offset=abc"])
def test_invalid_pagination_is_rejected(client, actors, query):
    _, headers, _ = actors[UserRole.user]
    assert client.get(f"/api/v1/tenants?{query}", headers=headers).status_code == 422


def test_multiple_tenants_use_stable_pagination(client, owned, db_session):
    owner, headers, first = owned
    second = client.post("/api/v1/tenants", json={"name": "Second"}, headers=headers).json()
    rows = list(db_session.scalars(select(Tenant).where(Tenant.created_by == owner.id)))
    for row in rows:
        row.created_at = rows[0].created_at
    db_session.commit()
    expected = sorted([first["id"], second["id"]])
    assert [item["id"] for item in client.get("/api/v1/tenants", headers=headers).json()] == expected
    assert client.get("/api/v1/tenants?offset=1&limit=1", headers=headers).json()[0]["id"] == expected[1]
    assert client.get("/api/v1/tenants?offset=2", headers=headers).json() == []


def test_user_can_access_two_fixture_memberships_without_access_to_other_tenants(client, actors, db_session):
    member, headers, _ = actors[UserRole.user]
    creator, _, _ = actors[UserRole.admin]
    tenants = [Tenant(name=f"Fixture tenant {index}", created_by=creator.id) for index in range(3)]
    db_session.add_all(tenants)
    db_session.flush()
    db_session.add_all([
        TenantMembership(tenant_id=tenant.id, user_id=creator.id, role=TenantRole.owner) for tenant in tenants
    ])
    memberships = [TenantMembership(tenant_id=tenant.id, user_id=member.id, role=TenantRole.member)
                   for tenant in tenants[:2]]
    db_session.add_all(memberships)
    db_session.commit()

    response = client.get("/api/v1/tenants", headers=headers)
    assert response.status_code == 200
    assert {item["id"] for item in response.json()} == {str(tenant.id) for tenant in tenants[:2]}
    for tenant in tenants[:2]:
        path = f"/api/v1/tenants/{tenant.id}"
        assert client.get(path, headers=headers).json()["role"] == "member"
        assert client.post(path + "/authorize", json={"permission": "tenant.read"}, headers=headers).status_code == 200
        assert client.post(
            path + "/authorize", json={"permission": "tenant.manage"}, headers=headers
        ).status_code == 403
    hidden_path = f"/api/v1/tenants/{tenants[2].id}"
    assert client.get(hidden_path, headers=headers).status_code == 404
    assert client.post(
        hidden_path + "/authorize", json={"permission": "tenant.read"}, headers=headers
    ).status_code == 404

    memberships[0].is_active = False
    db_session.commit()
    assert [item["id"] for item in client.get("/api/v1/tenants", headers=headers).json()] == [str(tenants[1].id)]
    assert client.get(f"/api/v1/tenants/{tenants[0].id}", headers=headers).status_code == 404
    assert client.get(f"/api/v1/tenants/{tenants[1].id}", headers=headers).status_code == 200


@pytest.mark.parametrize("body", [{"permission": "unknown"}, {},
                                   {"permission": "tenant.manage", "user_id": str(uuid4())},
                                   {"permission": "tenant.read", "allowed": True}])
def test_authorization_rejects_unknown_fields_and_permissions(client, owned, body):
    _, headers, tenant = owned
    assert client.post(f"/api/v1/tenants/{tenant['id']}/authorize", json=body, headers=headers).status_code == 422
    assert client.get("/api/v1/tenants/not-a-uuid", headers=headers).status_code == 422


@pytest.mark.parametrize("credential", ["missing", "malformed", "refresh", "revoked", "inactive"])
def test_all_tenant_routes_require_active_access_session(client, owned, actors, db_session, credential):
    owner, headers, tenant = owned
    if credential == "missing":
        headers = {}
    elif credential == "malformed":
        headers = {"Authorization": "Bearer malformed"}
    elif credential == "refresh":
        headers = {"Authorization": f"Bearer {actors[UserRole.user][2]}"}
    elif credential == "revoked":
        assert client.post("/api/v1/auth/logout", headers=headers).status_code == 204
    else:
        owner.is_active = False
        db_session.commit()
    assert client.get("/api/v1/tenants", headers=headers).status_code == 401
    assert client.post("/api/v1/tenants", json={"name": "Denied"}, headers=headers).status_code == 401
    assert client.get(f"/api/v1/tenants/{tenant['id']}", headers=headers).status_code == 401
    assert client.post(f"/api/v1/tenants/{tenant['id']}/authorize",
                       json={"permission": "tenant.read"}, headers=headers).status_code == 401


def test_unique_membership_is_enforced_by_postgresql(owned, db_session):
    owner, _, tenant = owned
    with pytest.raises(IntegrityError), db_session.begin_nested():
        db_session.add(TenantMembership(tenant_id=tenant["id"], user_id=owner.id, role=TenantRole.member))
        db_session.flush()
    assert db_session.scalar(select(func.count()).select_from(TenantMembership)) == 1


def test_membership_constraint_failure_rolls_back_tenant_and_audit(actors, db_session):
    owner, _, _ = actors[UserRole.user]

    def invalidate_foreign_key(mapper, connection, membership):
        membership.user_id = uuid4()

    event.listen(TenantMembership, "before_insert", invalidate_foreign_key)
    try:
        with pytest.raises(IntegrityError):
            create_tenant(db_session, owner.id, "Must roll back")
    finally:
        event.remove(TenantMembership, "before_insert", invalidate_foreign_key)
    assert db_session.scalar(select(func.count()).select_from(Tenant)) == 0
    assert db_session.scalar(select(func.count()).select_from(TenantMembership)) == 0
    assert db_session.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action == "tenant.created")) == 0


@pytest.mark.parametrize("endpoint", ["/api/v1/users", "/api/v1/admin/users"])
def test_deleting_creator_is_conflict_but_unrelated_user_can_be_deleted(client, owned, actors, endpoint):
    owner, owner_headers, tenant = owned
    other, _, _ = actors[UserRole.admin]
    _, admin_headers, _ = actors[UserRole.superadmin]
    response = client.delete(f"{endpoint}/{owner.id}", headers=admin_headers)
    assert response.status_code == 409 and response.json() == {"detail": "User owns a tenant"}
    assert client.get(f"/api/v1/tenants/{tenant['id']}", headers=owner_headers).status_code == 200
    assert client.delete(f"{endpoint}/{other.id}", headers=admin_headers).status_code == 204
