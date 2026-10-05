from uuid import uuid4

import pytest
from app.api.internal import require_service_key
from app.models.tenant import Tenant
from app.models.user import User
from app.services.auth_service import create_session_and_tokens
from fastapi import HTTPException
from pydantic import SecretStr


@pytest.fixture
def service_headers(test_settings):
    key = SecretStr("internal-test-only-service-key-32-bytes-long")
    test_settings.authfortress_webhook_service_key = key
    return {"X-Service-Key": key.get_secret_value()}


@pytest.fixture
def tenant(db_session):
    user = User(email="internal-tenant@example.com", username="internal-owner")
    db_session.add(user)
    db_session.flush()
    row = Tenant(name="Internal tenant", created_by=user.id)
    db_session.add(row)
    db_session.commit()
    return row


def test_active_status_is_minimal_and_rechecks_database(client, tenant, service_headers, db_session):
    path = f"/internal/v1/tenants/{tenant.id}/status"
    response = client.get(path, headers=service_headers)
    assert response.status_code == 200
    assert response.json() == {"tenant_id": str(tenant.id), "is_active": True}
    tenant.is_active = False
    db_session.commit()
    response = client.get(path, headers=service_headers)
    assert response.status_code == 404
    assert response.json() == {"detail": "Tenant not found"}


def test_missing_tenant_is_hidden(client, service_headers):
    response = client.get(f"/internal/v1/tenants/{uuid4()}/status", headers=service_headers)
    assert response.status_code == 404
    assert response.json() == {"detail": "Tenant not found"}


@pytest.mark.parametrize("key", [None, "", "wrong", "x" * 257])
def test_missing_or_invalid_service_key_is_rejected(client, tenant, service_headers, key):
    response = client.get(
        f"/internal/v1/tenants/{tenant.id}/status", headers={} if key is None else {"X-Service-Key": key}
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid service key"}


def test_non_ascii_service_key_is_rejected(test_settings, service_headers):
    # HTTP clients often reject Unicode headers before sending; exercise the dependency too.
    with pytest.raises(HTTPException) as caught:
        require_service_key(service_key="é" * 32, settings=test_settings)
    assert caught.value.status_code == 401
    assert caught.value.detail == "Invalid service key"


def test_unconfigured_endpoint_is_unavailable(client, tenant):
    response = client.get(f"/internal/v1/tenants/{tenant.id}/status")
    assert response.status_code == 503
    assert response.json() == {"detail": "Service unavailable"}


def test_user_jwt_cannot_replace_service_key(client, tenant, service_headers, db_session, test_settings, redis_client):
    user = db_session.get(User, tenant.created_by)
    access, _, _ = create_session_and_tokens(
        db_session, test_settings, redis_client, user=user, device_info=None, ip=None
    )
    assert client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {access}"}).status_code == 200
    response = client.get(f"/internal/v1/tenants/{tenant.id}/status", headers={"Authorization": f"Bearer {access}"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid service key"}


def test_service_key_cannot_access_user_api(client, service_headers):
    assert client.get("/api/v1/users/me", headers=service_headers).status_code == 401


def test_invalid_uuid_does_not_echo_service_key(client, service_headers):
    response = client.get("/internal/v1/tenants/not-a-uuid/status", headers=service_headers)
    assert response.status_code == 422
    assert service_headers["X-Service-Key"] not in response.text
