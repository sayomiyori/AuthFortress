"""Verify the built service through HTTP without printing credentials or tokens."""

import argparse
import uuid

import httpx


def verify(base_url: str) -> None:
    email = f"smoke-{uuid.uuid4().hex}@example.com"
    password = f"Smoke1-{uuid.uuid4().hex}"
    with httpx.Client(base_url=base_url, timeout=15) as client:
        assert client.get("/health").status_code == 200
        registration = client.post(
            "/api/v1/auth/register", json={"email": email, "password": password, "username": "smoke"}
        )
        assert registration.status_code == 200, "registration failed"
        user_id = registration.json()["user_id"]
        assert client.get("/api/v1/auth/me").status_code == 401
        assert client.get(
            "/api/v1/auth/me", headers={"Authorization": "Bearer malformed"}
        ).status_code == 401
        assert client.post(
            "/api/v1/auth/login", json={"email": email, "password": "Wrong1pass"}
        ).status_code == 401
        login = client.post("/api/v1/auth/login", json={"email": email, "password": password})
        assert login.status_code == 200, "login failed"
        tokens = login.json()
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}
        me = client.get("/api/v1/auth/me", headers=headers)
        assert me.status_code == 200 and me.json()["id"] == user_id
        assert client.get("/api/v1/admin/users", headers=headers).status_code == 403
        rotated = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
        assert rotated.status_code == 200, "refresh failed"
        assert client.post(
            "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
        ).status_code == 401
        headers = {"Authorization": f"Bearer {rotated.json()['access_token']}"}
        assert client.get("/api/v1/auth/me", headers=headers).status_code == 200
        assert client.post("/api/v1/auth/logout", headers=headers).status_code == 204
        assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
        assert client.post(
            "/api/v1/auth/refresh", json={"refresh_token": rotated.json()["refresh_token"]}
        ).status_code == 401
        metrics = client.get("/metrics")
        assert metrics.status_code == 200 and "auth_login_total" in metrics.text
    print(
        "PASS: health, registration, login, protected endpoint, auth failures, "
        "RBAC, rotation, replay, logout, metrics"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:38080")
    arguments = parser.parse_args()
    verify(arguments.base_url)
