import uuid

import jwt


def test_refresh_token_subject_mismatch_is_rejected(client, test_settings):
    credentials = {
        "email": "refresh@example.com",
        "password": "Secure1pass",
        "username": "refresh",
    }
    assert client.post("/api/v1/auth/register", json=credentials).status_code == 200
    login = client.post(
        "/api/v1/auth/login",
        json={"email": credentials["email"], "password": credentials["password"]},
    )
    assert login.status_code == 200
    refresh = login.json()["refresh_token"]
    payload = jwt.decode(refresh, test_settings.jwt_secret_key, algorithms=["HS256"])
    payload["sub"] = str(uuid.uuid4())
    forged = jwt.encode(payload, test_settings.jwt_secret_key, algorithm="HS256")
    assert (
        client.post("/api/v1/auth/refresh", json={"refresh_token": forged}).status_code == 401
    )
    assert (
        client.post("/api/v1/auth/refresh", json={"refresh_token": refresh}).status_code == 200
    )


def test_refresh_token_without_subject_is_rejected(client, test_settings):
    credentials = {
        "email": "refresh-nosub@example.com",
        "password": "Secure1pass",
        "username": "refresh-nosub",
    }
    assert client.post("/api/v1/auth/register", json=credentials).status_code == 200
    login = client.post(
        "/api/v1/auth/login",
        json={"email": credentials["email"], "password": credentials["password"]},
    )
    refresh = login.json()["refresh_token"]
    payload = jwt.decode(refresh, test_settings.jwt_secret_key, algorithms=["HS256"])
    del payload["sub"]
    forged = jwt.encode(payload, test_settings.jwt_secret_key, algorithm="HS256")
    assert (
        client.post("/api/v1/auth/refresh", json={"refresh_token": forged}).status_code == 401
    )


def test_register_login_me_refresh_old_refresh_fails_logout_me_fails(client):
    r = client.post(
        "/api/v1/auth/register",
        json={
            "email": "user@example.com",
            "password": "Secure1pass",
            "username": "tester",
        },
    )
    assert r.status_code == 200
    assert r.json()["email"] == "user@example.com"
    user_id = r.json()["user_id"]

    r = client.post(
        "/api/v1/auth/login",
        json={"email": "user@example.com", "password": "Secure1pass"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer"
    access = body["access_token"]
    refresh_a = body["refresh_token"]

    r = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {access}"})
    assert r.status_code == 200
    me = r.json()
    assert me["id"] == user_id
    assert me["email"] == "user@example.com"

    r = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_a})
    assert r.status_code == 200
    access2 = r.json()["access_token"]
    refresh_b = r.json()["refresh_token"]

    r = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_a})
    assert r.status_code == 401

    r = client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {access2}"},
    )
    assert r.status_code == 204

    r = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {access2}"})
    assert r.status_code == 401

    r = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_b})
    assert r.status_code == 401
