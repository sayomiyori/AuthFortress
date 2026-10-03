import pyotp
import pytest
from app.models.user import User


@pytest.fixture
def twofa_user(client):
    credentials = {"email": "twofa@example.com", "password": "Secure1pass", "username": "twofa"}
    assert client.post("/api/v1/auth/register", json=credentials).status_code == 200
    login = client.post("/api/v1/auth/login", json=credentials).json()
    headers = {"Authorization": f"Bearer {login['access_token']}"}
    setup = client.post("/api/v1/auth/2fa/setup", headers=headers)
    assert setup.status_code == 200
    secret = setup.json()["secret"]
    verification = client.post(
        "/api/v1/auth/2fa/verify", json={"code": pyotp.TOTP(secret).now()}, headers=headers
    )
    assert verification.status_code == 200
    return credentials, headers, secret, verification.json()["backup_codes"]


def test_enabled_twofa_cannot_be_reset_with_access_token(client, twofa_user, db_session):
    _, headers, _, _ = twofa_user
    response = client.post("/api/v1/auth/2fa/setup", headers=headers)
    assert response.status_code == 409
    assert db_session.query(User).filter_by(email="twofa@example.com").one().totp_enabled


def test_enabled_twofa_cannot_regenerate_backup_codes(client, twofa_user):
    _, headers, secret, _ = twofa_user
    response = client.post(
        "/api/v1/auth/2fa/verify", json={"code": pyotp.TOTP(secret).now()}, headers=headers
    )
    assert response.status_code == 409


def test_twofa_login_requires_code_and_temp_token_is_single_use(client, twofa_user):
    credentials, _, _, backup_codes = twofa_user
    response = client.post("/api/v1/auth/login", json=credentials)
    assert response.status_code == 200
    assert response.json()["requires_2fa"]
    assert "access_token" not in response.json()
    temp_token = response.json()["temp_token"]
    invalid = client.post("/api/v1/auth/login/2fa", json={"temp_token": temp_token, "code": "invalid"})
    assert invalid.status_code == 401
    success = client.post(
        "/api/v1/auth/login/2fa", json={"temp_token": temp_token, "code": backup_codes[0]}
    )
    assert success.status_code == 200
    headers = {"Authorization": f"Bearer {success.json()['access_token']}"}
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200
    replay = client.post(
        "/api/v1/auth/login/2fa", json={"temp_token": temp_token, "code": backup_codes[1]}
    )
    assert replay.status_code == 401


def test_twofa_backup_code_cannot_be_used_twice(client, twofa_user):
    credentials, _, _, backup_codes = twofa_user
    for expected in (200, 401):
        challenge = client.post("/api/v1/auth/login", json=credentials).json()["temp_token"]
        response = client.post(
            "/api/v1/auth/login/2fa", json={"temp_token": challenge, "code": backup_codes[0]}
        )
        assert response.status_code == expected


def test_totp_replay_cannot_bypass_guard_with_whitespace(client, twofa_user):
    credentials, _, secret, _ = twofa_user
    code = pyotp.TOTP(secret).now()
    for supplied, expected in ((code, 200), (f" {code} ", 401)):
        challenge = client.post("/api/v1/auth/login", json=credentials).json()["temp_token"]
        response = client.post(
            "/api/v1/auth/login/2fa", json={"temp_token": challenge, "code": supplied}
        )
        assert response.status_code == expected


def test_twofa_login_is_rate_limited(client, twofa_user):
    credentials, _, _, _ = twofa_user
    challenge = client.post("/api/v1/auth/login", json=credentials).json()["temp_token"]
    for _ in range(5):
        response = client.post("/api/v1/auth/login/2fa", json={"temp_token": challenge, "code": "invalid"})
        assert response.status_code == 401
    response = client.post("/api/v1/auth/login/2fa", json={"temp_token": challenge, "code": "invalid"})
    assert response.status_code == 429
    assert int(response.headers["Retry-After"]) > 0


def test_twofa_disable_requires_valid_code(client, twofa_user):
    credentials, headers, _, backup_codes = twofa_user
    assert client.post(
        "/api/v1/auth/2fa/disable", json={"code": "invalid"}, headers=headers
    ).status_code == 400
    assert client.post(
        "/api/v1/auth/2fa/disable", json={"code": backup_codes[0]}, headers=headers
    ).status_code == 204
    response = client.post("/api/v1/auth/login", json=credentials)
    assert response.status_code == 200 and "access_token" in response.json()
