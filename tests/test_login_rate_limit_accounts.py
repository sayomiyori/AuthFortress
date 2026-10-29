import hashlib
import hmac


def _register(client, email: str) -> None:
    response = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "Secure1pass", "username": email.split("@")[0]},
    )
    assert response.status_code == 200


def test_login_limit_is_per_account_and_hashes_redis_keys(client, redis_client, test_settings):
    first = "limit-a@example.com"
    second = "limit-b@example.com"
    _register(client, first)
    _register(client, second)
    wrong = {"email": first, "password": "Wrong1pass"}
    for _ in range(5):
        assert client.post("/api/v1/auth/login", json=wrong).status_code == 401
    assert client.post("/api/v1/auth/login", json=wrong).status_code == 429
    assert (
        client.post(
            "/api/v1/auth/login",
            json={"email": "LIMIT-A@Example.com", "password": "Wrong1pass"},
        ).status_code
        == 429
    )
    assert (
        client.post(
            "/api/v1/auth/login",
            json={"email": second, "password": "Wrong1pass"},
        ).status_code
        == 401
    )
    keys = [str(key) for key in redis_client.scan_iter("rl:login:account:*")]
    expected = hmac.new(
        test_settings.jwt_secret_key.encode(),
        first.encode(),
        hashlib.sha256,
    ).hexdigest()
    assert f"rl:login:account:{expected}" in keys
    assert all("example.com" not in key for key in keys)
