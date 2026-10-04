"""Verify backup-code single use through independent PostgreSQL transactions."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

import httpx
from app.config import Settings
from app.models.user import User
from app.services.auth_service import create_session_and_tokens
from app.services.jwt_service import create_temp_2fa_token
from app.services.oauth.token_crypto import encrypt_token
from app.services.totp_service import generate_totp_secret, hash_backup_code
from redis import Redis
from sqlalchemy import create_engine
from sqlalchemy.orm import Session


def verify() -> None:
    settings = Settings(
        _env_file=None,
        DATABASE_URL="postgresql+psycopg2://authfortress_test:local-test-only@localhost:55432/authfortress_test",
        JWT_SECRET_KEY="isolated-local-test-signing-key-32-characters",
    )
    engine = create_engine(settings.database_url)
    redis_client = Redis.from_url("redis://localhost:56379/0", decode_responses=True)
    try:
        for routes in (("login", "login"), ("login", "disable"), ("disable", "disable")):
            code = uuid4().hex
            with Session(engine) as db:
                user = User(
                    email=f"twofa-race-{uuid4().hex}@example.com", username="twofa-race",
                    totp_enabled=True, totp_secret_encrypted=encrypt_token(settings, generate_totp_secret()),
                    backup_codes_hashed=[hash_backup_code(code)],
                )
                db.add(user)
                db.commit()
                access, _, _ = create_session_and_tokens(
                    db, settings, redis_client, user=user, device_info=None, ip=None
                )
                challenges = [create_temp_2fa_token(settings, redis_client, user_id=str(user.id)) for _ in routes]
            start = Barrier(2)

            def attempt(index: int) -> int:
                with httpx.Client(base_url="http://127.0.0.1:38080", timeout=15) as client:
                    start.wait(timeout=10)
                    if routes[index] == "login":
                        response = client.post(
                            "/api/v1/auth/login/2fa", json={"temp_token": challenges[index], "code": code}
                        )
                    else:
                        response = client.post(
                            "/api/v1/auth/2fa/disable", json={"code": code},
                            headers={"Authorization": f"Bearer {access}"},
                        )
                    return response.status_code

            with ThreadPoolExecutor(max_workers=2) as pool:
                statuses = list(pool.map(attempt, range(2)))
            assert sum(status in (200, 204) for status in statuses) == 1, (routes, statuses)
            assert all(status in (200, 204, 400, 401) for status in statuses), (routes, statuses)
            print(f"PASS: backup-code race {'/'.join(routes)}: one success, one rejection")
    finally:
        redis_client.close()
        engine.dispose()


if __name__ == "__main__":
    verify()
