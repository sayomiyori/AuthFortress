"""Check single-use refresh rotation through concurrent HTTP requests."""

import argparse
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

import httpx
from app.config import Settings
from app.models.user import User
from app.services.auth_service import create_session_and_tokens, refresh_tokens
from redis import Redis
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session


def verify_database_race() -> None:
    database_url = os.environ.get("TEST_DATABASE_URL")
    redis_url = os.environ.get("TEST_REDIS_URL")
    if (not database_url or not (make_url(database_url).database or "").endswith("test")
            or not redis_url or not redis_url.endswith("/15")):
        raise RuntimeError("Explicit isolated TEST_DATABASE_URL and TEST_REDIS_URL /15 required")
    settings = Settings(
        _env_file=None,
        DATABASE_URL=database_url,
        JWT_SECRET_KEY="isolated-concurrency-test-key-at-least-32-characters",
    )
    engine = create_engine(settings.database_url)
    redis_client = Redis.from_url(redis_url, decode_responses=True)
    with Session(engine) as db:
        user = User(email=f"race-{uuid.uuid4().hex}@example.com", username="race")
        db.add(user)
        db.commit()
        _, token, _ = create_session_and_tokens(
            db, settings, redis_client, user=user, device_info=None, ip=None
        )

    # Coordinate the real Redis boundary after hash validation to expose a lost update.
    original_exists = redis_client.exists
    second_validation = threading.Event()
    counter_lock = threading.Lock()
    calls = 0

    def coordinated_exists(*names):
        nonlocal calls
        with counter_lock:
            calls += 1
            first = calls == 1
        if first:
            second_validation.wait(timeout=3)
        else:
            second_validation.set()
        return original_exists(*names)

    redis_client.exists = coordinated_exists
    start = threading.Barrier(2)

    def rotate(_: int) -> bool:
        with Session(engine) as db:
            start.wait(timeout=10)
            try:
                refresh_tokens(db, settings, redis_client, refresh_token=token)
                return True
            except ValueError:
                return False

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            successes = sum(pool.map(rotate, range(2)))
        assert successes == 1, f"Database refresh race: successes={successes}, expected=1"
    finally:
        redis_client.close()
        engine.dispose()
    print("PASS: two PostgreSQL transactions cannot consume the same refresh token")


def verify(base_url: str) -> None:
    credentials = {
        "email": f"concurrency-{uuid.uuid4().hex}@example.com",
        "password": f"Concurrency1-{uuid.uuid4().hex}",
        "username": "concurrency",
    }
    with httpx.Client(base_url=base_url, timeout=15) as client:
        assert client.post("/api/v1/auth/register", json=credentials).status_code == 200
        login = client.post("/api/v1/auth/login", json=credentials)
        assert login.status_code == 200
        refresh = login.json()["refresh_token"]
        start = threading.Barrier(8)

        def refresh_once(_: int) -> int:
            start.wait(timeout=10)
            response = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
            return response.status_code

        with ThreadPoolExecutor(max_workers=8) as pool:
            statuses = list(pool.map(refresh_once, range(8)))
        successes = statuses.count(200)
        rejections = statuses.count(401)
        assert successes == 1 and rejections == 7, (
            f"Concurrent refresh failed: successes={successes}, rejected={rejections}, statuses={statuses}"
        )
    print("PASS: concurrent refresh issues one token pair and rejects seven replays")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:38080")
    parser.add_argument("--database-race", action="store_true")
    args = parser.parse_args()
    if args.database_race:
        verify_database_race()
    else:
        verify(args.base_url)
