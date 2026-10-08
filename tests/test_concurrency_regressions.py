import asyncio
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

from app.middleware.audit import AuditMiddleware
from app.models.user import User
from app.services import auth_service
from fastapi import FastAPI, Request, Response
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker


def test_same_email_registration_race_is_a_conflict(db_engine, monkeypatch):
    sessions = sessionmaker(db_engine)
    barrier = threading.Barrier(2)
    original = auth_service.hash_password
    email = f"race-{uuid4()}@example.com"

    def coordinated_hash(value):
        barrier.wait(timeout=10)
        return original(value)

    monkeypatch.setattr(auth_service, "hash_password", coordinated_hash)

    def register():
        with sessions() as db:
            try:
                auth_service.register_user(db, email=email, password="Synthetic-Strong-Password1", username="race")
                return "created"
            except ValueError as exc:
                assert str(exc) == "Email already registered"
                return "conflict"

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = [pool.submit(register) for _ in range(2)]
            assert sorted(task.result(timeout=15) for task in outcomes) == ["conflict", "created"]
        with sessions() as db:
            assert db.query(User).filter(User.email == email).count() == 1
    finally:
        with sessions() as db:
            db.query(User).filter(User.email == email).delete()
            db.commit()


def test_audit_database_lock_does_not_block_event_loop(db_engine, monkeypatch):
    from app.models.audit import AuditLog

    path = f"/api/v1/auth/regression/{uuid4()}"
    sessions = sessionmaker(db_engine)
    monkeypatch.setattr("app.middleware.audit.SessionLocal", sessions)
    locked, release = threading.Event(), threading.Event()

    def hold_lock():
        with db_engine.begin() as connection:
            connection.execute(text("LOCK TABLE audit_logs IN ACCESS EXCLUSIVE MODE"))
            locked.set()
            release.wait(timeout=3)

    async def exercise():
        async def next_response(request):
            return Response(status_code=200)

        request = Request({"type": "http", "method": "GET", "path": path, "headers": []})
        start = time.perf_counter()
        task = asyncio.create_task(AuditMiddleware(FastAPI()).dispatch(request, next_response))
        try:
            await asyncio.sleep(0.05)
            assert time.perf_counter() - start < 1, "Audit blocked the event loop"
        finally:
            release.set()
            await task

    with ThreadPoolExecutor(max_workers=1) as pool:
        locker = pool.submit(hold_lock)
        assert locked.wait(timeout=5)
        try:
            asyncio.run(exercise())
        finally:
            release.set()
            locker.result(timeout=5)
            with sessions() as db:
                db.query(AuditLog).filter(AuditLog.details["path"].as_string() == path).delete()
                db.commit()
