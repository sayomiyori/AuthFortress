from typing import Callable

from fastapi import Request, Response
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware

from app.db.session import SessionLocal
from app.models.audit import AuditLog


class AuthAuditMiddleware(BaseHTTPMiddleware):
    """Log each request under /api/v1/auth to audit_logs."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path
        if not path.startswith("/api/v1/auth"):
            return await call_next(request)

        response = await call_next(request)

        db: Session = SessionLocal()
        try:
            user_id = None
            auth = request.headers.get("authorization")
            details: dict = {
                "method": request.method,
                "path": path,
                "status_code": response.status_code,
            }
            if auth:
                details["has_authorization"] = True

            log = AuditLog(
                user_id=user_id,
                action=f"auth:{request.method.lower()}:{path}",
                ip=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
                details=details,
            )
            db.add(log)
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()

        return response
