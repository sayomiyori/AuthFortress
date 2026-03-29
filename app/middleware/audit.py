from collections.abc import Callable

from app.db.session import SessionLocal
from app.models.audit import AuditLog
from fastapi import Request, Response
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware


class AuditMiddleware(BaseHTTPMiddleware):
    """Log each HTTP request under /api/v1/auth to audit_logs (transport-level trail)."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path
        if not path.startswith("/api/v1/auth"):
            return await call_next(request)

        response = await call_next(request)

        db: Session = SessionLocal()
        try:
            log = AuditLog(
                user_id=None,
                action="auth.http",
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
                details={
                    "method": request.method,
                    "path": path,
                    "status_code": response.status_code,
                },
            )
            db.add(log)
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()

        return response
