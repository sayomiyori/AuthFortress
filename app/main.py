from fastapi import Depends, FastAPI, Response
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.v1 import api_router
from app.config import get_settings
from app.core.metrics import active_sessions_gauge, metrics_response_body
from app.db.session import get_db
from app.middleware.audit import AuditMiddleware
from app.models.session import UserSession

settings = get_settings()

app = FastAPI(title=settings.app_name, debug=settings.debug)
app.add_middleware(AuditMiddleware)
app.include_router(api_router)


@app.get("/")
def root():
    return {
        "service": settings.app_name,
        "docs": "/docs",
        "health": "/health",
        "metrics": "/metrics",
        "api": "/api/v1",
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/metrics")
def prometheus_metrics(db: Session = Depends(get_db)):
    n = (
        db.query(func.count(UserSession.id))
        .filter(UserSession.revoked_at.is_(None))
        .scalar()
        or 0
    )
    active_sessions_gauge.set(n)
    body, content_type = metrics_response_body()
    return Response(content=body, media_type=content_type)
