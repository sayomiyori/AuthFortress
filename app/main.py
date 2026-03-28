from fastapi import FastAPI

from app.api.v1 import api_router
from app.config import get_settings
from app.middleware.audit import AuthAuditMiddleware

settings = get_settings()

app = FastAPI(title=settings.app_name, debug=settings.debug)
app.add_middleware(AuthAuditMiddleware)
app.include_router(api_router)


@app.get("/")
def root():
    return {
        "service": settings.app_name,
        "docs": "/docs",
        "health": "/health",
        "api": "/api/v1",
    }


@app.get("/health")
def health():
    return {"status": "ok"}
