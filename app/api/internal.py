from secrets import compare_digest
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.db.session import get_db
from app.services.tenant_service import get_active_tenant_id

router = APIRouter(prefix="/internal/v1", tags=["internal"])


def require_service_key(
    service_key: str | None = Header(default=None, alias="X-Service-Key"),
    settings: Settings = Depends(get_settings),
) -> None:
    configured = settings.authfortress_webhook_service_key
    if configured is None:
        raise HTTPException(status_code=503, detail="Service unavailable")
    if (
        service_key is None
        or not service_key.isascii()
        or len(service_key) > 256
        or not compare_digest(service_key.encode("ascii"), configured.get_secret_value().encode("ascii"))
    ):
        raise HTTPException(status_code=401, detail="Invalid service key")


class TenantStatus(BaseModel):
    tenant_id: UUID
    is_active: Literal[True] = True


@router.get("/tenants/{tenant_id}/status", response_model=TenantStatus, dependencies=[Depends(require_service_key)])
def tenant_status(tenant_id: UUID, db: Session = Depends(get_db)) -> TenantStatus:
    return TenantStatus(tenant_id=get_active_tenant_id(db, tenant_id))
