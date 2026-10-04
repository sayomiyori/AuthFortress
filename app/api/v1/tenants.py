import enum
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator
from sqlalchemy.orm import Session

from app.core.security import get_current_user
from app.db.session import get_db
from app.models.tenant import Tenant, TenantMembership, TenantRole
from app.models.user import User
from app.services import tenant_service

router = APIRouter(prefix="/tenants", tags=["tenants"])


class TenantPermission(str, enum.Enum):
    tenant_read = "tenant.read"
    bot_read = "bot.read"
    ai_read = "ai.read"
    tenant_manage = "tenant.manage"
    bot_manage = "bot.manage"
    ai_configure = "ai.configure"


MEMBER_PERMISSIONS = {TenantPermission.tenant_read, TenantPermission.bot_read, TenantPermission.ai_read}


class TenantCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Annotated[str, StringConstraints(strict=True, strip_whitespace=True, min_length=1, max_length=128)]


class TenantView(BaseModel):
    id: UUID
    name: str
    role: TenantRole
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def as_utc(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)


class AuthorizationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    permission: TenantPermission


class AuthorizedContext(BaseModel):
    user_id: UUID
    tenant_id: UUID
    role: TenantRole
    permission: TenantPermission
    allowed: bool = True


def _view(tenant: Tenant, membership: TenantMembership) -> TenantView:
    return TenantView(id=tenant.id, name=tenant.name, role=membership.role, created_at=tenant.created_at)


@router.post("", response_model=TenantView, status_code=201)
def create_tenant(body: TenantCreate, current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _view(*tenant_service.create_tenant(db, current.id, body.name))


@router.get("", response_model=list[TenantView])
def list_tenants(
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=100),
    current: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return [_view(*row) for row in tenant_service.list_tenants(db, current.id, offset, limit)]


@router.get("/{tenant_id}", response_model=TenantView)
def get_tenant(tenant_id: UUID, current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return _view(*tenant_service.get_tenant_membership(db, current.id, tenant_id))


@router.post("/{tenant_id}/authorize", response_model=AuthorizedContext)
def authorize_tenant(
    tenant_id: UUID,
    body: AuthorizationRequest,
    current: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _, membership = tenant_service.get_tenant_membership(db, current.id, tenant_id)
    if membership.role != TenantRole.owner and body.permission not in MEMBER_PERMISSIONS:
        raise HTTPException(status_code=403, detail="Insufficient tenant permissions")
    return AuthorizedContext(user_id=current.id, tenant_id=tenant_id, role=membership.role, permission=body.permission)
