from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.audit import AuditLog
from app.models.tenant import Tenant, TenantMembership, TenantRole
from app.models.user import User


def get_active_tenant_id(db: Session, tenant_id: UUID) -> UUID:
    active_id = db.scalar(select(Tenant.id).where(Tenant.id == tenant_id, Tenant.is_active.is_(True)))
    if active_id is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return active_id


def ensure_user_has_no_tenants(db: Session, user_id: UUID) -> None:
    if db.scalar(select(Tenant.id).where(Tenant.created_by == user_id).limit(1)) is not None:
        raise HTTPException(status_code=409, detail="User owns a tenant")


def create_tenant(db: Session, user_id: UUID, name: str) -> tuple[Tenant, TenantMembership]:
    try:
        # Serialize owner creation with user deletion; recheck the current identity.
        user = db.scalar(
            select(User).where(User.id == user_id).with_for_update().execution_options(populate_existing=True)
        )
        if user is None or not user.is_active:
            raise HTTPException(status_code=401, detail="User not found or inactive")
        tenant = Tenant(name=name, created_by=user_id)
        db.add(tenant)
        db.flush()
        membership = TenantMembership(tenant_id=tenant.id, user_id=user_id, role=TenantRole.owner)
        db.add(membership)
        db.add(AuditLog(user_id=user_id, action="tenant.created", details={"tenant_id": str(tenant.id)}))
        db.commit()
        db.refresh(tenant)
        db.refresh(membership)
        return tenant, membership
    except Exception:
        db.rollback()
        raise


def list_tenants(db: Session, user_id: UUID, offset: int, limit: int) -> list[tuple[Tenant, TenantMembership]]:
    rows = db.execute(
        select(Tenant, TenantMembership)
        .join(TenantMembership, TenantMembership.tenant_id == Tenant.id)
        .where(TenantMembership.user_id == user_id, TenantMembership.is_active.is_(True), Tenant.is_active.is_(True))
        .order_by(Tenant.created_at, Tenant.id).offset(offset).limit(limit)
    ).all()
    return [(tenant, membership) for tenant, membership in rows]


def get_tenant_membership(db: Session, user_id: UUID, tenant_id: UUID) -> tuple[Tenant, TenantMembership]:
    row = db.execute(
        select(Tenant, TenantMembership)
        .join(TenantMembership, TenantMembership.tenant_id == Tenant.id)
        .where(Tenant.id == tenant_id, TenantMembership.user_id == user_id,
               TenantMembership.is_active.is_(True), Tenant.is_active.is_(True))
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return row[0], row[1]
