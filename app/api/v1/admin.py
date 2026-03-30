import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, field_validator
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.core.rbac import require_min_role, require_superadmin
from app.core.redis_client import get_redis
from app.db.session import get_db
from app.models.audit import AuditLog
from app.models.session import UserSession
from app.models.user import User, UserRole
from app.services import auth_service
from app.services.audit_service import write_audit

router = APIRouter()


@router.get("/stats")
def admin_stats(
    db: Session = Depends(get_db),
    _: User = Depends(require_min_role(UserRole.admin)),
):
    user_count = db.query(func.count(User.id)).scalar() or 0
    active_sessions = (
        db.query(func.count(UserSession.id))
        .filter(UserSession.revoked_at.is_(None))
        .scalar()
        or 0
    )
    audit_count = db.query(func.count(AuditLog.id)).scalar() or 0
    return {
        "users": user_count,
        "active_sessions": active_sessions,
        "audit_entries": audit_count,
    }


class UserAdminOut(BaseModel):
    id: str
    email: str
    username: str
    role: str
    is_active: bool

    model_config = {"from_attributes": True}

    @field_validator("id", mode="before")
    @classmethod
    def id_as_str(cls, v: object) -> str:
        return str(v) if v is not None else ""

    @field_validator("role", mode="before")
    @classmethod
    def role_as_str(cls, v: object) -> str:
        if isinstance(v, UserRole):
            return v.value
        return str(v) if v is not None else ""


@router.get("/users", response_model=dict)
def admin_list_users(
    db: Session = Depends(get_db),
    _: User = Depends(require_min_role(UserRole.admin)),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
):
    # Do not call .count() on the same Query then .offset()/.limit() — breaks SQL/state on PostgreSQL.
    total = db.query(func.count(User.id)).scalar() or 0
    items = (
        db.query(User)
        .order_by(User.email)
        .offset((page - 1) * size)
        .limit(size)
        .all()
    )
    return {
        "items": [UserAdminOut.model_validate(u) for u in items],
        "total": total,
        "page": page,
        "size": size,
    }


@router.get("/users/{user_id}", response_model=UserAdminOut)
def admin_get_user(
    user_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = Depends(require_min_role(UserRole.admin)),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


class BlockBody(BaseModel):
    blocked: bool


@router.patch("/users/{user_id}/block", response_model=UserAdminOut)
def admin_block_user(
    user_id: uuid.UUID,
    body: BlockBody,
    db: Session = Depends(get_db),
    actor: User = Depends(require_min_role(UserRole.admin)),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    user.is_active = not body.blocked
    db.commit()
    db.refresh(user)
    write_audit(
        db,
        action="user_blocked" if body.blocked else "user_unblocked",
        user_id=actor.id,
        details={"target_user_id": str(user_id), "blocked": body.blocked},
    )
    return user


class RoleBody(BaseModel):
    role: UserRole


@router.patch("/users/{user_id}/role", response_model=UserAdminOut)
def admin_set_role(
    user_id: uuid.UUID,
    body: RoleBody,
    db: Session = Depends(get_db),
    actor: User = Depends(require_superadmin()),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    old = user.role.value
    user.role = body.role
    db.commit()
    db.refresh(user)
    write_audit(
        db,
        action="role_changed",
        user_id=actor.id,
        details={"target_user_id": str(user_id), "old_role": old, "new_role": body.role.value},
    )
    return user


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def admin_delete_user(
    user_id: uuid.UUID,
    db: Session = Depends(get_db),
    actor: User = Depends(require_superadmin()),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    db.delete(user)
    db.commit()
    write_audit(
        db,
        action="user_deleted",
        user_id=actor.id,
        details={"target_user_id": str(user_id)},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


class SessionOut(BaseModel):
    id: str
    user_id: str
    expires_at: datetime | None
    revoked_at: datetime | None
    ip: str | None

    model_config = {"from_attributes": True}


@router.get("/sessions", response_model=list[SessionOut])
def admin_list_sessions(
    db: Session = Depends(get_db),
    _: User = Depends(require_min_role(UserRole.admin)),
    active_only: bool = Query(True),
):
    q = db.query(UserSession)
    if active_only:
        q = q.filter(UserSession.revoked_at.is_(None))
    rows = q.order_by(UserSession.expires_at.desc()).limit(500).all()
    return [
        SessionOut(
            id=str(s.id),
            user_id=str(s.user_id),
            expires_at=s.expires_at,
            revoked_at=s.revoked_at,
            ip=s.ip,
        )
        for s in rows
    ]


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
def admin_revoke_session(
    session_id: uuid.UUID,
    db: Session = Depends(get_db),
    actor: User = Depends(require_min_role(UserRole.admin)),
    redis_client=Depends(get_redis),
):
    auth_service.logout_session(db, redis_client, session_id=str(session_id))
    write_audit(
        db,
        action="admin_session_revoked",
        user_id=actor.id,
        details={"session_id": str(session_id)},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/audit", response_model=dict)
def admin_audit(
    db: Session = Depends(get_db),
    _: User = Depends(require_min_role(UserRole.admin)),
    user_id: uuid.UUID | None = None,
    action: str | None = None,
    from_ts: datetime | None = Query(None, alias="from"),
    to_ts: datetime | None = Query(None, alias="to"),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=200),
):
    def _audit_filtered():
        q = db.query(AuditLog)
        if user_id is not None:
            q = q.filter(AuditLog.user_id == user_id)
        if action:
            q = q.filter(AuditLog.action == action)
        if from_ts is not None:
            q = q.filter(AuditLog.created_at >= from_ts)
        if to_ts is not None:
            q = q.filter(AuditLog.created_at <= to_ts)
        return q

    total = _audit_filtered().count()
    rows = (
        _audit_filtered()
        .order_by(AuditLog.created_at.desc())
        .offset((page - 1) * size)
        .limit(size)
        .all()
    )
    return {
        "items": [
            {
                "id": str(r.id),
                "user_id": str(r.user_id) if r.user_id else None,
                "action": r.action,
                "ip_address": r.ip_address,
                "user_agent": r.user_agent,
                "details": r.details,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
        "total": total,
        "page": page,
        "size": size,
    }


@router.get("/oauth/config", response_model=dict)
def admin_oauth_config(
    settings: Settings = Depends(get_settings),
    _: User = Depends(require_superadmin()),
):
    return {
        "google": {"configured": bool(settings.google_client_id and settings.google_client_secret)},
        "github": {"configured": bool(settings.github_client_id and settings.github_client_secret)},
        "yandex": {"configured": bool(settings.yandex_client_id and settings.yandex_client_secret)},
        "oauth_redirect_base_url": settings.oauth_redirect_base_url,
    }
