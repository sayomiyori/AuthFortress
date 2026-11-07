import uuid

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, EmailStr, Field, field_validator
from redis import Redis
from sqlalchemy.orm import Session

from app.core.rbac import can_manage_user, require_min_role, require_superadmin, role_rank
from app.core.redis_client import get_redis
from app.core.security import get_current_session_id, get_current_user
from app.db.session import get_db
from app.models.user import User, UserRole
from app.services import auth_service, tenant_service
from app.services.audit_service import write_audit
from app.services.password import hash_password, validate_password_strength

router = APIRouter()


class UserOut(BaseModel):
    id: str
    email: str
    username: str
    role: str
    is_active: bool

    model_config = {"from_attributes": True}

    @field_validator("id", mode="before")
    @classmethod
    def id_as_str(cls, value: object) -> str:
        return str(value)


class UserCreateAdmin(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)
    username: str = Field(min_length=1, max_length=128)
    role: UserRole = UserRole.user
    is_active: bool = True


class UserUpdateAdmin(BaseModel):
    email: EmailStr | None = None
    username: str | None = Field(default=None, max_length=128)
    password: str | None = None
    role: UserRole | None = None
    is_active: bool | None = None


@router.get("", response_model=list[UserOut])
def list_users(
    db: Session = Depends(get_db),
    _: User = Depends(require_min_role(UserRole.admin)),
    skip: int = 0,
    limit: int = 50,
):
    users = db.query(User).offset(skip).limit(min(limit, 200)).all()
    return users


@router.get("/me", response_model=UserOut)
def get_me(current: User = Depends(get_current_user)):
    return current


@router.get("/{user_id}", response_model=UserOut)
def get_user(
    user_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = Depends(require_min_role(UserRole.admin)),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    body: UserCreateAdmin,
    db: Session = Depends(get_db),
    actor: User = Depends(require_min_role(UserRole.admin)),
):
    if body.role != UserRole.user and role_rank(actor.role) < role_rank(UserRole.superadmin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only superadmin may assign non-default roles",
        )

    ok, err = validate_password_strength(body.password)
    if not ok:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err)

    if db.query(User).filter(User.email == body.email.lower()).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    user = User(
        email=body.email.lower(),
        hashed_password=hash_password(body.password),
        username=body.username,
        role=body.role,
        is_active=body.is_active,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    write_audit(
        db,
        action="user_created",
        user_id=actor.id,
        details={"target_user_id": str(user.id), "role": user.role.value},
    )
    return user


@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: uuid.UUID,
    body: UserUpdateAdmin,
    db: Session = Depends(get_db),
    actor: User = Depends(require_min_role(UserRole.admin)),
    redis_client: Redis = Depends(get_redis),
    current_session_id: str = Depends(get_current_session_id),
):
    user = (
        db.query(User)
        .filter(User.id == user_id)
        .with_for_update()
        .first()
    )
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if not can_manage_user(actor, user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot modify this user")
    if body.role is not None and role_rank(actor.role) < role_rank(UserRole.superadmin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only superadmin may change role",
        )

    email_changed = body.email is not None and body.email.lower() != user.email
    password_changed = body.password is not None
    username_changed = body.username is not None and body.username != user.username
    role_changed = body.role is not None and body.role != user.role
    active_changed = body.is_active is not None and body.is_active != user.is_active
    if body.email is not None:
        existing = db.query(User).filter(User.email == body.email.lower(), User.id != user_id).first()
        if existing:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already in use")
        user.email = body.email.lower()
    if body.username is not None:
        user.username = body.username
    if body.password is not None:
        ok, err = validate_password_strength(body.password)
        if not ok:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err)
        user.hashed_password = hash_password(body.password)
    if body.role is not None:
        user.role = body.role
    if body.is_active is not None:
        user.is_active = body.is_active

    changed = any(
        (
            email_changed,
            password_changed,
            username_changed,
            role_changed,
            active_changed,
        )
    )
    if not changed:
        return user

    revoked = 0
    deactivated = active_changed and not user.is_active
    reactivated = active_changed and user.is_active
    if email_changed or password_changed or deactivated or reactivated:
        # The helper commits the credential/active change and the revocations
        # together. Deactivation ends every session, including a self-blocked
        # caller's; reactivation revokes sessions that predate an out-of-band
        # deactivation; credential changes keep the caller's own session. The
        # active -> active path stays a no-op.
        revoked = auth_service.revoke_user_sessions(
            db,
            redis_client,
            user_id=user.id,
            except_session_id=(
                None
                if deactivated or reactivated
                else (current_session_id if actor.id == user.id else None)
            ),
        )
    else:
        db.commit()
    db.refresh(user)
    write_audit(
        db,
        action="user_updated",
        user_id=actor.id,
        details={
            "target_user_id": str(user_id),
            "password_changed": password_changed,
            "email_changed": email_changed,
            "username_changed": username_changed,
            "role_changed": role_changed,
            "active_changed": active_changed,
            "sessions_revoked": revoked,
        },
    )
    return user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: uuid.UUID,
    db: Session = Depends(get_db),
    actor: User = Depends(require_superadmin()),
):
    user = db.query(User).filter(User.id == user_id).with_for_update().first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    tenant_service.ensure_user_has_no_tenants(db, user_id)
    db.delete(user)
    db.commit()
    write_audit(
        db,
        action="user_deleted",
        user_id=None if actor.id == user_id else actor.id,
        details={"target_user_id": str(user_id)},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
