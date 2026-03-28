import uuid

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User, UserRole
from app.core.security import get_current_user, require_role
from app.services.password import hash_password, validate_password_strength

router = APIRouter()


class UserOut(BaseModel):
    id: str
    email: str
    username: str
    role: str
    is_active: bool

    model_config = {"from_attributes": True}


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
    _: User = Depends(require_role(UserRole.admin)),
    skip: int = 0,
    limit: int = 50,
):
    users = db.query(User).offset(skip).limit(min(limit, 200)).all()
    return users


@router.get("/me", response_model=UserOut)
def get_me(current: User = Depends(get_current_user)):
    """Текущий пользователь (любая роль с валидным access token)."""
    return current


@router.get("/{user_id}", response_model=UserOut)
def get_user(
    user_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = Depends(require_role(UserRole.admin)),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    body: UserCreateAdmin,
    db: Session = Depends(get_db),
    _: User = Depends(require_role(UserRole.admin)),
):
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
    return user


@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: uuid.UUID,
    body: UserUpdateAdmin,
    db: Session = Depends(get_db),
    _: User = Depends(require_role(UserRole.admin)),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

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

    db.commit()
    db.refresh(user)
    return user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = Depends(require_role(UserRole.admin)),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    db.delete(user)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
