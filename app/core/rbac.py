from collections.abc import Callable

from app.core.security import get_current_user
from app.models.user import User, UserRole
from fastapi import Depends, HTTPException, status

_ROLE_RANK: dict[str, int] = {
    UserRole.user.value: 0,
    UserRole.admin.value: 1,
    UserRole.superadmin.value: 2,
}


def role_rank(role: UserRole) -> int:
    return _ROLE_RANK.get(role.value, 0)


def require_min_role(minimum: UserRole) -> Callable[..., User]:
    need = role_rank(minimum)

    def checker(user: User = Depends(get_current_user)) -> User:
        if role_rank(user.role) < need:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return user

    return checker


def require_superadmin() -> Callable[..., User]:
    return require_min_role(UserRole.superadmin)
