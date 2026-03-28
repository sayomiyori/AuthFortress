import re

from passlib.context import CryptContext

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

PASSWORD_RULE = re.compile(r"^(?=.*[A-Z])(?=.*\d).{8,}$")


def validate_password_strength(password: str) -> tuple[bool, str | None]:
    if not PASSWORD_RULE.match(password):
        return False, "Password must be at least 8 characters with 1 digit and 1 uppercase letter"
    return True, None


def hash_password(plain: str) -> str:
    return _pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return _pwd_context.verify(plain, hashed)
