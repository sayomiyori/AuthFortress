import re

import bcrypt

PASSWORD_RULE = re.compile(r"^(?=.*[A-Z])(?=.*\d).{8,}$")


def validate_password_strength(password: str) -> tuple[bool, str | None]:
    if len(password.encode("utf-8")) > 72:
        return False, "Password must not exceed 72 UTF-8 bytes"
    if not PASSWORD_RULE.match(password):
        return False, "Password must be at least 8 characters with 1 digit and 1 uppercase letter"
    return True, None


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def verify_password(plain: str, hashed: str) -> bool:
    if len(plain.encode("utf-8")) > 72:
        return False
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        return False
