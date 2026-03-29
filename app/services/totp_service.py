import base64
import hashlib
import io
import secrets
from typing import TYPE_CHECKING

import pyotp
import qrcode

if TYPE_CHECKING:
    pass


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, email: str, issuer: str = "AuthFortress") -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)


def generate_qr_code_png(secret: str, email: str, issuer: str = "AuthFortress") -> bytes:
    uri = provisioning_uri(secret, email, issuer)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def qr_code_base64(secret: str, email: str, issuer: str = "AuthFortress") -> str:
    raw = generate_qr_code_png(secret, email, issuer)
    return base64.standard_b64encode(raw).decode("ascii")


def verify_totp(secret: str, code: str, *, valid_window: int = 1) -> bool:
    if not secret or not code:
        return False
    return bool(pyotp.TOTP(secret).verify(code.strip(), valid_window=valid_window))


def generate_backup_codes(count: int = 10) -> list[str]:
    return [secrets.token_hex(4) + "-" + secrets.token_hex(4) for _ in range(count)]


def hash_backup_code(code: str) -> str:
    return hashlib.sha256(code.strip().encode()).hexdigest()


def verify_and_consume_backup_code(user, code: str) -> bool:
    """Remove one matching backup code hash from user.backup_codes_hashed. Returns True if consumed."""
    import hmac

    raw = (code or "").strip()
    if not raw:
        return False
    hashes = user.backup_codes_hashed
    if not hashes:
        return False
    digest = hashlib.sha256(raw.encode()).hexdigest()
    new_list: list[str] = []
    consumed = False
    for h in hashes:
        if not consumed and hmac.compare_digest(h, digest):
            consumed = True
            continue
        new_list.append(h)
    if consumed:
        user.backup_codes_hashed = new_list
        return True
    return False
