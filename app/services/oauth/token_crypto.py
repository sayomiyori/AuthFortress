import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from app.config import Settings


def _fernet_key(settings: Settings) -> bytes:
    raw = (settings.oauth_token_encryption_key or "").strip()
    if raw:
        if len(raw) == 44 and raw.endswith("="):
            return raw.encode()
        digest = hashlib.sha256(raw.encode()).digest()
        return base64.urlsafe_b64encode(digest)
    digest = hashlib.sha256(settings.jwt_secret_key.encode()).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_token(settings: Settings, plaintext: str) -> str:
    if not plaintext:
        return ""
    f = Fernet(_fernet_key(settings))
    return f.encrypt(plaintext.encode()).decode()


def decrypt_token(settings: Settings, ciphertext: str) -> str:
    if not ciphertext:
        return ""
    f = Fernet(_fernet_key(settings))
    try:
        return f.decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        return ""
