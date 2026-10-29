import re

from sqlalchemy.orm import Session

from app.config import Settings
from app.models.oauth_account import OAuthAccount
from app.models.user import User, UserRole
from app.services.oauth.base import OAuthUserProfile
from app.services.oauth.token_crypto import encrypt_token


def _username_from_profile(profile: OAuthUserProfile) -> str:
    if profile.name:
        base = re.sub(r"[^\w\-.]+", "_", profile.name.strip())[:128]
        if base.strip("_"):
            return base.strip("_")[:128]
    local = profile.email.split("@")[0]
    return local[:128] if local else f"user_{profile.provider_user_id[:32]}"


def find_or_link_oauth_user(
    db: Session,
    settings: Settings,
    *,
    provider: str,
    profile: OAuthUserProfile,
    raw_access_token: str,
) -> tuple[User, str]:
    prov = provider.lower()
    at_enc = encrypt_token(settings, raw_access_token or "")

    acc = (
        db.query(OAuthAccount)
        .filter(
            OAuthAccount.provider == prov,
            OAuthAccount.provider_user_id == profile.provider_user_id,
        )
        .first()
    )
    if acc:
        acc.access_token_encrypted = at_enc
        acc.email = profile.email
        db.commit()
        db.refresh(acc.user)
        return acc.user, "oauth_login"

    user = db.query(User).filter(User.email == profile.email).first()
    if user:
        if db.query(OAuthAccount).filter(OAuthAccount.user_id == user.id, OAuthAccount.provider == prov).first():
            raise ValueError("This account is already linked to another OAuth identity")
        # Never auto-link an OAuth identity to a local account by email alone:
        # the local email was never verified and may belong to a pre-registered
        # attacker account. Explicit linking from an authenticated session is
        # required (not implemented in this increment).
        raise ValueError("Email already registered; sign in to link an OAuth identity explicitly")

    user = User(
        email=profile.email,
        hashed_password=None,
        username=_username_from_profile(profile),
        role=UserRole.user,
        is_active=True,
        oauth_provider=prov,
    )
    db.add(user)
    db.flush()
    db.add(
        OAuthAccount(
            user_id=user.id,
            provider=prov,
            provider_user_id=profile.provider_user_id,
            email=profile.email,
            access_token_encrypted=at_enc,
        ),
    )
    db.commit()
    db.refresh(user)
    return user, "oauth_register"
