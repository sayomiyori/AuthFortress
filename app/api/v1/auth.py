import jwt
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, Field
from redis import Redis
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.core.metrics import (
    auth_login_total,
    auth_register_total,
    rate_limit_exceeded_total,
    totp_setup_total,
)
from app.core.rate_limiter import sliding_window_allow
from app.core.redis_client import get_redis
from app.core.security import get_current_session_id, get_current_user
from app.db.session import get_db
from app.models.user import User
from app.services import auth_service, jwt_service, totp_service
from app.services.audit_service import write_audit
from app.services.jwt_service import create_temp_2fa_token, decode_temp_2fa_token
from app.services.oauth.token_crypto import decrypt_token, encrypt_token

router = APIRouter()


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


class RegisterBody(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)
    username: str = Field(min_length=1, max_length=128)


class RegisterResponse(BaseModel):
    user_id: str
    email: str


class LoginBody(BaseModel):
    email: EmailStr
    password: str


class Login2FABody(BaseModel):
    temp_token: str
    code: str = Field(min_length=4, max_length=32)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class Login2FAResponse(BaseModel):
    requires_2fa: bool = True
    temp_token: str


class RefreshBody(BaseModel):
    refresh_token: str


class MeResponse(BaseModel):
    id: str
    email: str
    username: str
    role: str


class TwoFASetupResponse(BaseModel):
    secret: str
    qr_code_base64: str
    provisioning_uri: str


class TwoFAVerifyBody(BaseModel):
    code: str = Field(min_length=6, max_length=8)


class TwoFAVerifyResponse(BaseModel):
    enabled: bool = True
    backup_codes: list[str]


class TwoFADisableBody(BaseModel):
    code: str = Field(min_length=6, max_length=32)


@router.get("/me", response_model=MeResponse)
def me(current: User = Depends(get_current_user)):
    return MeResponse(
        id=str(current.id),
        email=current.email,
        username=current.username,
        role=current.role.value,
    )


@router.post("/register", response_model=RegisterResponse)
def register(
    request: Request,
    body: RegisterBody,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    redis_client: Redis = Depends(get_redis),
):
    ip = _client_ip(request)
    key = f"rl:register:{ip}"
    allowed, retry_after = sliding_window_allow(redis_client, key=key, limit=3, window_seconds=60)
    if not allowed:
        rate_limit_exceeded_total.labels(route="register").inc()
        write_audit(
            db,
            action="rate_limit_exceeded",
            ip_address=ip,
            user_agent=request.headers.get("user-agent"),
            details={"route": "register"},
        )
        response.headers["Retry-After"] = str(retry_after)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many registration attempts",
            headers={"Retry-After": str(retry_after)},
        )

    try:
        user = auth_service.register_user(
            db,
            email=body.email,
            password=body.password,
            username=body.username,
        )
    except ValueError as e:
        msg = str(e)
        if "already registered" in msg.lower():
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=msg) from e
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg) from e

    auth_register_total.inc()
    write_audit(
        db,
        action="register",
        user_id=user.id,
        ip_address=ip,
        user_agent=request.headers.get("user-agent"),
        details={"email": user.email},
    )
    return RegisterResponse(user_id=str(user.id), email=user.email)


@router.post("/login")
def login(
    request: Request,
    body: LoginBody,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    redis_client: Redis = Depends(get_redis),
    user_agent: str | None = Header(default=None, alias="User-Agent"),
):
    ip = _client_ip(request)
    key = f"rl:login:{ip}"
    allowed, retry_after = sliding_window_allow(redis_client, key=key, limit=5, window_seconds=60)
    if not allowed:
        rate_limit_exceeded_total.labels(route="login").inc()
        write_audit(
            db,
            action="rate_limit_exceeded",
            ip_address=ip,
            user_agent=user_agent,
            details={"route": "login"},
        )
        response.headers["Retry-After"] = str(retry_after)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts",
            headers={"Retry-After": str(retry_after)},
        )

    user = auth_service.authenticate_user(db, email=body.email, password=body.password)
    if not user:
        auth_login_total.labels(method="password", status="failed").inc()
        write_audit(
            db,
            action="login_failed",
            ip_address=ip,
            user_agent=user_agent,
            details={"email": body.email},
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    if user.totp_enabled:
        temp = create_temp_2fa_token(settings, user_id=str(user.id))
        write_audit(
            db,
            action="login_success",
            user_id=user.id,
            ip_address=ip,
            user_agent=user_agent,
            details={"step": "password", "requires_2fa": True},
        )
        return Login2FAResponse(temp_token=temp)

    access, refresh, _ = auth_service.create_session_and_tokens(
        db,
        settings,
        redis_client,
        user=user,
        device_info=user_agent,
        ip=ip,
    )
    auth_login_total.labels(method="password", status="success").inc()
    write_audit(
        db,
        action="login_success",
        user_id=user.id,
        ip_address=ip,
        user_agent=user_agent,
        details={"step": "complete", "method": "password"},
    )
    return TokenResponse(access_token=access, refresh_token=refresh)


@router.post("/login/2fa", response_model=TokenResponse)
def login_2fa(
    request: Request,
    body: Login2FABody,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    redis_client: Redis = Depends(get_redis),
    user_agent: str | None = Header(default=None, alias="User-Agent"),
):
    ip = _client_ip(request)
    try:
        payload = decode_temp_2fa_token(settings, body.temp_token)
    except (jwt.PyJWTError, ValueError) as e:
        auth_login_total.labels(method="2fa", status="failed").inc()
        write_audit(
            db,
            action="login_2fa_failed",
            ip_address=ip,
            user_agent=user_agent,
            details={"reason": "invalid_temp_token"},
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired temp token") from e

    from uuid import UUID as UUIDType

    user = db.query(User).filter(User.id == UUIDType(str(payload["sub"]))).first()
    if not user or not user.is_active or not user.totp_enabled:
        auth_login_total.labels(method="2fa", status="failed").inc()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid 2FA session")

    secret_plain = decrypt_token(settings, user.totp_secret_encrypted or "")
    ok_totp = bool(secret_plain) and totp_service.verify_totp(secret_plain, body.code)
    ok_backup = totp_service.verify_and_consume_backup_code(user, body.code)
    if not ok_totp and not ok_backup:
        db.commit()
        auth_login_total.labels(method="2fa", status="failed").inc()
        write_audit(
            db,
            action="login_2fa_failed",
            user_id=user.id,
            ip_address=ip,
            user_agent=user_agent,
            details={},
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid 2FA code")

    if ok_backup:
        db.commit()

    access, refresh, _ = auth_service.create_session_and_tokens(
        db,
        settings,
        redis_client,
        user=user,
        device_info=user_agent,
        ip=ip,
    )
    auth_login_total.labels(method="2fa", status="success").inc()
    write_audit(
        db,
        action="login_2fa_success",
        user_id=user.id,
        ip_address=ip,
        user_agent=user_agent,
        details={},
    )
    return TokenResponse(access_token=access, refresh_token=refresh)


@router.post("/refresh", response_model=TokenResponse)
def refresh(
    request: Request,
    body: RefreshBody,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    redis_client: Redis = Depends(get_redis),
):
    from uuid import UUID

    payload = None
    try:
        payload = jwt_service.decode_token(settings, body.refresh_token)
    except jwt.PyJWTError:
        pass
    try:
        access, new_refresh = auth_service.refresh_tokens(
            db,
            settings,
            redis_client,
            refresh_token=body.refresh_token,
        )
    except ValueError as e:
        uid = None
        if payload and payload.get("sub"):
            try:
                uid = UUID(str(payload["sub"]))
            except ValueError:
                uid = None
        write_audit(
            db,
            action="token_refresh",
            user_id=uid,
            ip_address=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
            details={"result": "failed", "error": str(e)},
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e)) from e

    uid = UUID(str(payload["sub"])) if payload and payload.get("sub") else None
    write_audit(
        db,
        action="token_refresh",
        user_id=uid,
        ip_address=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        details={"result": "success"},
    )
    return TokenResponse(access_token=access, refresh_token=new_refresh)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    session_id: str = Depends(get_current_session_id),
    db: Session = Depends(get_db),
    redis_client: Redis = Depends(get_redis),
    current: User = Depends(get_current_user),
):
    auth_service.logout_session(db, redis_client, session_id=session_id)
    write_audit(
        db,
        action="logout",
        user_id=current.id,
        ip_address=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        details={"session_id": session_id},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/2fa/setup", response_model=TwoFASetupResponse)
def twofa_setup(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    current: User = Depends(get_current_user),
):
    secret = totp_service.generate_totp_secret()
    current.totp_secret_encrypted = encrypt_token(settings, secret)
    current.totp_enabled = False
    current.backup_codes_hashed = None
    db.commit()
    totp_setup_total.labels(status="started").inc()
    write_audit(
        db,
        action="2fa_setup",
        user_id=current.id,
        ip_address=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        details={"step": "secret_generated"},
    )
    return TwoFASetupResponse(
        secret=secret,
        qr_code_base64=totp_service.qr_code_base64(secret, current.email),
        provisioning_uri=totp_service.provisioning_uri(secret, current.email),
    )


@router.post("/2fa/verify", response_model=TwoFAVerifyResponse)
def twofa_verify(
    request: Request,
    body: TwoFAVerifyBody,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    current: User = Depends(get_current_user),
):
    secret_plain = decrypt_token(settings, current.totp_secret_encrypted or "")
    if not secret_plain or not totp_service.verify_totp(secret_plain, body.code):
        totp_setup_total.labels(status="failed").inc()
        write_audit(
            db,
            action="2fa_verify",
            user_id=current.id,
            ip_address=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
            details={"result": "invalid_code"},
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid TOTP code")

    plain_codes = totp_service.generate_backup_codes(10)
    current.backup_codes_hashed = [totp_service.hash_backup_code(c) for c in plain_codes]
    current.totp_enabled = True
    db.commit()
    totp_setup_total.labels(status="success").inc()
    write_audit(
        db,
        action="2fa_verify",
        user_id=current.id,
        ip_address=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        details={"result": "enabled"},
    )
    return TwoFAVerifyResponse(backup_codes=plain_codes)


@router.post("/2fa/disable", status_code=status.HTTP_204_NO_CONTENT)
def twofa_disable(
    request: Request,
    body: TwoFADisableBody,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    current: User = Depends(get_current_user),
):
    if not current.totp_secret_encrypted:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No 2FA secret to disable")

    secret_plain = decrypt_token(settings, current.totp_secret_encrypted or "")
    ok_totp = bool(secret_plain) and totp_service.verify_totp(secret_plain, body.code)
    ok_backup = totp_service.verify_and_consume_backup_code(current, body.code)
    if not ok_totp and not ok_backup:
        db.commit()
        write_audit(
            db,
            action="2fa_disable",
            user_id=current.id,
            ip_address=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
            details={"result": "invalid_code"},
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid code")

    current.totp_secret_encrypted = None
    current.totp_enabled = False
    current.backup_codes_hashed = None
    db.commit()
    write_audit(
        db,
        action="2fa_disable",
        user_id=current.id,
        ip_address=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        details={"result": "disabled"},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
