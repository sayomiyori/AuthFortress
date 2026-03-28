from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, Field
from redis import Redis
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.core.rate_limiter import sliding_window_allow
from app.core.redis_client import get_redis
from app.core.security import get_current_session_id, get_current_user
from app.db.session import get_db
from app.models.user import User
from app.services import auth_service

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


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshBody(BaseModel):
    refresh_token: str


class MeResponse(BaseModel):
    id: str
    email: str
    username: str
    role: str


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

    return RegisterResponse(user_id=str(user.id), email=user.email)


@router.post("/login", response_model=TokenResponse)
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
        response.headers["Retry-After"] = str(retry_after)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts",
            headers={"Retry-After": str(retry_after)},
        )

    user = auth_service.authenticate_user(db, email=body.email, password=body.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    access, refresh, _ = auth_service.create_session_and_tokens(
        db,
        settings,
        redis_client,
        user=user,
        device_info=user_agent,
        ip=ip,
    )
    return TokenResponse(access_token=access, refresh_token=refresh)


@router.post("/refresh", response_model=TokenResponse)
def refresh(
    body: RefreshBody,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    redis_client: Redis = Depends(get_redis),
):
    try:
        access, new_refresh = auth_service.refresh_tokens(
            db,
            settings,
            redis_client,
            refresh_token=body.refresh_token,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e)) from e

    return TokenResponse(access_token=access, refresh_token=new_refresh)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    session_id: str = Depends(get_current_session_id),
    db: Session = Depends(get_db),
    redis_client: Redis = Depends(get_redis),
):
    auth_service.logout_session(db, redis_client, session_id=session_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
