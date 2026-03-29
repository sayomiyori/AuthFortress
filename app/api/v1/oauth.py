import json
import secrets
from typing import Literal, cast
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from redis import Redis
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.core.metrics import auth_login_total
from app.core.redis_client import get_redis
from app.db.session import get_db
from app.services import auth_service
from app.services.audit_service import write_audit
from app.services.oauth.account_service import find_or_link_oauth_user
from app.services.oauth.base import OAuthProvider
from app.services.oauth.factory import OAuthFactory

router = APIRouter()

STATE_TTL_SECONDS = 600
STATE_REDIS_PREFIX = "oauth:state:"


def _provider_dep(provider: str, settings: Settings = Depends(get_settings)) -> OAuthProvider:
    try:
        p = OAuthFactory.get_provider(provider, settings)
    except KeyError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e
    if not p.configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"OAuth provider '{p.name}' is not configured (missing client id/secret)",
        )
    return p


def _safe_next_url(next_url: str | None, base: str) -> str:
    base = base.rstrip("/")
    if not next_url:
        return f"{base}/"
    if next_url.startswith("/") and not next_url.startswith("//"):
        return f"{base}{next_url}"
    return f"{base}/"


@router.get("/{provider}/authorize")
async def oauth_authorize(
    provider: str,
    oauth: OAuthProvider = Depends(_provider_dep),
    redis_client: Redis = Depends(get_redis),
    response_mode: Literal["json", "redirect"] = Query("json"),
    next: str | None = Query(default=None, description="Path only, e.g. /app — used with response_mode=redirect"),
):
    state = secrets.token_urlsafe(32)
    payload = json.dumps(
        {
            "provider": oauth.name,
            "response_mode": response_mode,
            "next": next or "",
        },
    )
    redis_client.setex(f"{STATE_REDIS_PREFIX}{state}", STATE_TTL_SECONDS, payload)
    url = oauth.create_authorization_url(state)
    return RedirectResponse(url=url, status_code=status.HTTP_302_FOUND)


@router.get("/{provider}/callback")
async def oauth_callback(
    provider: str,
    request: Request,
    code: str | None = Query(None),
    state: str | None = Query(None),
    error: str | None = Query(None),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    redis_client: Redis = Depends(get_redis),
):
    if error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"OAuth error: {error}")
    if not code or not state:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing code or state")

    try:
        oauth = OAuthFactory.get_provider(provider, settings)
    except KeyError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e
    if not oauth.configured():
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="OAuth not configured")

    raw = cast(str | None, redis_client.get(f"{STATE_REDIS_PREFIX}{state}"))
    if not raw:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired state")
    redis_client.delete(f"{STATE_REDIS_PREFIX}{state}")

    try:
        meta = json.loads(str(raw))
    except json.JSONDecodeError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Corrupt OAuth state") from None

    if meta.get("provider") != oauth.name:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Provider mismatch")

    authorization_response = str(request.url)
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            token = await oauth.exchange_code(authorization_response, client)
            profile = await oauth.fetch_profile(token, client)
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"OAuth provider HTTP error: {e.response.status_code}",
        ) from e
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="OAuth token exchange failed") from e

    try:
        user, oauth_event = find_or_link_oauth_user(
            db,
            settings,
            provider=oauth.name,
            profile=profile,
            raw_access_token=token.get("access_token") or "",
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e)) from e

    ip = request.client.host if request.client else None
    auth_login_total.labels(method="oauth", status="success").inc()
    write_audit(
        db,
        action=oauth_event,
        user_id=user.id,
        ip_address=ip,
        user_agent=request.headers.get("user-agent"),
        details={"provider": oauth.name, "email": profile.email},
    )
    access, refresh, _ = auth_service.create_session_and_tokens(
        db,
        settings,
        redis_client,
        user=user,
        device_info=request.headers.get("user-agent"),
        ip=ip,
    )

    mode = meta.get("response_mode") or "json"
    if mode == "redirect":
        target = _safe_next_url(meta.get("next") or None, settings.oauth_redirect_base_url)
        frag = urlencode(
            {
                "access_token": access,
                "refresh_token": refresh,
                "token_type": "bearer",
            },
        )
        return RedirectResponse(url=f"{target}#{frag}", status_code=status.HTTP_302_FOUND)

    return JSONResponse(
        {
            "access_token": access,
            "refresh_token": refresh,
            "token_type": "bearer",
        },
    )
