"""B-SEA — Auth API Endpoints"""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import get_client_ip, get_current_user, limiter
from app.core.models import User
from app.modules.auth.service import AuthService
from pydantic import BaseModel, EmailStr

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


class MFAVerifyRequest(BaseModel):
    user_id: str
    totp_code: str


class MFAEnableRequest(BaseModel):
    totp_code: str


from app.core.security import (
    create_access_token,
    create_refresh_token,
    verify_password,
)

import time
import asyncio
from collections import defaultdict

_identity_login_attempts = defaultdict(list)
_identity_lock = asyncio.Lock()

from app.core.config import get_settings

settings = get_settings()

@router.post("/login")
@limiter.limit(settings.rate_limit_ip_login)
async def login(
    request: Request,
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """Authenticate with username + password."""
    # Enforce Identity-based Rate Limit for prototype
    async with _identity_lock:
        now = time.time()
        window_start = now - 60
        _identity_login_attempts[body.username] = [
            t for t in _identity_login_attempts[body.username] if t > window_start
        ]
        
        limit_str = settings.rate_limit_identity_login
        max_attempts = int(limit_str.split("/")[0])
        
        if len(_identity_login_attempts[body.username]) >= max_attempts:
            raise HTTPException(status_code=429, detail="Too Many Requests for this identity")
            
        _identity_login_attempts[body.username].append(now)

    service = AuthService(db)
    ip = get_client_ip(request)
    result = await service.authenticate(body.username, body.password, ip)
    return result


@router.post("/mfa/verify")
@limiter.limit(settings.rate_limit_mfa)
async def verify_mfa(
    body: MFAVerifyRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Verify TOTP MFA code and issue tokens."""
    service = AuthService(db)
    ip = get_client_ip(request)
    result = await service.verify_mfa(body.user_id, body.totp_code, ip)
    return result


@router.get("/me")
async def get_me(current_user: User = Depends(get_current_user)):
    """Get current authenticated user profile."""
    return {
        "id": current_user.id,
        "username": current_user.username,
        "full_name": current_user.full_name,
        "email": current_user.email,
        "role": current_user.role.value,
        "org_id": current_user.org_id,
        "mfa_enabled": current_user.mfa_enabled,
        "is_active": current_user.is_active,
    }


@router.post("/mfa/setup")
async def setup_mfa(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Initialize MFA setup — returns secret + QR provisioning URI."""
    service = AuthService(db)
    return await service.setup_mfa(current_user.id)


@router.post("/mfa/enable")
async def enable_mfa(
    body: MFAEnableRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Enable MFA after verifying TOTP code."""
    service = AuthService(db)
    return await service.enable_mfa(current_user.id, body.totp_code)
