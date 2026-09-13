"""
B-SEA — FastAPI Dependencies
Shared dependency injection for authentication and authorization.
"""
from __future__ import annotations

from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.models import User
from app.core.security import decode_token
from app.modules.auth.service import ROLE_PERMISSIONS, has_permission

bearer_scheme = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Extract and validate JWT token from Authorization header.
    Returns the authenticated user.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_token(credentials.credentials)
        user_id: str = payload.get("sub")
        token_type: str = payload.get("type", "")

        if user_id is None or token_type != "access":
            raise credentials_exception

    except JWTError:
        raise credentials_exception

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None or not user.is_active or user.is_locked:
        raise credentials_exception

    return user


async def get_current_session_id(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> Optional[str]:
    """
    Extract the validated JWT session identifier (jti) from the Bearer token.
    Returns the jti claim as the session identifier.
    """
    try:
        payload = decode_token(credentials.credentials)
        return payload.get("jti")
    except Exception:
        return None


def require_permission(permission: str):
    """
    Dependency factory for permission-based authorization.
    Usage: Depends(require_permission("questions:create"))
    """
    async def check_permission(current_user: User = Depends(get_current_user)) -> User:
        if not has_permission(current_user.role.value, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions: {permission} required",
            )
        return current_user
    return check_permission


def require_role(*roles: str):
    """
    Dependency factory for role-based authorization.
    Usage: Depends(require_role("SUPER_ADMIN", "EXAM_AUTHORITY"))
    """
    async def check_role(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role.value not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role {current_user.role.value} not authorized for this operation",
            )
        return current_user
    return check_role


def get_client_ip(request: Request) -> str:
    """Extract client IP from request (handles proxies)."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def rate_limit_key_layered(request: Request) -> str:
    """
    Layered rate limiting key: 
    Use authorization header or registration_number in body (if available) to limit by identity.
    Otherwise limit by IP.
    """
    auth = request.headers.get("Authorization")
    if auth:
        return f"auth:{auth}"
    # Note: request.json() requires async reading, which slowapi doesn't support well natively in sync key_func.
    # Therefore, for unauthenticated routes, we rely primarily on IP.
    return get_client_ip(request)

from slowapi import Limiter
limiter = Limiter(key_func=rate_limit_key_layered)
