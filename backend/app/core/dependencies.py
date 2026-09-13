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

import os
import logging
from typing import Callable, Any
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from app.core.config import get_settings

settings = get_settings()
logger = logging.getLogger("bsea.limiter")

SECURITY_SENSITIVE_PATHS = (
    "/api/v1/auth/",
    "/api/v1/candidate/auth/",
    "/api/v1/break-glass/",
    "/api/v1/release/",
    "/api/v1/users/",
    "/api/v1/organizations/",
)


def is_security_sensitive_path(path: str) -> bool:
    """Determine if a request path is security-sensitive."""
    return any(path.startswith(prefix) for prefix in SECURITY_SENSITIVE_PATHS)


class BSEALimiter(Limiter):
    """
    B-SEA Distributed Rate Limiter with Differentiated Failure Handling.

    Security Invariants:
    1. Distributed shared state via Redis across horizontally scaled workers.
    2. Under Redis failure:
       - Security-sensitive endpoints FAIL CLOSED (503 Service Unavailable).
       - Candidate availability-sensitive endpoints DEGRADE GRACEFULLY to allow
         authoritative PostgreSQL validation to proceed without disruption.
    """

    def _check_request_limit(
        self,
        request: Request,
        endpoint_func: Optional[Callable[..., Any]],
        in_middleware: bool = True,
    ) -> None:
        try:
            super()._check_request_limit(request, endpoint_func, in_middleware)
        except RateLimitExceeded:
            raise
        except Exception as e:
            # Differentiated Redis failure policy
            path = ""
            if hasattr(request, "url") and request.url:
                path = str(request.url.path)
            elif isinstance(request, dict):
                path = request.get("path", "")

            if is_security_sensitive_path(path):
                logger.error(
                    "Redis rate-limit backend failure on security-sensitive endpoint '%s': %s. FAILING CLOSED.",
                    path,
                    e,
                )
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Security verification service temporarily unavailable (Rate limiter fail-closed). Please retry later.",
                )
            else:
                logger.warning(
                    "Redis rate-limit backend failure on candidate endpoint '%s': %s. Degrading gracefully.",
                    path,
                    e,
                )
                return


def get_rate_limit_storage_uri() -> str:
    """Return storage URI for rate limiter: Redis in production, memory in testing unless overridden."""
    explicit = os.environ.get("BSEA_RATE_LIMIT_STORAGE")
    if explicit:
        return explicit
    if os.environ.get("TESTING") == "1" or settings.environment == "testing":
        return "memory://"
    return settings.redis_url


limiter = BSEALimiter(
    key_func=rate_limit_key_layered,
    storage_uri=get_rate_limit_storage_uri(),
)
