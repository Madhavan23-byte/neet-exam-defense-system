"""
B-SEA Security Utilities
JWT, password hashing, token management.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import get_settings

settings = get_settings()

# ── Password Hashing ──────────────────────────────────────────────────────────
# Argon2id: winner of Password Hashing Competition, memory-hard
# Fallback to bcrypt if Argon2 is unavailable (never plaintext)
pwd_context = CryptContext(
    schemes=["argon2", "bcrypt"],
    deprecated="auto",
    argon2__memory_cost=65536,   # 64 MB
    argon2__time_cost=3,
    argon2__parallelism=4,
)


import asyncio

async def hash_password(password: str) -> str:
    """Hash password using Argon2id without blocking the event loop."""
    return await asyncio.to_thread(pwd_context.hash, password)


async def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against stored hash without blocking the event loop."""
    return await asyncio.to_thread(pwd_context.verify, plain_password, hashed_password)


# ── JWT Tokens ────────────────────────────────────────────────────────────────

def create_access_token(
    subject: str,
    role: str,
    org_id: str,
    extra_claims: Optional[dict] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Create a short-lived JWT access token.
    Claims follow JWT standard (sub, exp, iat) + B-SEA specific claims.
    """
    if expires_delta is None:
        expires_delta = timedelta(minutes=settings.access_token_expire_minutes)

    now = datetime.now(timezone.utc)
    expire = now + expires_delta

    payload = {
        "sub": subject,           # User ID
        "role": role,             # Primary role
        "org_id": org_id,         # Organization ID
        "iat": now,               # Issued at
        "exp": expire,            # Expiry
        "type": "access",
        "jti": secrets.token_hex(16),  # JWT ID (for revocation)
    }

    if extra_claims:
        payload.update(extra_claims)

    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def create_refresh_token(subject: str) -> str:
    """Create a long-lived refresh token."""
    expire = datetime.now(timezone.utc) + timedelta(
        days=settings.refresh_token_expire_days
    )
    payload = {
        "sub": subject,
        "exp": expire,
        "type": "refresh",
        "jti": secrets.token_hex(16),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def decode_token(token: str) -> dict:
    """
    Decode and validate a JWT token.
    Raises JWTError if invalid or expired.
    """
    return jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])


# ── Secure Token Generation ───────────────────────────────────────────────────

def generate_secure_token(length: int = 32) -> str:
    """Generate a cryptographically secure random token."""
    return secrets.token_urlsafe(length)


def hash_token(token: str) -> str:
    """SHA-256 hash a token for storage (tokens never stored plaintext)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_nonce() -> str:
    """Generate a one-time nonce for threshold authorization ceremonies."""
    return secrets.token_hex(32)


# ── IP / Device Hashing (Privacy) ────────────────────────────────────────────

def hash_ip(ip: str) -> str:
    """
    Hash IP address for privacy-preserving audit logs.
    We store the hash, not the raw IP, to minimize PII in logs.
    Still allows correlation for security investigation.
    """
    salt = settings.secret_key[:16]  # Stable salt for consistent hashing
    return hashlib.sha256(f"{salt}:{ip}".encode()).hexdigest()[:32]
