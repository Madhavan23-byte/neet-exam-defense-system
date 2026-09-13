"""
B-SEA — Auth Service
Authentication, MFA, session management, RBAC.
"""
from __future__ import annotations

import pyotp
import secrets
from datetime import datetime, timezone
from typing import Optional

from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.models import AuditResult, User, UserRoleEnum
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
    hash_ip,
)
from app.crypto.kms_interface import get_kms
from app.modules.audit.service import AuditService

settings = get_settings()


class AuthService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.audit = AuditService(db)
        self.kms = get_kms()

    async def authenticate(
        self, username: str, password: str, ip: str = "", device_id: str = ""
    ) -> dict:
        """
        Authenticate user with username + password.
        Returns partial auth state if MFA is required.
        """
        result = await self.db.execute(
            select(User).where(User.username == username)
        )
        user = result.scalar_one_or_none()

        if not user:
            await self.audit.log(
                event_type="LOGIN_FAILURE",
                result=AuditResult.FAILURE,
                action=f"Unknown user: {username}",
                ip_hash=hash_ip(ip),
                risk_score=0.3,
            )
            return {"success": False, "error": "Invalid credentials"}

        if user.is_locked:
            await self.audit.log(
                event_type="LOGIN_BLOCKED",
                result=AuditResult.BLOCKED,
                actor_id=user.id,
                actor_role=user.role.value,
                ip_hash=hash_ip(ip),
                risk_score=0.5,
            )
            return {"success": False, "error": "Account is locked. Contact administrator."}

        if not user.is_active:
            return {"success": False, "error": "Account is inactive."}

        is_valid_password = await verify_password(password, user.password_hash)
        if not is_valid_password:
            # Increment failed attempts
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= settings.max_mfa_attempts:
                user.is_locked = True

            await self.audit.log(
                event_type="LOGIN_FAILURE",
                result=AuditResult.FAILURE,
                actor_id=user.id,
                actor_role=user.role.value,
                ip_hash=hash_ip(ip),
                risk_score=0.4,
                metadata={"attempts": user.failed_login_attempts},
            )
            return {"success": False, "error": "Invalid credentials"}

        # Reset failed attempts on successful password
        user.failed_login_attempts = 0

        if user.mfa_enabled:
            # Return partial state — MFA verification required
            pre_auth_token = secrets.token_urlsafe(32)
            return {
                "success": True,
                "mfa_required": True,
                "pre_auth_token": pre_auth_token,
                "user_id": user.id,
            }

        # No MFA — issue tokens directly
        return await self._issue_tokens(user, ip, device_id)

    async def verify_mfa(
        self,
        user_id: str,
        totp_code: str,
        ip: str = "",
        device_id: str = "",
    ) -> dict:
        """Verify TOTP MFA code and issue tokens if valid."""
        result = await self.db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()

        if not user or not user.mfa_secret_encrypted:
            return {"success": False, "error": "MFA not configured"}

        # Decrypt MFA secret
        from app.crypto.kms_interface import EncryptedBlob
        blob = EncryptedBlob.from_dict(
            {"ciphertext_b64": user.mfa_secret_encrypted, "key_reference": f"mfa:{user_id}"}
        )
        try:
            secret = self.kms.decrypt(blob, f"mfa:{user_id}").decode("utf-8")
        except Exception:
            return {"success": False, "error": "MFA decryption failed"}

        totp = pyotp.TOTP(secret)
        if not totp.verify(totp_code, valid_window=1):
            await self.audit.log(
                event_type="MFA_FAILURE",
                result=AuditResult.FAILURE,
                actor_id=user_id,
                ip_hash=hash_ip(ip),
                risk_score=0.5,
            )
            return {"success": False, "error": "Invalid MFA code"}

        await self.audit.log(
            event_type="MFA_SUCCESS",
            result=AuditResult.SUCCESS,
            actor_id=user_id,
            actor_role=user.role.value,
            ip_hash=hash_ip(ip),
        )
        return await self._issue_tokens(user, ip, device_id)

    async def _issue_tokens(self, user: User, ip: str, device_id: str) -> dict:
        """Issue access + refresh tokens for authenticated user."""
        access_token = create_access_token(
            subject=user.id,
            role=user.role.value,
            org_id=user.org_id,
        )
        refresh_token = create_refresh_token(subject=user.id)

        # Update last login
        user.last_login = datetime.now(timezone.utc)
        user.last_login_ip_hash = hash_ip(ip)

        await self.audit.log(
            event_type="LOGIN",
            result=AuditResult.SUCCESS,
            actor_id=user.id,
            actor_role=user.role.value,
            ip_hash=hash_ip(ip),
            device_id=device_id,
        )

        return {
            "success": True,
            "mfa_required": False,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "user": {
                "id": user.id,
                "username": user.username,
                "full_name": user.full_name,
                "role": user.role.value,
                "org_id": user.org_id,
                "mfa_enabled": user.mfa_enabled,
            },
        }

    async def setup_mfa(self, user_id: str) -> dict:
        """Generate and store MFA secret for a user."""
        result = await self.db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if not user:
            return {"success": False, "error": "User not found"}

        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=user.email, issuer_name=settings.mfa_issuer
        )

        # Encrypt and store MFA secret
        blob = self.kms.encrypt(secret.encode("utf-8"), f"mfa:{user_id}")
        user.mfa_secret_encrypted = blob.ciphertext_b64

        await self.audit.log(
            event_type="MFA_SETUP",
            result=AuditResult.SUCCESS,
            actor_id=user_id,
            actor_role=user.role.value,
        )

        return {
            "success": True,
            "secret": secret,
            "provisioning_uri": provisioning_uri,
            "message": "Scan QR code with authenticator app. Verify before enabling.",
        }

    async def enable_mfa(self, user_id: str, totp_code: str) -> dict:
        """Verify TOTP code and enable MFA for user."""
        result = await self.db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()

        if not user or not user.mfa_secret_encrypted:
            return {"success": False, "error": "MFA not set up"}

        from app.crypto.kms_interface import EncryptedBlob
        blob = EncryptedBlob.from_dict(
            {"ciphertext_b64": user.mfa_secret_encrypted, "key_reference": ""}
        )
        secret = self.kms.decrypt(blob, f"mfa:{user_id}").decode("utf-8")

        totp = pyotp.TOTP(secret)
        if not totp.verify(totp_code, valid_window=1):
            return {"success": False, "error": "Invalid MFA code — setup failed"}

        user.mfa_enabled = True
        await self.audit.log(
            event_type="MFA_ENABLED",
            result=AuditResult.SUCCESS,
            actor_id=user_id,
        )
        return {"success": True, "message": "MFA enabled successfully"}


# ── RBAC Permission Check ──────────────────────────────────────────────────────

# Role permission matrix
ROLE_PERMISSIONS: dict[str, set[str]] = {
    UserRoleEnum.SUPER_ADMIN.value: {
        "users:create", "users:read", "users:update", "users:delete",
        "orgs:manage", "exams:manage", "questions:manage",
        "audit:read", "security:manage", "incidents:manage",
        "release:approve", "candidates:manage", "system:admin",
        "break_glass:request", "break_glass:view", "break_glass:approve", "break_glass:revoke",
    },
    UserRoleEnum.EXAM_AUTHORITY.value: {
        "exams:create", "exams:read", "exams:update",
        "blueprint:create", "blueprint:read", "blueprint:update",
        "forms:generate", "forms:read",
        "candidates:read", "candidates:manage",
        "release:approve", "centres:read",
        "questions:read_metadata",
        "break_glass:request", "break_glass:view", "break_glass:approve", "break_glass:revoke",
    },
    UserRoleEnum.QUESTION_SETTER.value: {
        "questions:create", "questions:read_own", "questions:update_own",
        "questions:submit",
    },
    UserRoleEnum.REVIEWER.value: {
        "questions:read_assigned", "questions:review",
    },
    UserRoleEnum.MODERATOR.value: {
        "questions:read_assigned", "questions:approve", "questions:reject",
        "blueprint:read",
    },
    UserRoleEnum.SECURITY_OFFICER.value: {
        "security:read", "security:manage",
        "incidents:create", "incidents:manage",
        "audit:read", "sessions:revoke",
        "release:freeze", "forms:revoke",
        "users:lock",
        "break_glass:request", "break_glass:view", "break_glass:approve", "break_glass:revoke",
    },
    UserRoleEnum.RELEASE_AUTHORITY.value: {
        "release:approve", "release:read",
        "exams:read",
        "break_glass:approve", "break_glass:view",
    },
    UserRoleEnum.CENTRE_ADMIN.value: {
        "centres:manage_own", "candidates:read_own_centre",
        "sessions:read_own_centre",
    },
    UserRoleEnum.INVIGILATOR.value: {
        "sessions:read_own_centre", "security:report",
    },
    UserRoleEnum.CANDIDATE.value: {
        "exam:take", "session:read_own", "responses:submit_own",
    },
    UserRoleEnum.AUDITOR.value: {
        "audit:read", "security:read", "exams:read",
        "questions:read_metadata",
        "break_glass:view",
    },
}


def has_permission(role: str, permission: str) -> bool:
    """Check if a role has a specific permission."""
    perms = ROLE_PERMISSIONS.get(role, set())
    return permission in perms or "system:admin" in perms
