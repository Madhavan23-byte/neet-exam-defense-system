"""
B-SEA Phase 3C-5E: Two-Person Control Quorum & Authorization Subsystem
Conforming strictly to docs/BSEA_PHASE3C5E_ARCHITECTURE_REV04_1.md Sections 1, 2, 8, 13.

Enforces:
- Invariant I-01: Requester / Approver Separation (No self-approval; raises DualControlSelfApprovalError).
- Invariant I-07: Replay Protection on auth_nonce via containment_consumed_nonces.
- Invariant I-09: Dual Authorization Quorum for HIGH and CRITICAL risk tiers.
- Bounded 300-second Authorization TTL.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Optional, List, Tuple
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.models import User, UserRoleEnum
from app.modules.containment.models import (
    ContainmentRequest,
    ContainmentAuthorization,
    ContainmentActionRisk,
    ContainmentConsumedNonce,
)


class AuthorizationError(Exception):
    """Base exception for containment authorization failures."""
    pass


class DualControlSelfApprovalError(AuthorizationError):
    """Raised when requester attempts to approve their own containment request (Invariant I-01)."""
    pass


class InsufficientQuorumError(AuthorizationError):
    """Raised when the approver lacks the requisite role or quorum is unfulfilled (Invariant I-09)."""
    pass


class AuthorizationExpiredError(AuthorizationError):
    """Raised when an authorization is presented after its TTL has expired."""
    pass


class ReplayAttackError(AuthorizationError):
    """Raised when an authorization nonce has already been consumed (Invariant I-07)."""
    pass


class AuthorizationService:
    """
    Two-Person Control Quorum Authorization Service.
    """

    AUTHORIZATION_TTL_SECONDS = 300  # 5 minutes

    @staticmethod
    async def verify_and_record_authorization(
        session: AsyncSession,
        request: ContainmentRequest,
        approver: User,
        risk_tier: ContainmentActionRisk,
        auth_nonce: str,
        signature: str,
        is_break_glass: bool = False,
        break_glass_token_id: Optional[str] = None,
    ) -> ContainmentAuthorization:
        """
        Validate and persist a cryptographic authorization signature.
        """
        now = datetime.now(timezone.utc)

        # 1. Invariant I-07: Replay Protection via containment_consumed_nonces (Checked FIRST)
        consumed_check = await session.get(ContainmentConsumedNonce, auth_nonce)
        if consumed_check is not None:
            raise ReplayAttackError(
                f"ReplayAttackError: Authorization nonce '{auth_nonce}' has already been consumed."
            )

        # 2. Invariant I-01: Requester / Approver Separation (strictly applies to HIGH and CRITICAL risk tiers)
        if not is_break_glass and risk_tier in {ContainmentActionRisk.HIGH, ContainmentActionRisk.CRITICAL} and request.requester_id == approver.id:
            raise DualControlSelfApprovalError(
                f"DualControlSelfApprovalError: Requester '{approver.id}' cannot approve their own containment request."
            )

        # 3. Check for duplicate approver on the same request
        existing_approvals = await session.execute(
            select(ContainmentAuthorization).where(ContainmentAuthorization.request_id == request.id)
        )
        existing_list = existing_approvals.scalars().all()
        for ea in existing_list:
            if ea.approver_id == approver.id:
                raise DualControlSelfApprovalError(
                    f"Approver '{approver.id}' has already authorized request '{request.id}'."
                )

        # 4. Role Quorum Validation
        if risk_tier == ContainmentActionRisk.CRITICAL:
            if approver.role != UserRoleEnum.SUPER_ADMIN:
                raise InsufficientQuorumError(
                    f"CRITICAL risk actions strictly mandate SUPER_ADMIN authorization (approver is '{approver.role}')."
                )
        elif risk_tier == ContainmentActionRisk.HIGH:
            valid_roles = {UserRoleEnum.SECURITY_OFFICER, UserRoleEnum.SUPER_ADMIN}
            if approver.role not in valid_roles:
                raise InsufficientQuorumError(
                    f"HIGH risk actions mandate SECURITY_OFFICER or SUPER_ADMIN authorization (approver is '{approver.role}')."
                )

        # 5. Persist authorization
        expires_at = now + timedelta(seconds=AuthorizationService.AUTHORIZATION_TTL_SECONDS)
        auth = ContainmentAuthorization(
            request_id=request.id,
            approver_id=approver.id,
            auth_nonce=auth_nonce,
            signature=signature,
            is_break_glass=is_break_glass,
            break_glass_token_id=break_glass_token_id,
            expires_at=expires_at,
            created_at=now,
        )
        session.add(auth)

        # Mark nonce consumed
        consumed_nonce_record = ContainmentConsumedNonce(
            nonce=auth_nonce,
            nonce_type="AUTH",
            consumed_by=approver.id,
            consumed_at=now,
        )
        session.add(consumed_nonce_record)
        await session.flush()

        return auth

    @staticmethod
    def is_quorum_satisfied(
        risk_tier: ContainmentActionRisk,
        authorizations: List[ContainmentAuthorization],
        requester_id: str,
    ) -> bool:
        """
        Evaluate whether the collected authorizations satisfy the mandatory quorum.
        """
        now = datetime.now(timezone.utc)
        valid_auths = [a for a in authorizations if a.expires_at >= now]

        # Break-Glass override satisfies quorum if single valid break-glass authorization exists
        if any(a.is_break_glass for a in valid_auths):
            return True

        if risk_tier in {ContainmentActionRisk.LOW, ContainmentActionRisk.MEDIUM}:
            # Single authorization required
            return len(valid_auths) >= 1

        elif risk_tier == ContainmentActionRisk.HIGH:
            # Dual authorization: Requester + 1 distinct approver, OR 2 distinct approvers
            distinct_principals = set(a.approver_id for a in valid_auths)
            distinct_principals.add(requester_id)
            return len(distinct_principals) >= 2 and len(valid_auths) >= 1

        elif risk_tier == ContainmentActionRisk.CRITICAL:
            # Dual Super-Admin: strictly requires 2 distinct approvers
            distinct_approvers = set(a.approver_id for a in valid_auths)
            return len(distinct_approvers) >= 2
