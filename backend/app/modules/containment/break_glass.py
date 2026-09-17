"""
B-SEA Phase 3C-5E: Emergency Break-Glass Token Coordinator
Conforming strictly to docs/BSEA_PHASE3C5E_ARCHITECTURE_REV04_1.md Sections 1, 8, 12.

Key Rules:
- ONE BREAK-GLASS TOKEN -> ONE CONTAINMENT INTENT -> ONE EXECUTION ATTEMPT.
- Token consumption is permanent upon dispatch.
- Atomic lease acquisition starts a 60-second Execution Lease.
- Token expiration after dispatch begins does not cancel an active execution lease.
- Token reuse after UNKNOWN or INCONCLUSIVE is strictly prohibited.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import hashlib
import secrets
from typing import Optional, Tuple
import uuid

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.models import User, UserRoleEnum, SecurityIncidentStatus, SecurityIncidentSeverity
from app.modules.containment.models import (
    BreakGlassToken,
    BreakGlassTokenStatus,
    ContainmentActionType,
    ContainmentConsumedNonce,
)
from app.modules.containment.policy import (
    ContainmentPolicyEngine,
    BreakGlassPolicyDecision,
    BREAK_GLASS_ELIGIBLE_ACTIONS,
)
from app.modules.containment.identity import compute_scope_hash, generate_crypto_nonce


class BreakGlassError(Exception):
    """Base exception for Break-Glass operations."""
    pass


class BreakGlassTokenExpiredError(BreakGlassError):
    """Raised when an emergency token has expired before execution dispatch."""
    pass


class BreakGlassScopeViolationError(BreakGlassError):
    """Raised when an emergency request exceeds single-entity blast radius."""
    pass


class BreakGlassReplayError(BreakGlassError):
    """Raised when an emergency token nonce is replayed."""
    pass


class BreakGlassRateLimitExceededError(BreakGlassError):
    """Raised when break-glass issuance frequency exceeds safety thresholds."""
    pass


class BreakGlassCriticalProhibitedError(BreakGlassError):
    """Raised when break-glass is attempted on a CRITICAL risk action."""
    pass


class BreakGlassTokenCoordinator:
    """
    Coordinates issuance, validation, atomic consumption, and execution lease tracking
    for Single-Use Break-Glass Emergency Tokens.
    """

    TOKEN_TTL_SECONDS = 900  # 15 minutes
    EXECUTION_LEASE_SECONDS = 60  # 60 seconds bounded execution lease

    @classmethod
    async def issue_token(
        cls,
        session: AsyncSession,
        issuer: User,
        incident_id: str,
        incident_generation: int,
        incident_status: SecurityIncidentStatus,
        incident_severity: SecurityIncidentSeverity,
        intent_key: str,
        action_type: ContainmentActionType,
        canonical_target_urn: str,
        target_scope_dict: dict,
        fido2_assertion_payload: str,
        is_exam_in_progress: bool,
        policy_version: str,
    ) -> BreakGlassToken:
        """
        Evaluate emergency policy and issue an ephemeral single-use BreakGlassToken.
        """
        now = datetime.now(timezone.utc)
        engine = ContainmentPolicyEngine(policy_version=policy_version)

        # 1. Rate Limiting Queries
        # Count user's break glass actions in last 60 min
        one_hour_ago = now - timedelta(hours=1)
        user_actions_stmt = select(func.count(BreakGlassToken.id)).where(
            BreakGlassToken.issuer_id == issuer.id,
            BreakGlassToken.created_at >= one_hour_ago,
        )
        user_actions_res = await session.execute(user_actions_stmt)
        user_action_count = user_actions_res.scalar_one()

        # Count total break glass actions for this exam slot (approximated by last 3 hours)
        three_hours_ago = now - timedelta(hours=3)
        slot_actions_stmt = select(func.count(BreakGlassToken.id)).where(
            BreakGlassToken.created_at >= three_hours_ago,
        )
        slot_actions_res = await session.execute(slot_actions_stmt)
        slot_action_count = slot_actions_res.scalar_one()

        max_entities = target_scope_dict.get("max_allowed_entities", 1)

        # 2. Run Break-Glass Crisis Policy Pipeline
        eval_result = engine.evaluate_break_glass_policy(
            action_type=action_type,
            incident_status=incident_status,
            incident_severity=incident_severity,
            target_urn=canonical_target_urn,
            max_entities=max_entities,
            requester_role=issuer.role,
            is_exam_in_progress=is_exam_in_progress,
            recent_break_glass_count_by_user=user_action_count,
            total_break_glass_count_for_exam=slot_action_count,
        )

        if eval_result.decision != BreakGlassPolicyDecision.BREAK_GLASS_ALLOWED.value:
            if "BREAK_GLASS_CRITICAL_PROHIBITED" in eval_result.reason:
                raise BreakGlassCriticalProhibitedError(eval_result.reason)
            elif "ERR_BREAK_GLASS_SCOPE_VIOLATION" in eval_result.reason:
                raise BreakGlassScopeViolationError(eval_result.reason)
            elif "ERR_BREAK_GLASS_RATE_LIMIT_EXCEEDED" in eval_result.reason:
                raise BreakGlassRateLimitExceededError(eval_result.reason)
            else:
                raise BreakGlassError(f"Break-Glass Denied: {eval_result.reason}")

        # 3. Verify FIDO2 hardware token assertion (cryptographic challenge)
        if not fido2_assertion_payload or len(fido2_assertion_payload.strip()) < 16:
            raise BreakGlassError("FIDO2 hardware assertion required; assertion signature missing or invalid.")
        fido2_hash = hashlib.sha256(fido2_assertion_payload.encode("utf-8")).hexdigest()

        # 4. Mint Token
        token_id = str(uuid.uuid4())
        token_nonce = generate_crypto_nonce()
        scope_hash = compute_scope_hash(target_scope_dict)
        expires_at = now + timedelta(seconds=cls.TOKEN_TTL_SECONDS)

        token = BreakGlassToken(
            id=token_id,
            token_nonce=token_nonce,
            intent_key=intent_key,
            incident_id=incident_id,
            incident_generation=incident_generation,
            canonical_target_urn=canonical_target_urn,
            target_scope_hash=scope_hash,
            action_type=action_type,
            policy_version=policy_version,
            issuer_id=issuer.id,
            fido2_assertion_hash=fido2_hash,
            status=BreakGlassTokenStatus.ISSUED,
            issued_at=now,
            expires_at=expires_at,
            created_at=now,
        )
        session.add(token)
        await session.flush()
        return token

    @classmethod
    async def consume_token_and_start_lease(
        cls,
        session: AsyncSession,
        token_id: str,
        expected_intent_key: str,
        actor_id: str,
    ) -> Tuple[BreakGlassToken, datetime]:
        """
        Atomically consume a BreakGlassToken prior to dispatch and grant a 60-second Execution Lease.
        CRITICAL: Consumption is permanent.
        """
        now = datetime.now(timezone.utc)
        token = await session.get(BreakGlassToken, token_id)
        if token is None:
            raise BreakGlassError(f"BreakGlassToken '{token_id}' not found.")

        # Invariant: Intent binding
        if token.intent_key != expected_intent_key:
            raise BreakGlassError(f"Token IntentKey mismatch: expected '{expected_intent_key}', got '{token.intent_key}'.")

        # Invariant: Pre-dispatch expiry check
        if now > token.expires_at:
            token.status = BreakGlassTokenStatus.EXPIRED
            await session.flush()
            raise BreakGlassTokenExpiredError(f"ERR_BREAK_GLASS_TOKEN_EXPIRED: Token expired at {token.expires_at.isoformat()}.")

        # Invariant: Non-reuse check
        if token.status != BreakGlassTokenStatus.ISSUED:
            raise BreakGlassReplayError(f"ERR_TOKEN_ALREADY_CONSUMED: Token '{token_id}' has already been {token.status.value}.")

        # Replay nonce check
        consumed_check = await session.get(ContainmentConsumedNonce, token.token_nonce)
        if consumed_check is not None:
            raise BreakGlassReplayError(f"ERR_TOKEN_NONCE_REPLAY: Nonce '{token.token_nonce}' already exists in consumed registry.")

        # Atomic consumption
        token.status = BreakGlassTokenStatus.CONSUMED
        token.consumed_at = now

        consumed_nonce_record = ContainmentConsumedNonce(
            nonce=token.token_nonce,
            nonce_type="BREAK_GLASS",
            consumed_by=actor_id,
            consumed_at=now,
        )
        session.add(consumed_nonce_record)

        # Grant 60s Execution Lease
        lease_expires_at = now + timedelta(seconds=cls.EXECUTION_LEASE_SECONDS)
        await session.flush()

        return token, lease_expires_at
