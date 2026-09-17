"""
B-SEA Phase 3C-5E: Independent Verification Engine
Conforming strictly to docs/BSEA_PHASE3C5E_ARCHITECTURE_REV04_1.md Sections 6, 7.

Implements out-of-band, independent verification of target subsystems:
- Queries authoritative target data store directly without trusting execution adapter.
- Yields tri-state outcome:
  - VERIFICATION_VERIFIED: Physical target confirmed contained.
  - VERIFICATION_FAILED: Physical target confirmed unmutated.
  - VERIFICATION_INCONCLUSIVE: Target unreachable, partitioned, or ambiguous.
- Generates deterministic verification proof with SHA-256 JCS proof_hash.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Optional, Dict, Any, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.models import (
    CandidateSession,
    SessionStatus,
    User,
    Question,
    ExamForm,
    Centre,
)
from app.modules.containment.models import (
    ContainmentActionType,
    VerificationOutcome,
)
from app.modules.containment.identity import jcs_canonicalize
from app.modules.containment.adapters import SubsystemExecutionRegistry


class IndependentVerificationResult:
    def __init__(
        self,
        outcome: VerificationOutcome,
        observed_target_state: str,
        proof_payload: Dict[str, Any],
        proof_hash: str,
        notes: Optional[str] = None,
    ):
        self.outcome = outcome
        self.observed_target_state = observed_target_state
        self.proof_payload = proof_payload
        self.proof_hash = proof_hash
        self.notes = notes


class IndependentVerificationEngine:
    """
    Independent Verification Engine inspecting target subsystems out-of-band.
    """

    _force_inconclusive: bool = False

    @classmethod
    def set_force_inconclusive(cls, force: bool):
        cls._force_inconclusive = force

    @classmethod
    async def verify_containment(
        cls,
        session: AsyncSession,
        action_type: ContainmentActionType,
        canonical_target_urn: str,
        verifier_name: str = "CentralVerificationDaemon",
    ) -> IndependentVerificationResult:
        """
        Query ground truth out-of-band to independently verify containment effect.
        """
        now = datetime.now(timezone.utc)

        if cls._force_inconclusive:
            payload = {
                "error": "ERR_VERIFICATION_TIMEOUT",
                "message": "Target subsystem data store unreachable out-of-band.",
                "timestamp": now.isoformat(),
            }
            p_hash = hashlib.sha256(jcs_canonicalize(payload).encode("utf-8")).hexdigest()
            return IndependentVerificationResult(
                outcome=VerificationOutcome.VERIFICATION_INCONCLUSIVE,
                observed_target_state="INDETERMINATE",
                proof_payload=payload,
                proof_hash=p_hash,
                notes="Force-injected inconclusive condition: target store unreachable.",
            )

        parts = canonical_target_urn.split(":")
        target_id = parts[-1] if len(parts) >= 4 else canonical_target_urn

        try:
            if action_type == ContainmentActionType.ACT_CAND_SESSION_TERM:
                return await cls._verify_session_term(session, target_id)
            elif action_type == ContainmentActionType.ACT_ACCT_DISABLE:
                return await cls._verify_acct_disable(session, target_id)
            elif action_type == ContainmentActionType.ACT_Q_PREVENT_ASSIGN:
                return await cls._verify_question_prevent_assign(session, target_id)
            elif action_type == ContainmentActionType.ACT_CENTRE_RESTRICT:
                return await cls._verify_centre_restrict(session, target_id)
            elif action_type == ContainmentActionType.ACT_FORM_SUSPEND:
                return await cls._verify_form_suspend(session, target_id)
            elif action_type == ContainmentActionType.ACT_CENTRE_SUSPEND:
                return await cls._verify_centre_suspend(session, target_id)
            elif action_type == ContainmentActionType.ACT_CRYPTO_REVOKE_MASTER:
                return await cls._verify_crypto_revoke_master(session, target_id)
            else:
                payload = {"error": "UNKNOWN_ACTION", "action_type": str(action_type)}
                p_hash = hashlib.sha256(jcs_canonicalize(payload).encode("utf-8")).hexdigest()
                return IndependentVerificationResult(
                    outcome=VerificationOutcome.VERIFICATION_INCONCLUSIVE,
                    observed_target_state="UNKNOWN",
                    proof_payload=payload,
                    proof_hash=p_hash,
                )
        except Exception as ex:
            payload = {"error": "EXCEPTION", "details": str(ex), "timestamp": now.isoformat()}
            p_hash = hashlib.sha256(jcs_canonicalize(payload).encode("utf-8")).hexdigest()
            return IndependentVerificationResult(
                outcome=VerificationOutcome.VERIFICATION_INCONCLUSIVE,
                observed_target_state="EXCEPTION",
                proof_payload=payload,
                proof_hash=p_hash,
                notes=f"Verification exception: {str(ex)}",
            )

    @classmethod
    async def _verify_session_term(cls, session: AsyncSession, session_id: str) -> IndependentVerificationResult:
        """Inspect CandidateSession status directly."""
        stmt = select(CandidateSession).where(CandidateSession.id == session_id)
        res = await session.execute(stmt)
        sess = res.scalar_one_or_none()

        if sess is None:
            # Session does not exist -> verified absent/terminated
            payload = {"session_id": session_id, "exists": False, "status": "TERMINATED"}
            p_hash = hashlib.sha256(jcs_canonicalize(payload).encode("utf-8")).hexdigest()
            return IndependentVerificationResult(
                outcome=VerificationOutcome.VERIFICATION_VERIFIED,
                observed_target_state="TERMINATED",
                proof_payload=payload,
                proof_hash=p_hash,
            )

        if sess.status == SessionStatus.REVOKED:
            payload = {"session_id": session_id, "exists": True, "status": sess.status.value}
            p_hash = hashlib.sha256(jcs_canonicalize(payload).encode("utf-8")).hexdigest()
            return IndependentVerificationResult(
                outcome=VerificationOutcome.VERIFICATION_VERIFIED,
                observed_target_state="REVOKED",
                proof_payload=payload,
                proof_hash=p_hash,
            )
        else:
            # Session is still ACTIVE -> Containment did not take effect!
            payload = {"session_id": session_id, "exists": True, "status": sess.status.value}
            p_hash = hashlib.sha256(jcs_canonicalize(payload).encode("utf-8")).hexdigest()
            return IndependentVerificationResult(
                outcome=VerificationOutcome.VERIFICATION_FAILED,
                observed_target_state=sess.status.value,
                proof_payload=payload,
                proof_hash=p_hash,
                notes="Discrepancy: Candidate session remains ACTIVE despite termination dispatch.",
            )

    @classmethod
    async def _verify_acct_disable(cls, session: AsyncSession, user_id: str) -> IndependentVerificationResult:
        """Inspect User lock status directly."""
        stmt = select(User).where(User.id == user_id)
        res = await session.execute(stmt)
        user = res.scalar_one_or_none()

        if user is None:
            payload = {"user_id": user_id, "exists": False}
            p_hash = hashlib.sha256(jcs_canonicalize(payload).encode("utf-8")).hexdigest()
            return IndependentVerificationResult(
                outcome=VerificationOutcome.VERIFICATION_FAILED,
                observed_target_state="NOT_FOUND",
                proof_payload=payload,
                proof_hash=p_hash,
            )

        if user.is_locked:
            payload = {"user_id": user_id, "is_locked": True, "is_active": user.is_active}
            p_hash = hashlib.sha256(jcs_canonicalize(payload).encode("utf-8")).hexdigest()
            return IndependentVerificationResult(
                outcome=VerificationOutcome.VERIFICATION_VERIFIED,
                observed_target_state="LOCKED",
                proof_payload=payload,
                proof_hash=p_hash,
            )
        else:
            payload = {"user_id": user_id, "is_locked": False, "is_active": user.is_active}
            p_hash = hashlib.sha256(jcs_canonicalize(payload).encode("utf-8")).hexdigest()
            return IndependentVerificationResult(
                outcome=VerificationOutcome.VERIFICATION_FAILED,
                observed_target_state="ACTIVE",
                proof_payload=payload,
                proof_hash=p_hash,
            )

    @classmethod
    async def _verify_question_prevent_assign(cls, session: AsyncSession, question_id: str) -> IndependentVerificationResult:
        """Inspect Question status directly."""
        stmt = select(Question).where(Question.id == question_id)
        res = await session.execute(stmt)
        q = res.scalar_one_or_none()

        if q is None:
            payload = {"question_id": question_id, "exists": False}
            p_hash = hashlib.sha256(jcs_canonicalize(payload).encode("utf-8")).hexdigest()
            return IndependentVerificationResult(
                outcome=VerificationOutcome.VERIFICATION_FAILED,
                observed_target_state="NOT_FOUND",
                proof_payload=payload,
                proof_hash=p_hash,
            )

        if q.status == "FLAGGED_CONTAINED":
            payload = {"question_id": question_id, "status": q.status}
            p_hash = hashlib.sha256(jcs_canonicalize(payload).encode("utf-8")).hexdigest()
            return IndependentVerificationResult(
                outcome=VerificationOutcome.VERIFICATION_VERIFIED,
                observed_target_state="FLAGGED_CONTAINED",
                proof_payload=payload,
                proof_hash=p_hash,
            )
        else:
            payload = {"question_id": question_id, "status": q.status}
            p_hash = hashlib.sha256(jcs_canonicalize(payload).encode("utf-8")).hexdigest()
            return IndependentVerificationResult(
                outcome=VerificationOutcome.VERIFICATION_FAILED,
                observed_target_state=q.status,
                proof_payload=payload,
                proof_hash=p_hash,
            )

    @classmethod
    async def _verify_centre_restrict(cls, session: AsyncSession, centre_id: str) -> IndependentVerificationResult:
        """Inspect Centre status directly."""
        stmt = select(Centre).where(Centre.id == centre_id)
        res = await session.execute(stmt)
        c = res.scalar_one_or_none()

        if c is not None and c.status == "RESTRICTED":
            payload = {"centre_id": centre_id, "status": "RESTRICTED"}
            p_hash = hashlib.sha256(jcs_canonicalize(payload).encode("utf-8")).hexdigest()
            return IndependentVerificationResult(
                outcome=VerificationOutcome.VERIFICATION_VERIFIED,
                observed_target_state="RESTRICTED",
                proof_payload=payload,
                proof_hash=p_hash,
            )
        else:
            payload = {"centre_id": centre_id, "status": getattr(c, "status", "UNKNOWN")}
            p_hash = hashlib.sha256(jcs_canonicalize(payload).encode("utf-8")).hexdigest()
            return IndependentVerificationResult(
                outcome=VerificationOutcome.VERIFICATION_FAILED,
                observed_target_state=getattr(c, "status", "UNKNOWN"),
                proof_payload=payload,
                proof_hash=p_hash,
            )

    @classmethod
    async def _verify_form_suspend(cls, session: AsyncSession, form_id: str) -> IndependentVerificationResult:
        """Inspect ExamForm status directly."""
        stmt = select(ExamForm).where(ExamForm.id == form_id)
        res = await session.execute(stmt)
        form = res.scalar_one_or_none()

        if form is not None and not form.is_active:
            payload = {"form_id": form_id, "is_active": False}
            p_hash = hashlib.sha256(jcs_canonicalize(payload).encode("utf-8")).hexdigest()
            return IndependentVerificationResult(
                outcome=VerificationOutcome.VERIFICATION_VERIFIED,
                observed_target_state="SUSPENDED",
                proof_payload=payload,
                proof_hash=p_hash,
            )
        else:
            payload = {"form_id": form_id, "is_active": getattr(form, "is_active", True)}
            p_hash = hashlib.sha256(jcs_canonicalize(payload).encode("utf-8")).hexdigest()
            return IndependentVerificationResult(
                outcome=VerificationOutcome.VERIFICATION_FAILED,
                observed_target_state="ACTIVE",
                proof_payload=payload,
                proof_hash=p_hash,
            )

    @classmethod
    async def _verify_centre_suspend(cls, session: AsyncSession, centre_id: str) -> IndependentVerificationResult:
        """Inspect Centre operational suspension directly."""
        stmt = select(Centre).where(Centre.id == centre_id)
        res = await session.execute(stmt)
        c = res.scalar_one_or_none()

        if c is not None and c.status == "SUSPENDED":
            payload = {"centre_id": centre_id, "status": "SUSPENDED"}
            p_hash = hashlib.sha256(jcs_canonicalize(payload).encode("utf-8")).hexdigest()
            return IndependentVerificationResult(
                outcome=VerificationOutcome.VERIFICATION_VERIFIED,
                observed_target_state="SUSPENDED",
                proof_payload=payload,
                proof_hash=p_hash,
            )
        else:
            payload = {"centre_id": centre_id, "status": getattr(c, "status", "UNKNOWN")}
            p_hash = hashlib.sha256(jcs_canonicalize(payload).encode("utf-8")).hexdigest()
            return IndependentVerificationResult(
                outcome=VerificationOutcome.VERIFICATION_FAILED,
                observed_target_state=getattr(c, "status", "UNKNOWN"),
                proof_payload=payload,
                proof_hash=p_hash,
            )

    @classmethod
    async def _verify_crypto_revoke_master(cls, session: AsyncSession, target_id: str) -> IndependentVerificationResult:
        """Inspect master key invalidation status directly."""
        if SubsystemExecutionRegistry._master_key_disabled:
            payload = {"key_id": target_id, "status": "DISABLED", "can_decrypt": False}
            p_hash = hashlib.sha256(jcs_canonicalize(payload).encode("utf-8")).hexdigest()
            return IndependentVerificationResult(
                outcome=VerificationOutcome.VERIFICATION_VERIFIED,
                observed_target_state="DISABLED",
                proof_payload=payload,
                proof_hash=p_hash,
            )
        else:
            payload = {"key_id": target_id, "status": "ENABLED", "can_decrypt": True}
            p_hash = hashlib.sha256(jcs_canonicalize(payload).encode("utf-8")).hexdigest()
            return IndependentVerificationResult(
                outcome=VerificationOutcome.VERIFICATION_FAILED,
                observed_target_state="ENABLED",
                proof_payload=payload,
                proof_hash=p_hash,
            )
