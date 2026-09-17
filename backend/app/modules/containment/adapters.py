"""
B-SEA Phase 3C-5E: Subsystem Execution Adapters
Conforming strictly to docs/BSEA_PHASE3C5E_ARCHITECTURE_REV04_1.md Sections 4, 6, 7.

Implements execution adapters with deterministic idempotency semantics:
- ACT_CAND_SESSION_TERM (LOW Risk)
- ACT_ACCT_DISABLE (HIGH Risk)
- ACT_Q_PREVENT_ASSIGN (HIGH Risk)
- ACT_CENTRE_RESTRICT (HIGH Risk)
- ACT_FORM_SUSPEND (CRITICAL Risk)
- ACT_CENTRE_SUSPEND (CRITICAL Risk)
- ACT_CRYPTO_REVOKE_MASTER (CRITICAL Risk)

Outcomes:
- EXECUTION_SUCCEEDED: Definite network/subsystem ack received.
- EXECUTION_FAILED: Definite rejection received from target.
- EXECUTION_UNKNOWN: Network timeout or connection drop (Never assume failure!).
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import time
from typing import Optional, Dict, Any, Tuple

from sqlalchemy import select, update
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
    ExecutionOutcome,
)
from app.crypto.kms_interface import get_kms


class ExecutionAdapterResult:
    def __init__(
        self,
        outcome: ExecutionOutcome,
        latency_ms: int,
        error_code: Optional[str] = None,
        error_message: Optional[str] = None,
        observed_snapshot: Optional[Dict[str, Any]] = None,
    ):
        self.outcome = outcome
        self.latency_ms = latency_ms
        self.error_code = error_code
        self.error_message = error_message
        self.observed_snapshot = observed_snapshot or {}


class SubsystemExecutionRegistry:
    """
    Registry of containment execution adapters.
    """

    # In-memory target state for cryptographic master key status simulation
    _master_key_disabled: bool = False
    # Mock failure triggers for fault-injection testing
    _force_timeout: bool = False
    _force_failure: bool = False

    @classmethod
    def set_fault_injection(cls, force_timeout: bool = False, force_failure: bool = False):
        cls._force_timeout = force_timeout
        cls._force_failure = force_failure

    @classmethod
    async def dispatch(
        cls,
        session: AsyncSession,
        action_type: ContainmentActionType,
        canonical_target_urn: str,
        external_operation_id: str,
        execution_lease_deadline: datetime,
    ) -> ExecutionAdapterResult:
        """
        Dispatch containment action to the appropriate subsystem adapter.
        """
        start_t = time.perf_counter()

        # Check Fault Injection
        if cls._force_timeout:
            # Simulate a network timeout exceeding lease
            return ExecutionAdapterResult(
                outcome=ExecutionOutcome.EXECUTION_UNKNOWN,
                latency_ms=int((time.perf_counter() - start_t) * 1000),
                error_code="ERR_NETWORK_TIMEOUT",
                error_message="Execution adapter network timeout waiting for subsystem acknowledgement.",
            )

        if cls._force_failure:
            return ExecutionAdapterResult(
                outcome=ExecutionOutcome.EXECUTION_FAILED,
                latency_ms=int((time.perf_counter() - start_t) * 1000),
                error_code="ERR_TARGET_REJECTED",
                error_message="Subsystem rejected execution command with HTTP 500.",
            )

        # Parse target ID from URN: urn:bsea:<target_type>:<target_id>
        parts = canonical_target_urn.split(":")
        target_id = parts[-1] if len(parts) >= 4 else canonical_target_urn

        try:
            if action_type == ContainmentActionType.ACT_CAND_SESSION_TERM:
                res = await cls._execute_session_term(session, target_id)
            elif action_type == ContainmentActionType.ACT_ACCT_DISABLE:
                res = await cls._execute_acct_disable(session, target_id)
            elif action_type == ContainmentActionType.ACT_Q_PREVENT_ASSIGN:
                res = await cls._execute_question_prevent_assign(session, target_id)
            elif action_type == ContainmentActionType.ACT_CENTRE_RESTRICT:
                res = await cls._execute_centre_restrict(session, target_id)
            elif action_type == ContainmentActionType.ACT_FORM_SUSPEND:
                res = await cls._execute_form_suspend(session, target_id)
            elif action_type == ContainmentActionType.ACT_CENTRE_SUSPEND:
                res = await cls._execute_centre_suspend(session, target_id)
            elif action_type == ContainmentActionType.ACT_CRYPTO_REVOKE_MASTER:
                res = await cls._execute_crypto_revoke_master(session, target_id)
            else:
                return ExecutionAdapterResult(
                    outcome=ExecutionOutcome.EXECUTION_FAILED,
                    latency_ms=int((time.perf_counter() - start_t) * 1000),
                    error_code="ERR_UNKNOWN_ACTION_TYPE",
                    error_message=f"No execution adapter registered for '{action_type}'.",
                )

            latency_ms = int((time.perf_counter() - start_t) * 1000)
            res.latency_ms = latency_ms
            return res

        except Exception as ex:
            latency_ms = int((time.perf_counter() - start_t) * 1000)
            return ExecutionAdapterResult(
                outcome=ExecutionOutcome.EXECUTION_UNKNOWN,
                latency_ms=latency_ms,
                error_code="ERR_ADAPTER_EXCEPTION",
                error_message=str(ex),
            )

    @classmethod
    async def _execute_session_term(cls, session: AsyncSession, session_id: str) -> ExecutionAdapterResult:
        """Terminate candidate exam session."""
        stmt = select(CandidateSession).where(CandidateSession.id == session_id)
        res = await session.execute(stmt)
        sess = res.scalar_one_or_none()
        if sess is None:
            # Idempotent: target not present in active sessions is already terminated
            return ExecutionAdapterResult(
                outcome=ExecutionOutcome.EXECUTION_SUCCEEDED,
                latency_ms=0,
                observed_snapshot={"status": "REVOKED", "target_found": False},
            )

        sess.status = SessionStatus.REVOKED
        await session.flush()
        return ExecutionAdapterResult(
            outcome=ExecutionOutcome.EXECUTION_SUCCEEDED,
            latency_ms=0,
            observed_snapshot={"status": "REVOKED", "target_found": True},
        )

    @classmethod
    async def _execute_acct_disable(cls, session: AsyncSession, user_id: str) -> ExecutionAdapterResult:
        """Disable user account."""
        stmt = select(User).where(User.id == user_id)
        res = await session.execute(stmt)
        user = res.scalar_one_or_none()
        if user is None:
            return ExecutionAdapterResult(
                outcome=ExecutionOutcome.EXECUTION_FAILED,
                latency_ms=0,
                error_code="ERR_USER_NOT_FOUND",
                error_message=f"User '{user_id}' does not exist.",
            )

        user.is_locked = True
        user.is_active = False
        await session.flush()
        return ExecutionAdapterResult(
            outcome=ExecutionOutcome.EXECUTION_SUCCEEDED,
            latency_ms=0,
            observed_snapshot={"is_locked": True, "is_active": False},
        )

    @classmethod
    async def _execute_question_prevent_assign(cls, session: AsyncSession, question_id: str) -> ExecutionAdapterResult:
        """Prevent question from being assigned in blueprints."""
        stmt = select(Question).where(Question.id == question_id)
        res = await session.execute(stmt)
        q = res.scalar_one_or_none()
        if q is None:
            return ExecutionAdapterResult(
                outcome=ExecutionOutcome.EXECUTION_FAILED,
                latency_ms=0,
                error_code="ERR_QUESTION_NOT_FOUND",
                error_message=f"Question '{question_id}' does not exist.",
            )

        # Set question status to quarantine / unassigned
        q.status = "FLAGGED_CONTAINED"
        await session.flush()
        return ExecutionAdapterResult(
            outcome=ExecutionOutcome.EXECUTION_SUCCEEDED,
            latency_ms=0,
            observed_snapshot={"status": "FLAGGED_CONTAINED", "is_assignable": False},
        )

    @classmethod
    async def _execute_centre_restrict(cls, session: AsyncSession, centre_id: str) -> ExecutionAdapterResult:
        """Restrict centre network capacity."""
        stmt = select(Centre).where(Centre.id == centre_id)
        res = await session.execute(stmt)
        c = res.scalar_one_or_none()
        if c is None:
            return ExecutionAdapterResult(
                outcome=ExecutionOutcome.EXECUTION_FAILED,
                latency_ms=0,
                error_code="ERR_CENTRE_NOT_FOUND",
                error_message=f"Centre '{centre_id}' does not exist.",
            )

        c.status = "RESTRICTED"
        await session.flush()
        return ExecutionAdapterResult(
            outcome=ExecutionOutcome.EXECUTION_SUCCEEDED,
            latency_ms=0,
            observed_snapshot={"status": "RESTRICTED"},
        )

    @classmethod
    async def _execute_form_suspend(cls, session: AsyncSession, form_id: str) -> ExecutionAdapterResult:
        """Suspend examination form variant."""
        stmt = select(ExamForm).where(ExamForm.id == form_id)
        res = await session.execute(stmt)
        form = res.scalar_one_or_none()
        if form is None:
            return ExecutionAdapterResult(
                outcome=ExecutionOutcome.EXECUTION_FAILED,
                latency_ms=0,
                error_code="ERR_FORM_NOT_FOUND",
                error_message=f"ExamForm '{form_id}' does not exist.",
            )

        form.is_active = False
        await session.flush()
        return ExecutionAdapterResult(
            outcome=ExecutionOutcome.EXECUTION_SUCCEEDED,
            latency_ms=0,
            observed_snapshot={"is_active": False, "status": "SUSPENDED"},
        )

    @classmethod
    async def _execute_centre_suspend(cls, session: AsyncSession, centre_id: str) -> ExecutionAdapterResult:
        """Suspend entire examination centre."""
        stmt = select(Centre).where(Centre.id == centre_id)
        res = await session.execute(stmt)
        c = res.scalar_one_or_none()
        if c is None:
            return ExecutionAdapterResult(
                outcome=ExecutionOutcome.EXECUTION_FAILED,
                latency_ms=0,
                error_code="ERR_CENTRE_NOT_FOUND",
                error_message=f"Centre '{centre_id}' does not exist.",
            )

        c.status = "SUSPENDED"
        await session.flush()
        return ExecutionAdapterResult(
            outcome=ExecutionOutcome.EXECUTION_SUCCEEDED,
            latency_ms=0,
            observed_snapshot={"status": "SUSPENDED"},
        )

    @classmethod
    async def _execute_crypto_revoke_master(cls, session: AsyncSession, target_id: str) -> ExecutionAdapterResult:
        """Emergency invalidation of slot master CMK."""
        cls._master_key_disabled = True
        return ExecutionAdapterResult(
            outcome=ExecutionOutcome.EXECUTION_SUCCEEDED,
            latency_ms=0,
            observed_snapshot={"key_state": "DISABLED", "decrypt_active": False},
        )
