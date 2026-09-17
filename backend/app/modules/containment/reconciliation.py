"""
B-SEA Phase 3C-5E: Reconciliation Daemon & Quarantine Manager
Conforming strictly to docs/BSEA_PHASE3C5E_ARCHITECTURE_REV04_1.md Sections 6, 7.

Key Capabilities:
1. Reconciles external mutations that succeeded when PostgreSQL transaction rolled back (TC-GATE-22, 29).
2. Manages Emergency Containment Quarantine Queue for VERIFICATION_INCONCLUSIVE outcomes (TC-GATE-32).
3. Enforces UNKNOWN -> VERIFY BEFORE RETRY (Never blindly redispatch!).
4. Handles manual Security Officer attestations (ATTEST_MANUAL_CONTAINED / ATTEST_MANUAL_FAILED).
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Optional, Dict, Any, List

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.models import User, UserRoleEnum
from app.modules.containment.models import (
    ContainmentRequest,
    ContainmentRequestStatus,
    ContainmentExecutionRecord,
    ContainmentVerificationProof,
    ExecutionOutcome,
    VerificationOutcome,
    ContainmentActionType,
)
from app.modules.containment.verifier import (
    IndependentVerificationEngine,
    IndependentVerificationResult,
)
from app.modules.containment.identity import jcs_canonicalize
from app.modules.audit.service import AuditService


class ReconciliationService:
    """
    Reconciliation Daemon and Quarantine Management Service.
    """

    @classmethod
    async def reconcile_external_mutation(
        cls,
        session: AsyncSession,
        request_id: str,
        external_operation_id: str,
        action_type: ContainmentActionType,
        canonical_target_urn: str,
        audit_service: AuditService,
    ) -> Optional[ContainmentExecutionRecord]:
        """
        Reconstruct and reconcile an execution record when PostgreSQL rolled back
        after the external adapter may have mutated physical target state.
        (TC-GATE-22, TC-GATE-29)
        """
        now = datetime.now(timezone.utc)

        # 1. Query target subsystem ground truth out-of-band
        verif_res = await IndependentVerificationEngine.verify_containment(
            session=session,
            action_type=action_type,
            canonical_target_urn=canonical_target_urn,
            verifier_name="ReconciliationVerifier",
        )

        # 2. Check if an execution record already exists in DB
        stmt = select(ContainmentExecutionRecord).where(
            ContainmentExecutionRecord.external_operation_id == external_operation_id
        )
        res = await session.execute(stmt)
        exec_record = res.scalar_one_or_none()

        if verif_res.outcome == VerificationOutcome.VERIFICATION_VERIFIED:
            # Physical mutation occurred! Reconstruct DB records without redispatching!
            if exec_record is None:
                exec_record = ContainmentExecutionRecord(
                    request_id=request_id,
                    external_operation_id=external_operation_id,
                    adapter_name="ReconstructedAdapter",
                    raw_outcome=ExecutionOutcome.EXECUTION_SUCCEEDED,
                    latency_ms=0,
                    started_at=now,
                    completed_at=now,
                    created_at=now,
                )
                session.add(exec_record)
                await session.flush()

            # Record verification proof
            proof = ContainmentVerificationProof(
                execution_id=exec_record.id,
                verifier_name="ReconciliationVerifier",
                verification_outcome=VerificationOutcome.VERIFICATION_VERIFIED,
                observed_target_state=verif_res.observed_target_state,
                proof_hash=verif_res.proof_hash,
                proof_payload=verif_res.proof_payload,
                verified_at=now,
                created_at=now,
            )
            session.add(proof)

            # Update request status to VERIFIED
            req = await session.get(ContainmentRequest, request_id)
            if req:
                req.status = ContainmentRequestStatus.VERIFIED
            await session.flush()

            # Log Mode B reconciliation audit record
            await audit_service.log_security_event(
                event_type="CONTAINMENT_RECONCILIATION_CORRECTED",
                resource_type="containment_request",
                resource_id=request_id,
                action="RECONCILE_EXTERNAL_MUTATION",
                metadata={
                    "external_operation_id": external_operation_id,
                    "canonical_target_urn": canonical_target_urn,
                    "reconciliation_verdict": "PHYSICAL_MUTATION_RECONSTRUCTED",
                },
                risk_score=0.5,
            )
            return exec_record

        elif verif_res.outcome == VerificationOutcome.VERIFICATION_FAILED:
            # Target is unmutated; update record to FAILED
            if exec_record:
                exec_record.raw_outcome = ExecutionOutcome.EXECUTION_FAILED
            req = await session.get(ContainmentRequest, request_id)
            if req:
                req.status = ContainmentRequestStatus.FAILED
            await session.flush()
            return exec_record

        else:
            # Inconclusive -> Quarantine
            req = await session.get(ContainmentRequest, request_id)
            if req:
                req.status = ContainmentRequestStatus.QUARANTINED
            await session.flush()
            return exec_record

    @classmethod
    async def submit_manual_attestation(
        cls,
        session: AsyncSession,
        request_id: str,
        officer: User,
        attestation_status: str,  # 'ATTEST_MANUAL_CONTAINED' or 'ATTEST_MANUAL_FAILED'
        notes: str,
        audit_service: AuditService,
    ) -> ContainmentRequest:
        """
        Operator handling for QUARANTINED / INCONCLUSIVE containment requests.
        (TC-GATE-32)
        """
        now = datetime.now(timezone.utc)
        if officer.role not in {UserRoleEnum.SECURITY_OFFICER, UserRoleEnum.SUPER_ADMIN}:
            raise PermissionError("Only SECURITY_OFFICER or SUPER_ADMIN may submit manual containment attestation.")

        req = await session.get(ContainmentRequest, request_id)
        if req is None:
            raise ValueError(f"ContainmentRequest '{request_id}' not found.")

        # Update verification proof with manual attestation
        # Find latest execution record
        stmt = (
            select(ContainmentExecutionRecord)
            .where(ContainmentExecutionRecord.request_id == request_id)
            .order_by(ContainmentExecutionRecord.created_at.desc())
        )
        res = await session.execute(stmt)
        exec_record = res.scalars().first()

        if exec_record:
            stmt_proof = select(ContainmentVerificationProof).where(
                ContainmentVerificationProof.execution_id == exec_record.id
            )
            proof_res = await session.execute(stmt_proof)
            proof = proof_res.scalar_one_or_none()

            if proof:
                proof.manual_attestation_officer_id = officer.id
                proof.manual_attestation_notes = notes
                if attestation_status == "ATTEST_MANUAL_CONTAINED":
                    proof.verification_outcome = VerificationOutcome.VERIFICATION_VERIFIED
                    proof.observed_target_state = "MANUALLY_CONFIRMED_CONTAINED"
                else:
                    proof.verification_outcome = VerificationOutcome.VERIFICATION_FAILED
                    proof.observed_target_state = "MANUALLY_CONFIRMED_FAILED"

        if attestation_status == "ATTEST_MANUAL_CONTAINED":
            req.status = ContainmentRequestStatus.VERIFIED
        else:
            req.status = ContainmentRequestStatus.FAILED

        await session.flush()

        # Audit emission
        await audit_service.log_security_event(
            event_type="CONTAINMENT_MANUAL_ATTESTATION",
            actor_id=officer.id,
            actor_role=officer.role.value,
            resource_type="containment_request",
            resource_id=request_id,
            action=attestation_status,
            metadata={"notes": notes, "final_status": req.status.value},
            risk_score=0.8,
        )

        return req
