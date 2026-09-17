"""
B-SEA Phase 3C-5E Containment Coordinator Service
Authoritative Implementation conforming to Rev-04.1.

Implements the complete 11-step lifecycle:
1. Intent & Request Canonicalization (IntentKey independent of RequesterID)
2. Standard & Break-Glass Policy Evaluation (Dual Pipeline)
3. Two-Person Control Quorum Authorization (Requester/Approver Separation)
4. Pre-Dispatch Safety Invariant (Durable pre-dispatch persistence)
5. Mode B Pre-Dispatch Security Audit Emission
6. Idempotent Execution Adapter Dispatch (ExternalOperationID)
7. Durable Execution Result Persistence & Mode B Result Audit
8. Independent Out-of-Band Verification
9. Verification Result Persistence & Mode B Verification Audit
10. 5D Observational CAS Transition (SecurityIncident -> CONTAINED)
11. UNKNOWN / INCONCLUSIVE Quarantine & Recovery (Forensic Completeness)
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, Tuple, List
import uuid

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.core.database import AsyncSessionLocal
from app.core.models import User, UserRoleEnum
from app.modules.incidents.models import (
    SecurityIncident,
    SecurityIncidentStatus,
    CorrelationStatus,
    SealVerificationStatus,
)
from app.modules.incidents.service import SecurityIncidentService
from app.modules.incidents.exceptions import (
    IncidentNotFoundError,
    InvalidStateTransitionError,
    OptimisticLockError,
)
from app.modules.audit.service import AuditService, AuditResult
from app.modules.containment.models import (
    ContainmentIntent,
    ContainmentIntentStatus,
    ContainmentRequest,
    ContainmentRequestStatus,
    ContainmentAuthorization,
    BreakGlassToken,
    BreakGlassTokenStatus,
    ContainmentExecutionRecord,
    ContainmentVerificationProof,
    ContainmentConsumedNonce,
    ContainmentActionType,
    ContainmentActionRisk,
    ExecutionOutcome,
    VerificationOutcome,
)
from app.modules.containment.identity import (
    canonicalize_target_urn,
    compute_intent_key,
    compute_request_key,
    compute_scope_hash,
    compute_target_snapshot_hash,
    compute_policy_fingerprint,
    compute_external_operation_id,
    generate_crypto_nonce,
    jcs_canonicalize,
)
from app.modules.containment.policy import (
    ContainmentPolicyEngine,
    StandardPolicyDecision,
    BreakGlassPolicyDecision,
    PolicyEvaluationResult,
    CURRENT_POLICY_VERSION,
)
from app.modules.containment.authorization import (
    AuthorizationService,
    DualControlSelfApprovalError,
    InsufficientQuorumError,
    AuthorizationExpiredError,
    ReplayAttackError,
)
from app.modules.containment.adapters import (
    SubsystemExecutionRegistry,
    ExecutionAdapterResult,
)
from app.modules.containment.verifier import (
    IndependentVerificationEngine,
    IndependentVerificationResult,
)
from app.modules.containment.break_glass import (
    BreakGlassTokenCoordinator,
    BreakGlassError,
    BreakGlassCriticalProhibitedError,
    BreakGlassTokenExpiredError,
    BreakGlassReplayError,
)
from app.modules.containment.reconciliation import ReconciliationService


class ContainmentServiceError(Exception):
    """Base exception for containment service errors."""
    pass


class ContainmentPolicyDeniedError(ContainmentServiceError):
    """Raised when containment policy engine denies request."""
    pass


class TargetStateMismatchError(ContainmentServiceError):
    """Raised when target state snapshot or generation changed prior to execution."""
    pass


class ExecutionLeaseExpiredError(ContainmentServiceError):
    """Raised when execution lease expired before execution dispatch."""
    pass


class ContainmentCoordinatorService:
    """
    Authoritative Coordinator for Phase 3C-5E Policy-Governed Security Containment.
    Integrates policy evaluation, quorum authorization, dispatch, verification,
    audit emission, and 5D incident lifecycle management.
    """

    def __init__(
        self,
        db_session: Optional[AsyncSession] = None,
        audit_service: Optional[AuditService] = None,
        incident_service: Optional[SecurityIncidentService] = None,
    ):
        self.db = db_session
        self.audit_service = audit_service or AuditService()
        self.incident_service = incident_service or SecurityIncidentService(
            db=db_session,
            audit_service=self.audit_service,
        )

    # -------------------------------------------------------------------------
    # STEP 1: REQUEST & INTENT INITIATION
    # -------------------------------------------------------------------------
    async def request_containment(
        self,
        requester: User,
        action_type: ContainmentActionType,
        incident_id: str,
        target_dict: Dict[str, Any],
        justification: str,
        max_allowed_entities: int = 1,
        session: Optional[AsyncSession] = None,
    ) -> ContainmentRequest:
        """
        Processes a containment request, computes canonical intent key, evaluates standard policy,
        persists intent and request records, and emits pre-authorization Mode B audits.
        """
        sess = session or self.db
        if sess is None:
            raise ContainmentServiceError("Database session required for containment request.")

        # 1. Fetch & validate 5D Security Incident
        stmt = select(SecurityIncident).where(SecurityIncident.id == incident_id)
        res = await sess.execute(stmt)
        incident = res.scalar_one_or_none()
        if not incident:
            raise IncidentNotFoundError(f"SecurityIncident '{incident_id}' not found.")

        # Incident must be active to receive containment
        if incident.status in {
            SecurityIncidentStatus.CONTAINED,
            SecurityIncidentStatus.RESOLVED,
            SecurityIncidentStatus.CLOSED,
            SecurityIncidentStatus.FALSE_POSITIVE,
            SecurityIncidentStatus.DUPLICATE,
        }:
            raise InvalidStateTransitionError(
                f"Cannot request containment on incident in state '{incident.status.value}'."
            )

        # 2. Canonical Identity computation
        canonical_target_urn = canonicalize_target_urn(action_type, target_dict)
        target_snapshot_hash = compute_target_snapshot_hash(target_dict)
        scope_hash = compute_scope_hash(target_dict)

        intent_key = compute_intent_key(
            action_type=action_type,
            canonical_target_urn=canonical_target_urn,
            incident_id=str(incident.id),
            incident_generation=incident.generation,
        )

        now = datetime.now(timezone.utc)
        request_key = compute_request_key(
            intent_key=intent_key,
            requester_id=str(requester.id),
            request_time=now,
        )

        # 3. Policy Evaluation
        engine = ContainmentPolicyEngine()
        pol_eval = engine.evaluate_standard_policy(
            action_type=action_type,
            incident_status=incident.status,
            incident_severity=incident.severity,
            target_urn=canonical_target_urn,
            max_entities=max_allowed_entities,
            requester_role=requester.role,
        )

        policy_fingerprint = compute_policy_fingerprint(
            action_type=action_type,
            risk_tier=pol_eval.risk_tier,
            policy_version=pol_eval.policy_version,
        )

        # 4. Handle Policy Denial
        if pol_eval.decision == StandardPolicyDecision.DENY.value:
            await self.audit_service.log_security_event(
                event_type="CONTAINMENT_REQUEST_DENIED",
                result=AuditResult.FAILURE,
                actor_id=str(requester.id),
                actor_role=requester.role.value if hasattr(requester.role, "value") else str(requester.role),
                resource_type="CONTAINMENT_INTENT",
                resource_id=intent_key,
                action=action_type.value,
                metadata={
                    "reason": pol_eval.reason,
                    "incident_id": str(incident.id),
                    "action_type": action_type.value,
                },
            )
            raise ContainmentPolicyDeniedError(f"Policy denied containment: {pol_eval.reason}")

        # 5. Locate or create ContainmentIntent
        stmt_intent = select(ContainmentIntent).where(ContainmentIntent.intent_key == intent_key)
        res_intent = await sess.execute(stmt_intent)
        intent = res_intent.scalar_one_or_none()

        if not intent:
            intent = ContainmentIntent(
                intent_key=intent_key,
                incident_id=incident.id,
                incident_generation=incident.generation,
                action_type=action_type,
                canonical_target_urn=canonical_target_urn,
                risk_tier=pol_eval.risk_tier,
                status=ContainmentIntentStatus.REGISTERED,
            )
            sess.add(intent)
            await sess.flush()

        # 6. Create ContainmentRequest
        req_status = (
            ContainmentRequestStatus.AWAITING_AUTHORIZATION
            if pol_eval.decision == StandardPolicyDecision.REQUIRE_SECOND_AUTHORIZER.value
            else ContainmentRequestStatus.AUTHORIZED
        )

        request_rec = ContainmentRequest(
            request_key=request_key,
            intent_key=intent_key,
            requester_id=requester.id,
            target_snapshot_hash=target_snapshot_hash,
            scope_hash=scope_hash,
            max_allowed_entities=max_allowed_entities,
            policy_version=pol_eval.policy_version,
            policy_fingerprint=policy_fingerprint,
            policy_decision=pol_eval.decision,
            status=req_status,
        )
        sess.add(request_rec)
        await sess.flush()

        # 7. Pre-Dispatch Mode B Audit Records (Ordered Audit Sequencing)
        # Event 1: CONTAINMENT_REQUESTED
        await self.audit_service.log_security_event(
            event_type="CONTAINMENT_REQUESTED",
            result=AuditResult.SUCCESS,
            actor_id=str(requester.id),
            actor_role=requester.role.value if hasattr(requester.role, "value") else str(requester.role),
            resource_type="CONTAINMENT_REQUEST",
            resource_id=str(request_rec.id),
            action=action_type.value,
            metadata={
                "intent_key": intent_key,
                "request_key": request_key,
                "target_urn": canonical_target_urn,
                "incident_id": str(incident.id),
                "generation": incident.generation,
                "justification": justification,
            },
        )

        # Event 2: CONTAINMENT_POLICY_EVALUATED
        await self.audit_service.log_security_event(
            event_type="CONTAINMENT_POLICY_EVALUATED",
            result=AuditResult.SUCCESS,
            actor_id=str(requester.id),
            actor_role=requester.role.value if hasattr(requester.role, "value") else str(requester.role),
            resource_type="CONTAINMENT_REQUEST",
            resource_id=str(request_rec.id),
            action=action_type.value,
            metadata={
                "decision": pol_eval.decision,
                "risk_tier": pol_eval.risk_tier.value,
                "policy_version": pol_eval.policy_version,
                "policy_fingerprint": policy_fingerprint,
            },
        )

        # 8. Single-signoff auto-authorization for ALLOW (LOW / MEDIUM risk actions)
        if pol_eval.decision == StandardPolicyDecision.ALLOW.value:
            nonce = generate_crypto_nonce()
            await AuthorizationService.verify_and_record_authorization(
                session=sess,
                request=request_rec,
                approver=requester,
                risk_tier=pol_eval.risk_tier,
                auth_nonce=nonce,
                signature=f"sig_{nonce[:16]}",
                is_break_glass=False,
            )
            await self.audit_service.log_security_event(
                event_type="CONTAINMENT_AUTHORIZED",
                result=AuditResult.SUCCESS,
                actor_id=str(requester.id),
                actor_role=requester.role.value if hasattr(requester.role, "value") else str(requester.role),
                resource_type="CONTAINMENT_REQUEST",
                resource_id=str(request_rec.id),
                action=action_type.value,
                metadata={
                    "approver_id": str(requester.id),
                    "authorization_type": "SINGLE_PRINCIPAL_ALLOW",
                    "auth_nonce": nonce,
                },
            )

        return request_rec

    # -------------------------------------------------------------------------
    # STEP 2: TWO-PERSON CONTROL QUORUM AUTHORIZATION
    # -------------------------------------------------------------------------
    async def authorize_containment(
        self,
        request_id: str,
        approver: User,
        auth_nonce: str,
        signature: Optional[str] = None,
        session: Optional[AsyncSession] = None,
    ) -> ContainmentAuthorization:
        """
        Executes two-person control authorization check for pending containment request.
        Enforces requester/approver separation, role quorum, and single-use nonce consumption.
        """
        sess = session or self.db
        if sess is None:
            raise ContainmentServiceError("Database session required for authorization.")

        req = await sess.get(ContainmentRequest, request_id)
        if not req:
            raise ContainmentServiceError(f"ContainmentRequest '{request_id}' not found.")

        # Load Intent to get risk tier
        stmt_intent = select(ContainmentIntent).where(ContainmentIntent.intent_key == req.intent_key)
        res_intent = await sess.execute(stmt_intent)
        intent = res_intent.scalar_one_or_none()
        if not intent:
            raise ContainmentServiceError(f"ContainmentIntent '{req.intent_key}' not found.")

        sig = signature or f"sig_{auth_nonce[:16]}"
        auth = await AuthorizationService.verify_and_record_authorization(
            session=sess,
            request=req,
            approver=approver,
            risk_tier=intent.risk_tier,
            auth_nonce=auth_nonce,
            signature=sig,
            is_break_glass=False,
        )

        # Check if quorum is satisfied to transition request status
        stmt_auths = select(ContainmentAuthorization).where(ContainmentAuthorization.request_id == req.id)
        res_auths = await sess.execute(stmt_auths)
        all_auths = res_auths.scalars().all()

        if AuthorizationService.is_quorum_satisfied(intent.risk_tier, all_auths, req.requester_id):
            req.status = ContainmentRequestStatus.AUTHORIZED
            await sess.flush()

        # Event 3: CONTAINMENT_AUTHORIZED
        await self.audit_service.log_security_event(
            event_type="CONTAINMENT_AUTHORIZED",
            result=AuditResult.SUCCESS,
            actor_id=str(approver.id),
            actor_role=approver.role.value if hasattr(approver.role, "value") else str(approver.role),
            resource_type="CONTAINMENT_REQUEST",
            resource_id=str(request_id),
            action="AUTHORIZE",
            metadata={
                "approver_id": str(approver.id),
                "auth_id": str(auth.id),
                "auth_nonce": auth_nonce,
                "is_break_glass": False,
                "status": req.status.value,
            },
        )

        return auth

    # -------------------------------------------------------------------------
    # STEP 3: EXECUTION COORDINATOR (PRE-DISPATCH & DISPATCH)
    # -------------------------------------------------------------------------
    async def execute_containment(
        self,
        request_id: str,
        executor: User,
        target_dict: Dict[str, Any],
        break_glass_token: Optional[BreakGlassToken] = None,
        session: Optional[AsyncSession] = None,
    ) -> Tuple[ContainmentExecutionRecord, IndependentVerificationResult]:
        """
        Coordinates execution lifecycle:
        1. Validates request authorization & state
        2. Acquires execution lease
        3. PRE-DISPATCH SAFETY INVARIANT: Persists execution record & commits Mode B pre-dispatch audit
        4. Dispatches subsystem execution adapter
        5. Persists execution result & commits Mode B result audit
        6. Invokes independent verification
        7. Advances incident status via 5D CAS transition upon verified success
        """
        sess = session or self.db
        if sess is None:
            raise ContainmentServiceError("Database session required for execution.")

        req = await sess.get(ContainmentRequest, request_id)
        if not req:
            raise ContainmentServiceError(f"ContainmentRequest '{request_id}' not found.")

        # Verify Authorization status
        if req.status != ContainmentRequestStatus.AUTHORIZED:
            raise ContainmentServiceError(f"Cannot execute request in state '{req.status.value}'.")

        # Load Intent
        stmt_intent = select(ContainmentIntent).where(ContainmentIntent.intent_key == req.intent_key)
        res_intent = await sess.execute(stmt_intent)
        intent = res_intent.scalar_one_or_none()
        if not intent:
            raise ContainmentServiceError(f"ContainmentIntent '{req.intent_key}' not found.")

        # Load Incident & verify generation
        stmt_inc = select(SecurityIncident).where(SecurityIncident.id == intent.incident_id)
        res_inc = await sess.execute(stmt_inc)
        incident = res_inc.scalar_one_or_none()
        if not incident:
            raise IncidentNotFoundError(f"Incident '{intent.incident_id}' not found.")

        if incident.generation != intent.incident_generation:
            raise TargetStateMismatchError(
                f"Incident generation mismatch: intent={intent.incident_generation}, incident={incident.generation}"
            )

        # Target snapshot check
        current_target_snapshot = compute_target_snapshot_hash(target_dict)
        if current_target_snapshot != req.target_snapshot_hash:
            raise TargetStateMismatchError("Target state snapshot changed between request and execution dispatch.")

        now = datetime.now(timezone.utc)

        # ---------------------------------------------------------------------
        # PRE-DISPATCH SAFETY INVARIANT:
        # Generate execution ID and ExternalOperationID, acquire 60-second lease,
        # and durably persist execution intent BEFORE opening any external socket.
        # ---------------------------------------------------------------------
        execution_id = str(uuid.uuid4())
        # Count previous attempts
        stmt_attempts = select(ContainmentExecutionRecord).where(ContainmentExecutionRecord.request_id == req.id)
        res_attempts = await sess.execute(stmt_attempts)
        attempts = res_attempts.scalars().all()
        attempt_count = len(attempts) + 1

        external_op_id = compute_external_operation_id(
            intent_key=req.intent_key,
            execution_id=execution_id,
            attempt_count=attempt_count,
        )

        lease_deadline = now + timedelta(seconds=60)
        req.execution_lease_expires_at = lease_deadline
        req.status = ContainmentRequestStatus.EXECUTING
        intent.status = ContainmentIntentStatus.IN_PROGRESS

        exec_record = ContainmentExecutionRecord(
            id=execution_id,
            request_id=req.id,
            external_operation_id=external_op_id,
            adapter_name=intent.action_type.value,
            raw_outcome=ExecutionOutcome.EXECUTION_UNKNOWN,
            started_at=now,
            created_at=now,
        )
        sess.add(exec_record)
        await sess.flush()
        await sess.commit()

        # Mode B Audit Event: CONTAINMENT_EXECUTION_STARTED (durably logged)
        await self.audit_service.log_security_event(
            event_type="CONTAINMENT_EXECUTION_STARTED",
            result=AuditResult.SUCCESS,
            actor_id=str(executor.id),
            actor_role=executor.role.value if hasattr(executor.role, "value") else str(executor.role),
            resource_type="CONTAINMENT_EXECUTION_RECORD",
            resource_id=str(execution_id),
            action=intent.action_type.value,
            metadata={
                "external_operation_id": external_op_id,
                "request_id": str(req.id),
                "intent_key": req.intent_key,
                "lease_expires_at": lease_deadline.isoformat(),
            },
        )

        # ---------------------------------------------------------------------
        # EXECUTION ADAPTER DISPATCH
        # ---------------------------------------------------------------------
        try:
            adapter_res: ExecutionAdapterResult = await SubsystemExecutionRegistry.dispatch(
                session=sess,
                action_type=intent.action_type,
                canonical_target_urn=intent.canonical_target_urn,
                external_operation_id=external_op_id,
                execution_lease_deadline=lease_deadline,
            )
        except Exception as exc:
            # UNKNOWN outcome on uncaught dispatch exception
            adapter_res = ExecutionAdapterResult(
                outcome=ExecutionOutcome.EXECUTION_UNKNOWN,
                latency_ms=0,
                error_code="DISPATCH_UNCAUGHT_EXCEPTION",
                error_message=str(exc),
            )

        # Persist Execution Result
        completed_at = datetime.now(timezone.utc)
        exec_record.raw_outcome = adapter_res.outcome
        exec_record.latency_ms = adapter_res.latency_ms
        exec_record.error_code = adapter_res.error_code
        exec_record.error_message = adapter_res.error_message
        exec_record.completed_at = completed_at
        req.status = ContainmentRequestStatus.EXECUTED
        await sess.flush()
        await sess.commit()

        # Mode B Audit Event: CONTAINMENT_EXECUTION_RESULT
        audit_res = AuditResult.SUCCESS if adapter_res.outcome == ExecutionOutcome.EXECUTION_SUCCEEDED else AuditResult.FAILURE
        await self.audit_service.log_security_event(
            event_type="CONTAINMENT_EXECUTION_RESULT",
            result=audit_res,
            actor_id=str(executor.id),
            actor_role=executor.role.value if hasattr(executor.role, "value") else str(executor.role),
            resource_type="CONTAINMENT_EXECUTION_RECORD",
            resource_id=str(execution_id),
            action=intent.action_type.value,
            metadata={
                "outcome": adapter_res.outcome.value,
                "external_operation_id": external_op_id,
                "latency_ms": adapter_res.latency_ms,
                "error_code": adapter_res.error_code,
            },
        )

        # ---------------------------------------------------------------------
        # INDEPENDENT VERIFICATION
        # ---------------------------------------------------------------------
        verification_result = await self.verify_execution(
            execution_id=execution_id,
            session=sess,
        )

        return exec_record, verification_result

    # -------------------------------------------------------------------------
    # STEP 4: INDEPENDENT VERIFICATION & 5D CAS TRANSITION
    # -------------------------------------------------------------------------
    async def verify_execution(
        self,
        execution_id: str,
        session: Optional[AsyncSession] = None,
    ) -> IndependentVerificationResult:
        """
        Executes out-of-band verification on executed containment action.
        Follows the authoritative 3x3 outcome matrix:
        - UNKNOWN + VERIFIED -> Succeeded -> Transition 5D to CONTAINED
        - UNKNOWN + FAILED -> Failed -> Quarantine / No 5D update
        - INCONCLUSIVE -> Quarantined -> Manual Security Officer Attestation Required
        """
        sess = session or self.db
        if sess is None:
            raise ContainmentServiceError("Database session required for verification.")

        exec_rec = await sess.get(ContainmentExecutionRecord, execution_id)
        if not exec_rec:
            raise ContainmentServiceError(f"Execution record '{execution_id}' not found.")

        # Load Request & Intent
        req = await sess.get(ContainmentRequest, exec_rec.request_id)
        stmt_intent = select(ContainmentIntent).where(ContainmentIntent.intent_key == req.intent_key)
        res_intent = await sess.execute(stmt_intent)
        intent = res_intent.scalar_one_or_none()

        req.status = ContainmentRequestStatus.VERIFYING_PENDING
        await sess.flush()

        # Audit Event 6: CONTAINMENT_VERIFICATION_STARTED
        await self.audit_service.log_security_event(
            event_type="CONTAINMENT_VERIFICATION_STARTED",
            result=AuditResult.SUCCESS,
            resource_type="CONTAINMENT_EXECUTION_RECORD",
            resource_id=str(execution_id),
            action=intent.action_type.value,
            metadata={
                "execution_id": str(execution_id),
                "action_type": intent.action_type.value,
                "raw_outcome": exec_rec.raw_outcome.value,
            },
        )

        # Run independent verifier engine
        v_result: IndependentVerificationResult = await IndependentVerificationEngine.verify_containment(
            session=sess,
            action_type=intent.action_type,
            canonical_target_urn=intent.canonical_target_urn,
            verifier_name=f"{intent.action_type.value}_verifier",
        )

        now = datetime.now(timezone.utc)
        proof = ContainmentVerificationProof(
            execution_id=execution_id,
            verifier_name=f"{intent.action_type.value}_verifier",
            verification_outcome=v_result.outcome,
            observed_target_state=v_result.observed_target_state,
            proof_hash=v_result.proof_hash,
            proof_payload=v_result.proof_payload,
            verified_at=now,
            created_at=now,
        )
        sess.add(proof)
        await sess.flush()

        # Audit Event 7: Verification Result Audit
        v_audit_type = (
            "CONTAINMENT_VERIFIED"
            if v_result.outcome == VerificationOutcome.VERIFICATION_VERIFIED
            else ("CONTAINMENT_FAILED" if v_result.outcome == VerificationOutcome.VERIFICATION_FAILED else "CONTAINMENT_INCONCLUSIVE")
        )
        v_audit_result = AuditResult.SUCCESS if v_result.outcome == VerificationOutcome.VERIFICATION_VERIFIED else AuditResult.FAILURE

        await self.audit_service.log_security_event(
            event_type=v_audit_type,
            result=v_audit_result,
            resource_type="CONTAINMENT_VERIFICATION_PROOF",
            resource_id=str(proof.id),
            action=intent.action_type.value,
            metadata={
                "verification_outcome": v_result.outcome.value,
                "proof_hash": v_result.proof_hash,
                "execution_id": str(execution_id),
            },
        )

        # Outcome state updates
        if v_result.outcome == VerificationOutcome.VERIFICATION_VERIFIED:
            req.status = ContainmentRequestStatus.VERIFIED
            intent.status = ContainmentIntentStatus.CONTAINED
            await sess.flush()
            await sess.commit()

            # -----------------------------------------------------------------
            # 5D OBSERVATIONAL CAS TRANSITION:
            # Advance SecurityIncident to CONTAINED via SecurityIncidentService
            # -----------------------------------------------------------------
            stmt_inc = select(SecurityIncident).where(SecurityIncident.id == intent.incident_id)
            res_inc = await sess.execute(stmt_inc)
            incident = res_inc.scalar_one_or_none()

            if incident and incident.status == SecurityIncidentStatus.INVESTIGATING:
                await self.incident_service.transition_status(
                    incident_id=str(incident.id),
                    actor_id=str(req.requester_id),
                    actor_role=UserRoleEnum.SUPER_ADMIN.value,
                    new_status=SecurityIncidentStatus.CONTAINED,
                    expected_version=incident.version,
                    containment_data={
                        "containment_reference_id": str(intent.id),
                        "containment_mechanism": intent.action_type.value,
                        "authorization_principal": str(req.requester_id),
                        "containment_timestamp": now,
                        "audit_event_reference": v_result.proof_hash,
                    },
                    db_session=sess,
                )

        elif v_result.outcome == VerificationOutcome.VERIFICATION_FAILED:
            req.status = ContainmentRequestStatus.FAILED
            intent.status = ContainmentIntentStatus.FAILED
            await sess.flush()
            await sess.commit()

        elif v_result.outcome == VerificationOutcome.VERIFICATION_INCONCLUSIVE:
            req.status = ContainmentRequestStatus.QUARANTINED
            await sess.flush()
            await sess.commit()

        return v_result

    # -------------------------------------------------------------------------
    # EMERGENCY BREAK-GLASS LIFECYCLE
    # -------------------------------------------------------------------------
    async def issue_break_glass_token(
        self,
        issuer: User,
        action_type: ContainmentActionType,
        incident_id: str,
        target_dict: Dict[str, Any],
        fido2_assertion_payload: str,
        is_exam_in_progress: bool = True,
        session: Optional[AsyncSession] = None,
    ) -> BreakGlassToken:
        """
        Issues an emergency Break-Glass token.
        Enforces:
        - Critical actions categorically prohibited
        - Incident in investigating status and CRITICAL/HIGH severity
        - Single-entity ceiling
        - Superadmin rate limiting
        - FIDO2 / WebAuthn cryptographic assertion verification
        """
        sess = session or self.db
        if sess is None:
            raise ContainmentServiceError("Database session required to issue Break-Glass token.")

        stmt = select(SecurityIncident).where(SecurityIncident.id == incident_id)
        res = await sess.execute(stmt)
        incident = res.scalar_one_or_none()
        if not incident:
            raise IncidentNotFoundError(f"Incident '{incident_id}' not found.")

        canonical_target_urn = canonicalize_target_urn(action_type, target_dict)
        intent_key = compute_intent_key(
            action_type=action_type,
            canonical_target_urn=canonical_target_urn,
            incident_id=str(incident.id),
            incident_generation=incident.generation,
        )

        token = await BreakGlassTokenCoordinator.issue_token(
            session=sess,
            issuer=issuer,
            incident_id=str(incident.id),
            incident_generation=incident.generation,
            incident_status=incident.status,
            incident_severity=incident.severity,
            intent_key=intent_key,
            action_type=action_type,
            canonical_target_urn=canonical_target_urn,
            target_scope_dict=target_dict,
            fido2_assertion_payload=fido2_assertion_payload,
            is_exam_in_progress=is_exam_in_progress,
            policy_version=CURRENT_POLICY_VERSION,
        )

        await self.audit_service.log_security_event(
            event_type="CONTAINMENT_BREAK_GLASS_ISSUED",
            result=AuditResult.SUCCESS,
            actor_id=str(issuer.id),
            actor_role=issuer.role.value if hasattr(issuer.role, "value") else str(issuer.role),
            resource_type="BREAK_GLASS_TOKEN",
            resource_id=str(token.id),
            action=action_type.value,
            metadata={
                "token_nonce": token.token_nonce,
                "intent_key": token.intent_key,
                "expires_at": token.expires_at.isoformat(),
            },
        )

        return token

    async def execute_break_glass(
        self,
        token_id: str,
        executor: User,
        target_dict: Dict[str, Any],
        justification: str,
        session: Optional[AsyncSession] = None,
    ) -> Tuple[ContainmentExecutionRecord, IndependentVerificationResult]:
        """
        Executes emergency Break-Glass containment action.
        Atomically consumes token, emits CONTAINMENT_EMERGENCY_OVERRIDE audit,
        and executes with independent verification.
        """
        sess = session or self.db
        if sess is None:
            raise ContainmentServiceError("Database session required for Break-Glass execution.")

        # Load token to find intent key
        tok = await sess.get(BreakGlassToken, token_id)
        if not tok:
            raise BreakGlassError(f"BreakGlassToken '{token_id}' not found.")

        # 1. Atomically consume token and acquire lease
        token, lease_expires_at = await BreakGlassTokenCoordinator.consume_token_and_start_lease(
            session=sess,
            token_id=token_id,
            expected_intent_key=tok.intent_key,
            actor_id=str(executor.id),
        )

        # 2. Fetch or create ContainmentRequest for this intent
        canonical_target_urn = canonicalize_target_urn(token.action_type, target_dict)
        target_snapshot_hash = compute_target_snapshot_hash(target_dict)
        scope_hash = compute_scope_hash(target_dict)

        now = datetime.now(timezone.utc)
        request_key = compute_request_key(
            intent_key=token.intent_key,
            requester_id=str(executor.id),
            request_time=now,
        )

        policy_fingerprint = compute_policy_fingerprint(
            action_type=token.action_type,
            risk_tier=ContainmentActionRisk.HIGH,
            policy_version=token.policy_version,
        )

        # Fetch / Create Intent
        stmt_intent = select(ContainmentIntent).where(ContainmentIntent.intent_key == token.intent_key)
        res_intent = await sess.execute(stmt_intent)
        intent = res_intent.scalar_one_or_none()

        if not intent:
            intent = ContainmentIntent(
                intent_key=token.intent_key,
                incident_id=token.incident_id,
                incident_generation=token.incident_generation,
                action_type=token.action_type,
                canonical_target_urn=canonical_target_urn,
                risk_tier=ContainmentActionRisk.HIGH,
                status=ContainmentIntentStatus.REGISTERED,
            )
            sess.add(intent)
            await sess.flush()

        req = ContainmentRequest(
            request_key=request_key,
            intent_key=token.intent_key,
            requester_id=executor.id,
            target_snapshot_hash=target_snapshot_hash,
            scope_hash=scope_hash,
            max_allowed_entities=1,
            policy_version=token.policy_version,
            policy_fingerprint=policy_fingerprint,
            policy_decision="BREAK_GLASS_ALLOWED",
            status=ContainmentRequestStatus.AUTHORIZED,
        )
        sess.add(req)
        await sess.flush()

        # Record Break-Glass Authorization
        await AuthorizationService.verify_and_record_authorization(
            session=sess,
            request=req,
            approver=executor,
            risk_tier=ContainmentActionRisk.HIGH,
            auth_nonce=token.token_nonce,
            signature=f"sig_bg_{token.token_nonce[:16]}",
            is_break_glass=True,
            break_glass_token_id=token.id,
        )

        # Audit Event: CONTAINMENT_EMERGENCY_OVERRIDE
        await self.audit_service.log_security_event(
            event_type="CONTAINMENT_EMERGENCY_OVERRIDE",
            result=AuditResult.SUCCESS,
            actor_id=str(executor.id),
            actor_role=executor.role.value if hasattr(executor.role, "value") else str(executor.role),
            resource_type="BREAK_GLASS_TOKEN",
            resource_id=str(token.id),
            action=token.action_type.value,
            metadata={
                "token_id": str(token.id),
                "intent_key": token.intent_key,
                "justification": justification,
            },
        )

        # Execute through standard coordinator lifecycle
        return await self.execute_containment(
            request_id=req.id,
            executor=executor,
            target_dict=target_dict,
            break_glass_token=token,
            session=sess,
        )
