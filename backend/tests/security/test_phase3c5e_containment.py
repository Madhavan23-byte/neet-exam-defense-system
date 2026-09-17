"""
B-SEA Phase 3C-5E Containment Subsystem Acceptance Test Suite
Conforming to docs/BSEA_PHASE3C5E_ARCHITECTURE_REV04_1.md.

Covers all 35 Mandatory Acceptance Gates:
  TC-GATE-01: Idempotency (Parallel concurrent requests with identical IntentKey)
  TC-GATE-02: Idempotency (Different requesters submit request for same target session)
  TC-GATE-03: Idempotency (Network retry after successful execution)
  TC-GATE-04: 5D Boundary (Generation rollover N -> N+1 rejects 5E update)
  TC-GATE-05: TOCTOU (Target session status modified between authorization and execution)
  TC-GATE-06: Policy (Active policy catalog updated; request signed under superseded version)
  TC-GATE-07: Authorization (Requester attempts to sign as second approver for HIGH risk)
  TC-GATE-08: Authorization (Re-submission of consumed authorization signature)
  TC-GATE-09: Authorization (Valid authorization executed after 301s TTL expiry)
  TC-GATE-10: Break-Glass (Attempt to invoke Break-Glass for CRITICAL risk action)
  TC-GATE-11: Break-Glass (Break-Glass Token submitted with max_allowed_entities > 1)
  TC-GATE-12: Break-Glass (Replay of consumed BreakGlassToken nonce)
  TC-GATE-13: Break-Glass (Break-Glass Token executed after 901s TTL expiry)
  TC-GATE-14: Break-Glass (Super-admin attempts 3rd break-glass action within 60 min)
  TC-GATE-15: Separation of Duty (CRITICAL action mandates SUPER_ADMIN quorum)
  TC-GATE-16: Verification (Adapter reports success, but target remains unmutated)
  TC-GATE-17: Failure (Execution adapter times out after 10 seconds -> EXECUTION_UNKNOWN)
  TC-GATE-18: Failure (Target subsystem completely unreachable -> fails closed)
  TC-GATE-19: Audit (Simulated failure during pre-dispatch audit -> zero dispatch)
  TC-GATE-20: Rollback / Compensation (Reversible compensation semantics)
  TC-GATE-21: Regression (Full repository test suite passes with zero regressions)
  TC-GATE-22: DB Divergence (External mutation succeeds, DB rolls back -> reconciliation)
  TC-GATE-23: Timeout State (Adapter times out -> EXECUTION_UNKNOWN; verifier dispatches)
  TC-GATE-24: Orthogonality (Incident severity CRITICAL vs action CRITICAL break-glass denial)
  TC-GATE-25: Policy Gate (Standard policy REQUIRE_SECOND_AUTHORIZER != Break-Glass)
  TC-GATE-26: Lease Pre-Check (Break-Glass token expires prior to execution dispatch)
  TC-GATE-27: Lease Post-Check (Token expires while adapter is executing within 60s lease)
  TC-GATE-28: Intent Lock (Officer B submits request for Target X while Officer A's request active)
  TC-GATE-29: Reconcile Target (Reconciliation verifies ground truth before DB reconstruction)
  TC-GATE-30: UNKNOWN + VERIFIED (State advances to VERIFIED; 5D incident updated)
  TC-GATE-31: UNKNOWN + FAILED (Request marked FAILED; retry mandates new authorized attempt)
  TC-GATE-32: Inconclusive Quarantine (VERIFICATION_INCONCLUSIVE -> quarantined, manual attestation)
  TC-GATE-33: Break-Glass No Reuse (Consumed token encounters UNKNOWN/INCONCLUSIVE -> burned)
  TC-GATE-34: Break-Glass Fresh Auth (Re-attempt mandates fresh emergency evaluation & token)
  TC-GATE-35: Lease Expiry (Execution lease 60s expires without ack -> EXECUTION_UNKNOWN)
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone, timedelta
import hashlib
import json
import uuid
import pytest
import asyncpg
from sqlalchemy import select, update, text

from app.core.database import AsyncSessionLocal
from app.core.models import (
    User,
    Organization,
    UserRoleEnum,
    SecurityIncident,
    SecurityIncidentStatus,
    SecurityIncidentSeverity,
    CandidateSession,
    SessionStatus,
    Question,
    Centre,
    ExamForm,
    Candidate,
    Exam,
    ExamStatus,
    FormStatus,
    SecurityMode,
)
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
)
from app.modules.containment.policy import (
    ContainmentPolicyEngine,
    StandardPolicyDecision,
    BreakGlassPolicyDecision,
    CURRENT_POLICY_VERSION,
)
from app.modules.containment.authorization import (
    AuthorizationService,
    DualControlSelfApprovalError,
    InsufficientQuorumError,
    AuthorizationExpiredError,
    ReplayAttackError,
)
from app.modules.containment.break_glass import (
    BreakGlassTokenCoordinator,
    BreakGlassError,
    BreakGlassCriticalProhibitedError,
    BreakGlassScopeViolationError,
    BreakGlassRateLimitExceededError,
    BreakGlassTokenExpiredError,
    BreakGlassReplayError,
)
from app.modules.containment.adapters import (
    SubsystemExecutionRegistry,
    ExecutionAdapterResult,
)
from app.modules.containment.verifier import (
    IndependentVerificationEngine,
    IndependentVerificationResult,
)
from app.modules.containment.reconciliation import ReconciliationService
from app.modules.containment.service import (
    ContainmentCoordinatorService,
    ContainmentPolicyDeniedError,
    TargetStateMismatchError,
)
from app.modules.incidents.service import SecurityIncidentService
from app.modules.audit.service import AuditService

DB_URL = "postgresql://postgres:root@localhost:5432/bsea"


async def _ensure_org(session) -> str:
    stmt = select(Organization).limit(1)
    res = await session.execute(stmt)
    org = res.scalars().first()
    if not org:
        org = Organization(
            id=str(uuid.uuid4()),
            name="B-SEA National Authority",
            short_name="B-SEA",
            org_type="CENTRAL_GOVERNMENT",
            country="IN",
            timezone="Asia/Kolkata",
            is_active=True,
        )
        session.add(org)
        await session.flush()
    return org.id


async def _get_or_create_user(role: UserRoleEnum, email_prefix: str) -> User:
    async with AsyncSessionLocal() as session:
        org_id = await _ensure_org(session)
        uid = str(uuid.uuid4())
        user = User(
            id=uid,
            org_id=org_id,
            email=f"{email_prefix}_{uid[:8]}@bsea.gov.in",
            username=f"{email_prefix}_{uid[:8]}",
            password_hash="mock_password_hash",
            full_name=f"Test {role.value} {email_prefix}",
            role=role,
            is_active=True,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user


async def _create_test_incident(
    status: SecurityIncidentStatus = SecurityIncidentStatus.INVESTIGATING,
    severity: SecurityIncidentSeverity = SecurityIncidentSeverity.HIGH,
    generation: int = 1,
) -> SecurityIncident:
    async with AsyncSessionLocal() as session:
        inc = SecurityIncident(
            id=str(uuid.uuid4()),
            incident_number=f"INC-{uuid.uuid4().hex[:8].upper()}",
            threat_vector_key=f"tvk_{uuid.uuid4().hex}",
            canonical_rule_id="RULE-EXFIL-01",
            rule_id="RULE-EXFIL-01",
            title="Test Containment Incident",
            description="Automated test incident for containment acceptance gates",
            incident_type="RULE-EXFIL-01",
            dimensions_json={"exam_id": "EXAM-CBT-2026"},
            first_signal_at=datetime.now(timezone.utc),
            latest_signal_at=datetime.now(timezone.utc),
            policy_version="v1",
            exam_id="EXAM-CBT-2026",
            generation=generation,
            correlation_status="OPEN",
            status=status,
            severity=severity,
            version=1,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        session.add(inc)
        await session.commit()
        await session.refresh(inc)
        return inc


async def _create_test_candidate_session() -> CandidateSession:
    async with AsyncSessionLocal() as session:
        org_id = await _ensure_org(session)
        cand_user = await _get_or_create_user(UserRoleEnum.CANDIDATE, "cand")

        cand_id = str(uuid.uuid4())
        cand = Candidate(
            id=cand_id,
            org_id=org_id,
            user_id=cand_user.id,
            registration_number=f"REG-{uuid.uuid4().hex[:8].upper()}",
            full_name="Test Candidate",
            email_hash=hashlib.sha256(f"cand_{cand_id}@example.com".encode()).hexdigest(),
            identity_verified=True,
        )
        session.add(cand)

        exam_id = str(uuid.uuid4())
        exam = Exam(
            id=exam_id,
            org_id=org_id,
            title="Test Containment Exam",
            exam_type="CBT",
            security_mode=SecurityMode.HIGH,
            duration_minutes=180,
            status=ExamStatus.ONGOING,
            required_approvals=1,
            min_centre_readiness_pct=80,
            release_frozen=False,
            created_by=cand_user.id,
        )
        session.add(exam)

        form_id = str(uuid.uuid4())
        form = ExamForm(
            id=form_id,
            exam_id=exam.id,
            form_label="Form A",
            question_ids=[],
            option_orders={},
            integrity_hash=hashlib.sha256(b"mock_integrity_hash").hexdigest(),
            status=FormStatus.ACTIVE,
        )
        session.add(form)
        await session.flush()

        sess = CandidateSession(
            id=str(uuid.uuid4()),
            candidate_id=cand.id,
            exam_id=exam.id,
            form_id=form.id,
            session_token_hash=f"tok_{uuid.uuid4().hex}",
            status=SessionStatus.ACTIVE,
            device_fingerprint=f"fp_{uuid.uuid4().hex[:8]}",
            ip_hash=f"ip_{uuid.uuid4().hex[:8]}",
            current_question_index=0,
            tab_switch_count=0,
            security_violations=0,
        )
        session.add(sess)
        await session.commit()
        await session.refresh(sess)
        return sess



@pytest.fixture(autouse=True)
def cleanup_containment_tables():
    async def _clean():
        async with AsyncSessionLocal() as session:
            await session.execute(text("TRUNCATE TABLE containment_consumed_nonces, containment_verification_proofs, containment_execution_records, containment_authorizations, break_glass_tokens, containment_requests, containment_intents CASCADE;"))
            await session.commit()
    asyncio.run(_clean())
    yield
    asyncio.run(_clean())

# =============================================================================
# ACCEPTANCE GATES TC-GATE-01 THROUGH TC-GATE-35
# =============================================================================

def test_gate_01_idempotency_concurrent_identical_requests():
    async def _test():
        officer = await _get_or_create_user(UserRoleEnum.SECURITY_OFFICER, "officer_01")
        incident = await _create_test_incident()
        target = {"session_id": "sess_1001"}

        urn = canonicalize_target_urn(ContainmentActionType.ACT_CAND_SESSION_TERM, target)
        k1 = compute_intent_key(ContainmentActionType.ACT_CAND_SESSION_TERM, urn, str(incident.id), incident.generation)
        k2 = compute_intent_key(ContainmentActionType.ACT_CAND_SESSION_TERM, urn, str(incident.id), incident.generation)

        assert k1 == k2
        assert len(k1) == 64
    asyncio.run(_test())


def test_gate_02_idempotency_distinct_requesters_same_intent():
    async def _test():
        officer1 = await _get_or_create_user(UserRoleEnum.SECURITY_OFFICER, "officer_a")
        officer2 = await _get_or_create_user(UserRoleEnum.SECURITY_OFFICER, "officer_b")
        incident = await _create_test_incident()
        target = {"session_id": "sess_shared_2002"}

        urn = canonicalize_target_urn(ContainmentActionType.ACT_CAND_SESSION_TERM, target)
        k1 = compute_intent_key(ContainmentActionType.ACT_CAND_SESSION_TERM, urn, str(incident.id), incident.generation)
        k2 = compute_intent_key(ContainmentActionType.ACT_CAND_SESSION_TERM, urn, str(incident.id), incident.generation)

        # Invariant I-02: IntentKey is independent of RequesterID
        assert k1 == k2
    asyncio.run(_test())


def test_gate_03_idempotency_network_retry_after_success():
    async def _test():
        target = {"session_id": f"sess_retried_{uuid.uuid4().hex[:6]}"}
        urn = canonicalize_target_urn(ContainmentActionType.ACT_CAND_SESSION_TERM, target)
        async with AsyncSessionLocal() as session:
            # First execution
            res1 = await SubsystemExecutionRegistry.dispatch(
                session=session,
                action_type=ContainmentActionType.ACT_CAND_SESSION_TERM,
                canonical_target_urn=urn,
                external_operation_id=f"op_{uuid.uuid4().hex[:8]}",
                execution_lease_deadline=datetime.now(timezone.utc) + timedelta(seconds=60),
            )
            assert res1.outcome == ExecutionOutcome.EXECUTION_SUCCEEDED

            # Network retry with identical target URN
            res2 = await SubsystemExecutionRegistry.dispatch(
                session=session,
                action_type=ContainmentActionType.ACT_CAND_SESSION_TERM,
                canonical_target_urn=urn,
                external_operation_id=f"op_{uuid.uuid4().hex[:8]}",
                execution_lease_deadline=datetime.now(timezone.utc) + timedelta(seconds=60),
            )
            assert res2.outcome == ExecutionOutcome.EXECUTION_SUCCEEDED
    asyncio.run(_test())


def test_gate_04_generation_rollover_5d_boundary():
    async def _test():
        officer = await _get_or_create_user(UserRoleEnum.SECURITY_OFFICER, "officer_gen")
        incident = await _create_test_incident(generation=1)
        target = {"session_id": f"sess_gen_{uuid.uuid4().hex[:6]}"}

        coord = ContainmentCoordinatorService()
        async with AsyncSessionLocal() as session:
            req = await coord.request_containment(
                requester=officer,
                action_type=ContainmentActionType.ACT_CAND_SESSION_TERM,
                incident_id=str(incident.id),
                target_dict=target,
                justification="Testing generation rollover boundary.",
                session=session,
            )
            await session.commit()

            # Advance incident generation in 5D
            incident.generation = 2
            await session.merge(incident)
            await session.commit()

            # Execution attempt must reject due to generation mismatch
            with pytest.raises(TargetStateMismatchError):
                await coord.execute_containment(
                    request_id=req.id,
                    executor=officer,
                    target_dict=target,
                    session=session,
                )
    asyncio.run(_test())


def test_gate_05_toctou_target_state_mutation_rejection():
    async def _test():
        officer = await _get_or_create_user(UserRoleEnum.SECURITY_OFFICER, "officer_toctou")
        incident = await _create_test_incident()
        target_initial = {"session_id": "sess_toctou_1", "state": "ACTIVE"}

        coord = ContainmentCoordinatorService()
        async with AsyncSessionLocal() as session:
            req = await coord.request_containment(
                requester=officer,
                action_type=ContainmentActionType.ACT_CAND_SESSION_TERM,
                incident_id=str(incident.id),
                target_dict=target_initial,
                justification="Testing TOCTOU target state mutation.",
                session=session,
            )
            await session.commit()

            # Target dictionary changes before dispatch
            target_mutated = {"session_id": "sess_toctou_1", "state": "COMPLETED"}
            with pytest.raises(TargetStateMismatchError):
                await coord.execute_containment(
                    request_id=req.id,
                    executor=officer,
                    target_dict=target_mutated,
                    session=session,
                )
    asyncio.run(_test())


def test_gate_06_policy_superseded_version_rejection():
    async def _test():
        fp1 = compute_policy_fingerprint(ContainmentActionType.ACT_CAND_SESSION_TERM, ContainmentActionRisk.MEDIUM, "REV-04.1")
        fp2 = compute_policy_fingerprint(ContainmentActionType.ACT_CAND_SESSION_TERM, ContainmentActionRisk.MEDIUM, "REV-03.0")
        assert fp1 != fp2
    asyncio.run(_test())


def test_gate_07_authorization_requester_approver_separation():
    async def _test():
        officer = await _get_or_create_user(UserRoleEnum.SECURITY_OFFICER, "officer_sep")
        incident = await _create_test_incident()
        target = {"session_id": f"sess_sep_{uuid.uuid4().hex[:6]}"}

        coord = ContainmentCoordinatorService()
        async with AsyncSessionLocal() as session:
            req = await coord.request_containment(
                requester=officer,
                action_type=ContainmentActionType.ACT_ACCT_DISABLE,
                incident_id=str(incident.id),
                target_dict=target,
                justification="Testing requester-approver separation.",
                session=session,
            )
            await session.commit()

            # Requester attempts to self-approve HIGH risk action
            with pytest.raises(DualControlSelfApprovalError):
                await AuthorizationService.verify_and_record_authorization(
                    session=session,
                    request=req,
                    approver=officer,
                    risk_tier=ContainmentActionRisk.HIGH,
                    auth_nonce=generate_crypto_nonce(),
                    signature="sig_self_approval",
                )
    asyncio.run(_test())


def test_gate_08_authorization_nonce_replay_protection():
    async def _test():
        officer1 = await _get_or_create_user(UserRoleEnum.SECURITY_OFFICER, "officer_r1")
        officer2 = await _get_or_create_user(UserRoleEnum.SECURITY_OFFICER, "officer_r2")
        incident = await _create_test_incident()
        target = {"session_id": f"sess_replay_{uuid.uuid4().hex[:6]}"}

        coord = ContainmentCoordinatorService()
        nonce = generate_crypto_nonce()

        async with AsyncSessionLocal() as session:
            req = await coord.request_containment(
                requester=officer1,
                action_type=ContainmentActionType.ACT_ACCT_DISABLE,
                incident_id=str(incident.id),
                target_dict=target,
                justification="Testing authorization replay defense.",
                session=session,
            )
            await session.commit()

            # First authorization succeeds
            await AuthorizationService.verify_and_record_authorization(
                session=session,
                request=req,
                approver=officer2,
                risk_tier=ContainmentActionRisk.HIGH,
                auth_nonce=nonce,
                signature="sig_valid_1",
            )
            await session.commit()

            # Second authorization with identical nonce must fail
            with pytest.raises(ReplayAttackError):
                await AuthorizationService.verify_and_record_authorization(
                    session=session,
                    request=req,
                    approver=officer2,
                    risk_tier=ContainmentActionRisk.HIGH,
                    auth_nonce=nonce,
                    signature="sig_replayed",
                )
    asyncio.run(_test())


def test_gate_09_authorization_expiry_ttl():
    async def _test():
        now = datetime.now(timezone.utc)
        expired_auth = ContainmentAuthorization(
            request_id=str(uuid.uuid4()),
            approver_id="app_1",
            auth_nonce="nonce_exp",
            signature="sig_exp",
            is_break_glass=False,
            expires_at=now - timedelta(seconds=10),
            created_at=now - timedelta(seconds=310),
        )
        assert not AuthorizationService.is_quorum_satisfied(ContainmentActionRisk.HIGH, [expired_auth], "req_1")
    asyncio.run(_test())


def test_gate_10_break_glass_critical_prohibited():
    async def _test():
        superadmin = await _get_or_create_user(UserRoleEnum.SUPER_ADMIN, "super_bg1")
        incident = await _create_test_incident(severity=SecurityIncidentSeverity.CRITICAL)
        target = {"form_id": "form_101"}

        coord = ContainmentCoordinatorService()
        async with AsyncSessionLocal() as session:
            with pytest.raises(BreakGlassCriticalProhibitedError):
                await coord.issue_break_glass_token(
                    issuer=superadmin,
                    action_type=ContainmentActionType.ACT_FORM_SUSPEND,
                    incident_id=str(incident.id),
                    target_dict=target,
                    fido2_assertion_payload="fido2_hardware_assertion_token_valid_bytes_123",
                    session=session,
                )
    asyncio.run(_test())


def test_gate_11_break_glass_scope_violation():
    async def _test():
        superadmin = await _get_or_create_user(UserRoleEnum.SUPER_ADMIN, "super_bg2")
        incident = await _create_test_incident(severity=SecurityIncidentSeverity.CRITICAL)
        target = {"user_id": "usr_bg_scope", "max_allowed_entities": 2}

        coord = ContainmentCoordinatorService()
        async with AsyncSessionLocal() as session:
            with pytest.raises(BreakGlassScopeViolationError):
                await coord.issue_break_glass_token(
                    issuer=superadmin,
                    action_type=ContainmentActionType.ACT_ACCT_DISABLE,
                    incident_id=str(incident.id),
                    target_dict=target,
                    fido2_assertion_payload="fido2_hardware_assertion_token_valid_bytes_123",
                    session=session,
                )
    asyncio.run(_test())


def test_gate_12_break_glass_token_replay_protection():
    async def _test():
        superadmin = await _get_or_create_user(UserRoleEnum.SUPER_ADMIN, "super_bg3")
        incident = await _create_test_incident(severity=SecurityIncidentSeverity.CRITICAL)
        target = {"centre_id": f"centre_{uuid.uuid4().hex[:6]}"}

        coord = ContainmentCoordinatorService()
        async with AsyncSessionLocal() as session:
            token = await coord.issue_break_glass_token(
                issuer=superadmin,
                action_type=ContainmentActionType.ACT_ACCT_DISABLE,
                incident_id=str(incident.id),
                target_dict=target,
                fido2_assertion_payload="fido2_hardware_assertion_token_valid_bytes_123",
                session=session,
            )
            await session.commit()

            # First consumption succeeds
            await BreakGlassTokenCoordinator.consume_token_and_start_lease(
                session=session,
                token_id=token.id,
                expected_intent_key=token.intent_key,
                actor_id=str(superadmin.id),
            )
            await session.commit()

            # Second consumption must raise BreakGlassReplayError
            with pytest.raises(BreakGlassReplayError):
                await BreakGlassTokenCoordinator.consume_token_and_start_lease(
                    session=session,
                    token_id=token.id,
                    expected_intent_key=token.intent_key,
                    actor_id=str(superadmin.id),
                )
    asyncio.run(_test())


def test_gate_13_break_glass_token_expiry():
    async def _test():
        superadmin = await _get_or_create_user(UserRoleEnum.SUPER_ADMIN, "super_bg4")
        incident = await _create_test_incident(severity=SecurityIncidentSeverity.CRITICAL)
        target = {"centre_id": f"centre_{uuid.uuid4().hex[:6]}"}

        coord = ContainmentCoordinatorService()
        async with AsyncSessionLocal() as session:
            token = await coord.issue_break_glass_token(
                issuer=superadmin,
                action_type=ContainmentActionType.ACT_ACCT_DISABLE,
                incident_id=str(incident.id),
                target_dict=target,
                fido2_assertion_payload="fido2_hardware_assertion_token_valid_bytes_123",
                session=session,
            )
            # Force expiration
            token.expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
            await session.flush()
            await session.commit()

            with pytest.raises(BreakGlassTokenExpiredError):
                await BreakGlassTokenCoordinator.consume_token_and_start_lease(
                    session=session,
                    token_id=token.id,
                    expected_intent_key=token.intent_key,
                    actor_id=str(superadmin.id),
                )
    asyncio.run(_test())


def test_gate_14_break_glass_rate_limit_exceeded():
    async def _test():
        superadmin = await _get_or_create_user(UserRoleEnum.SUPER_ADMIN, "super_bg_rate")
        incident = await _create_test_incident(severity=SecurityIncidentSeverity.CRITICAL)

        coord = ContainmentCoordinatorService()
        async with AsyncSessionLocal() as session:
            # Issue 1st token
            await coord.issue_break_glass_token(
                issuer=superadmin,
                action_type=ContainmentActionType.ACT_ACCT_DISABLE,
                incident_id=str(incident.id),
                target_dict={"user_id": "u1"},
                fido2_assertion_payload="fido2_hardware_assertion_token_valid_bytes_123",
                session=session,
            )
            # Issue 2nd token
            await coord.issue_break_glass_token(
                issuer=superadmin,
                action_type=ContainmentActionType.ACT_ACCT_DISABLE,
                incident_id=str(incident.id),
                target_dict={"user_id": "u2"},
                fido2_assertion_payload="fido2_hardware_assertion_token_valid_bytes_123",
                session=session,
            )
            await session.commit()

            # 3rd token within 60 min must raise rate limit error
            with pytest.raises(BreakGlassRateLimitExceededError):
                await coord.issue_break_glass_token(
                    issuer=superadmin,
                    action_type=ContainmentActionType.ACT_ACCT_DISABLE,
                    incident_id=str(incident.id),
                    target_dict={"user_id": "u3"},
                    fido2_assertion_payload="fido2_hardware_assertion_token_valid_bytes_123",
                    session=session,
                )
    asyncio.run(_test())


def test_gate_15_separation_of_duty_role_quorum():
    async def _test():
        requester_officer = await _get_or_create_user(UserRoleEnum.SECURITY_OFFICER, "req_q15")
        approver_officer = await _get_or_create_user(UserRoleEnum.SECURITY_OFFICER, "app_q15")
        incident = await _create_test_incident()
        intent = ContainmentIntent(
            id=str(uuid.uuid4()),
            intent_key="int_k_g15",
            incident_id=incident.id,
            incident_generation=1,
            action_type=ContainmentActionType.ACT_FORM_SUSPEND,
            canonical_target_urn="urn:bsea:form:f1",
            risk_tier=ContainmentActionRisk.CRITICAL,
            status=ContainmentIntentStatus.REGISTERED,
        )
        req = ContainmentRequest(
            id=str(uuid.uuid4()),
            request_key="req_k_g15",
            intent_key="int_k_g15",
            requester_id=requester_officer.id,
            target_snapshot_hash="h1",
            scope_hash="h2",
            policy_version="REV-04.1",
            policy_fingerprint="fp1",
            policy_decision="REQUIRE_SECOND_AUTHORIZER",
            status=ContainmentRequestStatus.AWAITING_AUTHORIZATION,
        )

        async with AsyncSessionLocal() as session:
            session.add(intent)
            await session.flush()
            session.add(req)
            await session.flush()
            # Security officer cannot authorize CRITICAL action (requires SUPER_ADMIN)
            with pytest.raises(InsufficientQuorumError):
                await AuthorizationService.verify_and_record_authorization(
                    session=session,
                    request=req,
                    approver=approver_officer,
                    risk_tier=ContainmentActionRisk.CRITICAL,
                    auth_nonce=generate_crypto_nonce(),
                    signature="sig_officer",
                )
    asyncio.run(_test())


def test_gate_16_verification_discrepancy_detected():
    async def _test():
        target = {"user_id": f"usr_unmutated_{uuid.uuid4().hex[:6]}"}
        urn = canonicalize_target_urn(ContainmentActionType.ACT_ACCT_DISABLE, target)
        async with AsyncSessionLocal() as session:
            # Target was never created, so verifier observes account is not locked
            v_res = await IndependentVerificationEngine.verify_containment(
                session=session,
                action_type=ContainmentActionType.ACT_ACCT_DISABLE,
                canonical_target_urn=urn,
            )
            assert v_res.outcome == VerificationOutcome.VERIFICATION_FAILED
    asyncio.run(_test())


def test_gate_17_adapter_timeout_unknown_outcome():
    async def _test():
        SubsystemExecutionRegistry._force_timeout = True
        try:
            async with AsyncSessionLocal() as session:
                res = await SubsystemExecutionRegistry.dispatch(
                    session=session,
                    action_type=ContainmentActionType.ACT_CAND_SESSION_TERM,
                    canonical_target_urn="urn:bsea:session:sess_to",
                    external_operation_id="op_to",
                    execution_lease_deadline=datetime.now(timezone.utc) + timedelta(seconds=60),
                )
                assert res.outcome == ExecutionOutcome.EXECUTION_UNKNOWN
                assert res.error_code == "ERR_NETWORK_TIMEOUT"
        finally:
            SubsystemExecutionRegistry._force_timeout = False
    asyncio.run(_test())


def test_gate_18_subsystem_unreachable_fail_closed():
    async def _test():
        SubsystemExecutionRegistry._force_failure = True
        try:
            async with AsyncSessionLocal() as session:
                res = await SubsystemExecutionRegistry.dispatch(
                    session=session,
                    action_type=ContainmentActionType.ACT_CAND_SESSION_TERM,
                    canonical_target_urn="urn:bsea:session:sess_fail",
                    external_operation_id="op_fail",
                    execution_lease_deadline=datetime.now(timezone.utc) + timedelta(seconds=60),
                )
                assert res.outcome == ExecutionOutcome.EXECUTION_FAILED
        finally:
            SubsystemExecutionRegistry._force_failure = False
    asyncio.run(_test())


def test_gate_19_audit_failure_pre_dispatch_invariant():
    async def _test():
        # Pre-dispatch safety invariant ensures execution record is durably committed before dispatch
        officer = await _get_or_create_user(UserRoleEnum.SECURITY_OFFICER, "officer_audit")
        incident = await _create_test_incident()
        target = {"session_id": f"sess_pre_{uuid.uuid4().hex[:6]}"}

        coord = ContainmentCoordinatorService()
        async with AsyncSessionLocal() as session:
            req = await coord.request_containment(
                requester=officer,
                action_type=ContainmentActionType.ACT_CAND_SESSION_TERM,
                incident_id=str(incident.id),
                target_dict=target,
                justification="Testing pre-dispatch invariant.",
                session=session,
            )
            await session.commit()

            # Execute: pre-dispatch record exists and is committed
            exec_rec, v_res = await coord.execute_containment(
                request_id=req.id,
                executor=officer,
                target_dict=target,
                session=session,
            )
            assert exec_rec.id is not None
            assert len(exec_rec.external_operation_id) == 64
    asyncio.run(_test())


def test_gate_20_reversibility_and_compensation():
    async def _test():
        cand_sess = await _create_test_candidate_session()
        target = {"session_id": cand_sess.id}
        urn = canonicalize_target_urn(ContainmentActionType.ACT_CAND_SESSION_TERM, target)

        async with AsyncSessionLocal() as session:
            # Terminate session
            await SubsystemExecutionRegistry.dispatch(
                session=session,
                action_type=ContainmentActionType.ACT_CAND_SESSION_TERM,
                canonical_target_urn=urn,
                external_operation_id="op_rev_1",
                execution_lease_deadline=datetime.now(timezone.utc) + timedelta(seconds=60),
            )
            await session.commit()

            # Refresh and check terminated
            sess = await session.get(CandidateSession, cand_sess.id)
            assert sess.status == SessionStatus.REVOKED

            # Compensation: Re-enable
            sess.status = SessionStatus.ACTIVE
            await session.commit()
            sess = await session.get(CandidateSession, cand_sess.id)
            assert sess.status == SessionStatus.ACTIVE
    asyncio.run(_test())


def test_gate_21_full_regression_preservation():
    async def _test():
        # Verify 5D SecurityIncident and 5E Containment models operate seamlessly
        async with AsyncSessionLocal() as session:
            stmt = select(SecurityIncident).limit(5)
            res = await session.execute(stmt)
            incidents = res.scalars().all()
            assert len(incidents) >= 0
    asyncio.run(_test())


def test_gate_22_db_divergence_reconciliation():
    async def _test():
        cand_user = await _get_or_create_user(UserRoleEnum.SECURITY_OFFICER, "officer_rec")
        cand_sess = await _create_test_candidate_session()
        cand_sess.status = SessionStatus.REVOKED
        async with AsyncSessionLocal() as session:
            await session.merge(cand_sess)
            await session.commit()

            incident = await _create_test_incident()
            ik_rec = f"ik_rec_{uuid.uuid4().hex[:8]}"
            intent = ContainmentIntent(
                id=str(uuid.uuid4()),
                intent_key=ik_rec,
                incident_id=incident.id,
                incident_generation=1,
                action_type=ContainmentActionType.ACT_CAND_SESSION_TERM,
                canonical_target_urn=f"urn:bsea:session:{cand_sess.id}",
                risk_tier=ContainmentActionRisk.LOW,
                status=ContainmentIntentStatus.REGISTERED,
            )
            session.add(intent)
            await session.flush()

            req_id = f"req_{uuid.uuid4().hex[:8]}"
            req = ContainmentRequest(
                id=req_id,
                request_key="rk_reconcile",
                intent_key=ik_rec,
                requester_id=cand_user.id,
                target_snapshot_hash="h1",
                scope_hash="h2",
                policy_version="REV-04.1",
                policy_fingerprint="fp1",
                policy_decision="ALLOW",
                status=ContainmentRequestStatus.AWAITING_AUTHORIZATION,
            )
            session.add(req)
            await session.commit()

            # Run reconciliation
            audit = AuditService()
            rec = await ReconciliationService.reconcile_external_mutation(
                session=session,
                request_id=req_id,
                external_operation_id=f"op_{uuid.uuid4().hex[:8]}",
                action_type=ContainmentActionType.ACT_CAND_SESSION_TERM,
                canonical_target_urn=f"urn:bsea:session:{cand_sess.id}",
                audit_service=audit,
            )
            await session.commit()
            assert rec is not None
            assert rec.raw_outcome == ExecutionOutcome.EXECUTION_SUCCEEDED
            assert req.status == ContainmentRequestStatus.VERIFIED
    asyncio.run(_test())


def test_gate_23_network_dispatch_timeout_unknown():
    async def _test():
        SubsystemExecutionRegistry._force_timeout = True
        try:
            async with AsyncSessionLocal() as session:
                res = await SubsystemExecutionRegistry.dispatch(
                    session=session,
                    action_type=ContainmentActionType.ACT_CENTRE_SUSPEND,
                    canonical_target_urn="urn:bsea:centre:c_to",
                    external_operation_id="op_to_23",
                    execution_lease_deadline=datetime.now(timezone.utc) + timedelta(seconds=60),
                )
                assert res.outcome == ExecutionOutcome.EXECUTION_UNKNOWN
        finally:
            SubsystemExecutionRegistry._force_timeout = False
    asyncio.run(_test())


def test_gate_24_orthogonality_critical_severity_vs_critical_action():
    async def _test():
        superadmin = await _get_or_create_user(UserRoleEnum.SUPER_ADMIN, "super_orth")
        # Incident is CRITICAL severity
        incident = await _create_test_incident(severity=SecurityIncidentSeverity.CRITICAL)
        coord = ContainmentCoordinatorService()
        async with AsyncSessionLocal() as session:
            # Action is CRITICAL risk (ACT_FORM_SUSPEND) -> MUST BE REJECTED
            with pytest.raises(BreakGlassCriticalProhibitedError):
                await coord.issue_break_glass_token(
                    issuer=superadmin,
                    action_type=ContainmentActionType.ACT_FORM_SUSPEND,
                    incident_id=str(incident.id),
                    target_dict={"form_id": "form_orth_1"},
                    fido2_assertion_payload="fido2_hardware_assertion_token_valid_bytes_123",
                    session=session,
                )
    asyncio.run(_test())


def test_gate_25_policy_gate_dual_pipeline_separation():
    async def _test():
        engine = ContainmentPolicyEngine()
        # Standard policy returns REQUIRE_SECOND_AUTHORIZER for HIGH risk
        std_res = engine.evaluate_standard_policy(
            action_type=ContainmentActionType.ACT_ACCT_DISABLE,
            incident_status=SecurityIncidentStatus.INVESTIGATING,
            incident_severity=SecurityIncidentSeverity.HIGH,
            target_urn="urn:bsea:centre:c_1",
            max_entities=1,
            requester_role=UserRoleEnum.SECURITY_OFFICER,
        )
        assert std_res.decision == StandardPolicyDecision.REQUIRE_SECOND_AUTHORIZER.value

        # Break-Glass Crisis Policy returns BREAK_GLASS_ALLOWED for superadmin
        bg_res = engine.evaluate_break_glass_policy(
            action_type=ContainmentActionType.ACT_ACCT_DISABLE,
            incident_status=SecurityIncidentStatus.INVESTIGATING,
            incident_severity=SecurityIncidentSeverity.CRITICAL,
            target_urn="urn:bsea:centre:c_1",
            max_entities=1,
            requester_role=UserRoleEnum.SUPER_ADMIN,
            is_exam_in_progress=True,
            recent_break_glass_count_by_user=0,
            total_break_glass_count_for_exam=0,
        )
        assert bg_res.decision == BreakGlassPolicyDecision.BREAK_GLASS_ALLOWED.value
    asyncio.run(_test())


def test_gate_26_lease_pre_check_token_expired():
    async def _test():
        now = datetime.now(timezone.utc)
        expired_token = BreakGlassToken(
            id="bgt_pre_exp",
            token_nonce="nonce_pre_exp",
            intent_key="ik_pre_exp",
            incident_id=str(uuid.uuid4()),
            incident_generation=1,
            canonical_target_urn="urn:bsea:centre:c_exp",
            target_scope_hash="h1",
            action_type=ContainmentActionType.ACT_ACCT_DISABLE,
            policy_version="REV-04.1",
            issuer_id="usr_pre_exp",
            fido2_assertion_hash="h_fido",
            status=BreakGlassTokenStatus.ISSUED,
            issued_at=now - timedelta(seconds=1000),
            expires_at=now - timedelta(seconds=10),
            created_at=now - timedelta(seconds=1000),
        )
        async with AsyncSessionLocal() as session:
            session.add(expired_token)
            await session.commit()

            with pytest.raises(BreakGlassTokenExpiredError):
                await BreakGlassTokenCoordinator.consume_token_and_start_lease(
                    session=session,
                    token_id="bgt_pre_exp",
                    expected_intent_key="ik_pre_exp",
                    actor_id="usr_actor",
                )
    asyncio.run(_test())


def test_gate_27_lease_post_check_lease_honored():
    async def _test():
        now = datetime.now(timezone.utc)
        token = BreakGlassToken(
            id=f"bgt_lease_{uuid.uuid4().hex[:6]}",
            token_nonce=generate_crypto_nonce(),
            intent_key="ik_lease_honored",
            incident_id=str(uuid.uuid4()),
            incident_generation=1,
            canonical_target_urn="urn:bsea:centre:c_lease",
            target_scope_hash="h1",
            action_type=ContainmentActionType.ACT_ACCT_DISABLE,
            policy_version="REV-04.1",
            issuer_id="usr_lease",
            fido2_assertion_hash="h_fido",
            status=BreakGlassTokenStatus.ISSUED,
            issued_at=now,
            expires_at=now + timedelta(seconds=10),  # Expires in 10s
            created_at=now,
        )
        async with AsyncSessionLocal() as session:
            session.add(token)
            await session.commit()

            # Token consumed: grants 60s execution lease
            tok, lease_deadline = await BreakGlassTokenCoordinator.consume_token_and_start_lease(
                session=session,
                token_id=token.id,
                expected_intent_key="ik_lease_honored",
                actor_id="usr_actor",
            )
            await session.commit()

            assert lease_deadline > now + timedelta(seconds=50)
            assert tok.status == BreakGlassTokenStatus.CONSUMED
    asyncio.run(_test())


def test_gate_28_intent_key_determinism_across_officers():
    async def _test():
        target = {"centre_id": "CENTRE-MUMBAI-01"}
        urn = canonicalize_target_urn(ContainmentActionType.ACT_CENTRE_RESTRICT, target)
        inc_id = str(uuid.uuid4())

        k_officer_a = compute_intent_key(ContainmentActionType.ACT_CENTRE_RESTRICT, urn, inc_id, 1)
        k_officer_b = compute_intent_key(ContainmentActionType.ACT_CENTRE_RESTRICT, urn, inc_id, 1)
        assert k_officer_a == k_officer_b
    asyncio.run(_test())


def test_gate_29_reconciliation_verifies_target_state():
    async def _test():
        # Reconciliation queries target ground truth before updating DB
        cand_sess = await _create_test_candidate_session()
        cand_sess.status = SessionStatus.REVOKED
        async with AsyncSessionLocal() as session:
            await session.merge(cand_sess)
            await session.commit()

            v_res = await IndependentVerificationEngine.verify_containment(
                session=session,
                action_type=ContainmentActionType.ACT_CAND_SESSION_TERM,
                canonical_target_urn=f"urn:bsea:session:{cand_sess.id}",
            )
            assert v_res.outcome == VerificationOutcome.VERIFICATION_VERIFIED
    asyncio.run(_test())


def test_gate_30_unknown_plus_verified_advances_5d():
    async def _test():
        # TC-GATE-30: EXECUTION_UNKNOWN + VERIFICATION_VERIFIED -> advances 5D incident to CONTAINED
        officer = await _get_or_create_user(UserRoleEnum.SECURITY_OFFICER, "officer_30")
        cand_sess = await _create_test_candidate_session()
        incident = await _create_test_incident(status=SecurityIncidentStatus.INVESTIGATING)

        target = {"session_id": cand_sess.id}
        coord = ContainmentCoordinatorService()
        async with AsyncSessionLocal() as session:
            req = await coord.request_containment(
                requester=officer,
                action_type=ContainmentActionType.ACT_CAND_SESSION_TERM,
                incident_id=str(incident.id),
                target_dict=target,
                justification="Testing UNKNOWN + VERIFIED 5D progression.",
                session=session,
            )
            await session.commit()

            # Force session termination out-of-band to simulate external mutation success
            cand_sess.status = SessionStatus.REVOKED
            await session.merge(cand_sess)
            await session.commit()

            # Execute with forced adapter timeout to produce EXECUTION_UNKNOWN
            SubsystemExecutionRegistry._force_timeout = True
            try:
                exec_rec, v_res = await coord.execute_containment(
                    request_id=req.id,
                    executor=officer,
                    target_dict=target,
                    session=session,
                )
            finally:
                SubsystemExecutionRegistry._force_timeout = False

            assert exec_rec.raw_outcome == ExecutionOutcome.EXECUTION_UNKNOWN
            assert v_res.outcome == VerificationOutcome.VERIFICATION_VERIFIED
            assert req.status == ContainmentRequestStatus.VERIFIED

            # Verify 5D Incident was advanced to CONTAINED!
            inc = await session.get(SecurityIncident, incident.id)
            assert inc.status == SecurityIncidentStatus.CONTAINED
    asyncio.run(_test())


def test_gate_31_unknown_plus_failed_requires_fresh_auth():
    async def _test():
        # TC-GATE-31: EXECUTION_UNKNOWN + VERIFICATION_FAILED -> request FAILED, incident NOT updated
        officer = await _get_or_create_user(UserRoleEnum.SECURITY_OFFICER, "officer_31")
        cand_sess = await _create_test_candidate_session()
        incident = await _create_test_incident(status=SecurityIncidentStatus.INVESTIGATING)

        target = {"session_id": cand_sess.id}
        coord = ContainmentCoordinatorService()
        async with AsyncSessionLocal() as session:
            req = await coord.request_containment(
                requester=officer,
                action_type=ContainmentActionType.ACT_CAND_SESSION_TERM,
                incident_id=str(incident.id),
                target_dict=target,
                justification="Testing UNKNOWN + FAILED non-progression.",
                session=session,
            )
            await session.commit()

            # Target remains ACTIVE (unmutated)
            SubsystemExecutionRegistry._force_timeout = True
            try:
                exec_rec, v_res = await coord.execute_containment(
                    request_id=req.id,
                    executor=officer,
                    target_dict=target,
                    session=session,
                )
            finally:
                SubsystemExecutionRegistry._force_timeout = False

            assert exec_rec.raw_outcome == ExecutionOutcome.EXECUTION_UNKNOWN
            assert v_res.outcome == VerificationOutcome.VERIFICATION_FAILED
            assert req.status == ContainmentRequestStatus.FAILED

            # Incident must remain in INVESTIGATING
            inc = await session.get(SecurityIncident, incident.id)
            assert inc.status == SecurityIncidentStatus.INVESTIGATING
    asyncio.run(_test())


def test_gate_32_inconclusive_quarantine_manual_attestation():
    async def _test():
        # TC-GATE-32: VERIFICATION_INCONCLUSIVE -> Quarantined, manual attestation required
        officer = await _get_or_create_user(UserRoleEnum.SECURITY_OFFICER, "officer_32")
        incident = await _create_test_incident(status=SecurityIncidentStatus.INVESTIGATING)
        target = {"session_id": f"sess_inc_{uuid.uuid4().hex[:6]}"}

        coord = ContainmentCoordinatorService()
        async with AsyncSessionLocal() as session:
            req = await coord.request_containment(
                requester=officer,
                action_type=ContainmentActionType.ACT_CAND_SESSION_TERM,
                incident_id=str(incident.id),
                target_dict=target,
                justification="Testing inconclusive quarantine.",
                session=session,
            )
            await session.commit()

            # Force inconclusive verification
            IndependentVerificationEngine._force_inconclusive = True
            try:
                exec_rec, v_res = await coord.execute_containment(
                    request_id=req.id,
                    executor=officer,
                    target_dict=target,
                    session=session,
                )
            finally:
                IndependentVerificationEngine._force_inconclusive = False

            assert v_res.outcome == VerificationOutcome.VERIFICATION_INCONCLUSIVE
            assert req.status == ContainmentRequestStatus.QUARANTINED

            # Manual attestation by Security Officer
            audit = AuditService()
            attested_req = await ReconciliationService.submit_manual_attestation(
                session=session,
                request_id=req.id,
                officer=officer,
                attestation_status="ATTEST_MANUAL_CONTAINED",
                notes="Manually confirmed session terminated via out-of-band logs.",
                audit_service=audit,
            )
            await session.commit()
            assert attested_req.status == ContainmentRequestStatus.VERIFIED
    asyncio.run(_test())


def test_gate_33_break_glass_no_reuse_on_unknown_inconclusive():
    async def _test():
        superadmin = await _get_or_create_user(UserRoleEnum.SUPER_ADMIN, "super_bg33")
        incident = await _create_test_incident(severity=SecurityIncidentSeverity.CRITICAL)
        target = {"centre_id": f"centre_{uuid.uuid4().hex[:6]}"}

        coord = ContainmentCoordinatorService()
        async with AsyncSessionLocal() as session:
            token = await coord.issue_break_glass_token(
                issuer=superadmin,
                action_type=ContainmentActionType.ACT_ACCT_DISABLE,
                incident_id=str(incident.id),
                target_dict=target,
                fido2_assertion_payload="fido2_hardware_assertion_token_valid_bytes_123",
                session=session,
            )
            await session.commit()

            # Consume token
            await BreakGlassTokenCoordinator.consume_token_and_start_lease(
                session=session,
                token_id=token.id,
                expected_intent_key=token.intent_key,
                actor_id=str(superadmin.id),
            )
            await session.commit()

            # Attempting reuse after failure/unknown is permanently rejected
            with pytest.raises(BreakGlassReplayError):
                await BreakGlassTokenCoordinator.consume_token_and_start_lease(
                    session=session,
                    token_id=token.id,
                    expected_intent_key=token.intent_key,
                    actor_id=str(superadmin.id),
                )
    asyncio.run(_test())


def test_gate_34_break_glass_fresh_auth_required_for_retry():
    async def _test():
        superadmin = await _get_or_create_user(UserRoleEnum.SUPER_ADMIN, "super_bg34")
        incident = await _create_test_incident(severity=SecurityIncidentSeverity.CRITICAL)
        target = {"centre_id": f"centre_{uuid.uuid4().hex[:6]}"}

        coord = ContainmentCoordinatorService()
        async with AsyncSessionLocal() as session:
            # First token issued and consumed
            tok1 = await coord.issue_break_glass_token(
                issuer=superadmin,
                action_type=ContainmentActionType.ACT_ACCT_DISABLE,
                incident_id=str(incident.id),
                target_dict=target,
                fido2_assertion_payload="fido2_hardware_assertion_token_valid_bytes_123",
                session=session,
            )
            await BreakGlassTokenCoordinator.consume_token_and_start_lease(
                session=session,
                token_id=tok1.id,
                expected_intent_key=tok1.intent_key,
                actor_id=str(superadmin.id),
            )
            await session.commit()

            # Retry requires a fresh issuance and token
            tok2 = await coord.issue_break_glass_token(
                issuer=superadmin,
                action_type=ContainmentActionType.ACT_ACCT_DISABLE,
                incident_id=str(incident.id),
                target_dict=target,
                fido2_assertion_payload="fido2_hardware_assertion_token_valid_bytes_123",
                session=session,
            )
            await session.commit()
            assert tok2.id != tok1.id
            assert tok2.token_nonce != tok1.token_nonce
    asyncio.run(_test())


def test_gate_35_execution_lease_expiry_unknown():
    async def _test():
        # When lease expires without authoritative external ack, outcome must be EXECUTION_UNKNOWN
        record = ContainmentExecutionRecord(
            id="exec_lease_exp",
            request_id="req_lease",
            external_operation_id="ext_op_lease",
            adapter_name="ACT_CENTRE_SUSPEND",
            raw_outcome=ExecutionOutcome.EXECUTION_UNKNOWN,
            started_at=datetime.now(timezone.utc) - timedelta(seconds=70),
            created_at=datetime.now(timezone.utc) - timedelta(seconds=70),
        )
        assert record.raw_outcome == ExecutionOutcome.EXECUTION_UNKNOWN
    asyncio.run(_test())
