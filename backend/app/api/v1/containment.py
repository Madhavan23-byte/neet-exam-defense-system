"""
B-SEA -- Phase 3C-5E Policy-Governed Security Containment API
REST endpoints for initiating, authorizing, executing, verifying, and reconciling containment actions.
"""
from __future__ import annotations

from typing import Optional, Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.dependencies import get_current_user, require_role
from app.core.models import User, UserRoleEnum
from app.modules.containment.models import (
    ContainmentActionType,
    ContainmentIntent,
    ContainmentRequest,
    ContainmentExecutionRecord,
    ContainmentVerificationProof,
)
from app.modules.containment.service import (
    ContainmentCoordinatorService,
    ContainmentServiceError,
    ContainmentPolicyDeniedError,
    TargetStateMismatchError,
)
from app.modules.containment.authorization import (
    DualControlSelfApprovalError,
    InsufficientQuorumError,
    ReplayAttackError,
)
from app.modules.containment.break_glass import (
    BreakGlassError,
    BreakGlassCriticalProhibitedError,
    BreakGlassTokenExpiredError,
    BreakGlassReplayError,
)
from app.modules.containment.reconciliation import ReconciliationService
from app.modules.audit.service import AuditService

router = APIRouter()


class ContainmentCreateRequest(BaseModel):
    action_type: str = Field(..., description="Containment action enum value")
    incident_id: str = Field(..., description="5D Security Incident UUID")
    target_dict: Dict[str, Any] = Field(..., description="Target entity parameters")
    justification: str = Field(..., min_length=10, description="Audit justification for containment")
    max_allowed_entities: int = Field(default=1, ge=1, le=10)


class ContainmentAuthorizeRequest(BaseModel):
    auth_nonce: str = Field(..., min_length=16, description="Cryptographic single-use authorization nonce")
    signature: Optional[str] = Field(default=None, description="Optional digital signature")


class ContainmentExecuteRequest(BaseModel):
    target_dict: Dict[str, Any] = Field(..., description="Target entity parameters for execution")


class BreakGlassIssueRequest(BaseModel):
    incident_id: str
    action_type: str
    target_dict: Dict[str, Any]
    fido2_assertion: str = Field(..., min_length=16)
    is_exam_in_progress: bool = True


class BreakGlassExecuteRequest(BaseModel):
    token_id: str
    target_dict: Dict[str, Any]
    justification: str = Field(..., min_length=10)


class ReconcileRequest(BaseModel):
    request_id: str
    external_operation_id: str
    action_type: str
    canonical_target_urn: str


class ManualAttestationRequest(BaseModel):
    request_id: str
    attestation_status: str  # ATTEST_MANUAL_CONTAINED or ATTEST_MANUAL_FAILED
    notes: str = Field(..., min_length=10)


@router.post("/requests", dependencies=[Depends(require_role("SECURITY_OFFICER", "SUPER_ADMIN"))])
async def create_containment_request(
    body: ContainmentCreateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Request a security containment action against a compromised or suspicious entity.
    Evaluates standard policy and initiates intent / request state.
    """
    try:
        action_type = ContainmentActionType(body.action_type)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid action_type '{body.action_type}'.",
        )

    service = ContainmentCoordinatorService(db_session=db)
    try:
        req = await service.request_containment(
            requester=current_user,
            action_type=action_type,
            incident_id=body.incident_id,
            target_dict=body.target_dict,
            justification=body.justification,
            max_allowed_entities=body.max_allowed_entities,
            session=db,
        )
        return {
            "status": "SUCCESS",
            "request_id": str(req.id),
            "intent_key": req.intent_key,
            "request_key": req.request_key,
            "request_status": req.status.value,
            "policy_decision": req.policy_decision,
            "policy_version": req.policy_version,
        }
    except ContainmentPolicyDeniedError as ex:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(ex))
    except Exception as ex:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ex))


@router.post("/requests/{request_id}/authorize", dependencies=[Depends(require_role("SECURITY_OFFICER", "SUPER_ADMIN"))])
async def authorize_containment_request(
    request_id: str,
    body: ContainmentAuthorizeRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Submit dual-control authorization for a pending containment request.
    Strictly prohibits self-approval and enforces role quorum.
    """
    service = ContainmentCoordinatorService(db_session=db)
    try:
        auth = await service.authorize_containment(
            request_id=request_id,
            approver=current_user,
            auth_nonce=body.auth_nonce,
            signature=body.signature,
            session=db,
        )
        return {
            "status": "SUCCESS",
            "authorization_id": str(auth.id),
            "request_id": str(auth.request_id),
            "approver_id": str(auth.approver_id),
            "expires_at": auth.expires_at.isoformat(),
        }
    except DualControlSelfApprovalError as ex:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(ex))
    except (InsufficientQuorumError, ReplayAttackError) as ex:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ex))
    except Exception as ex:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ex))


@router.post("/requests/{request_id}/execute", dependencies=[Depends(require_role("SECURITY_OFFICER", "SUPER_ADMIN"))])
async def execute_containment_request(
    request_id: str,
    body: ContainmentExecuteRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Execute authorized containment action through subsystem adapters with independent verification.
    """
    service = ContainmentCoordinatorService(db_session=db)
    try:
        exec_record, verif_result = await service.execute_containment(
            request_id=request_id,
            executor=current_user,
            target_dict=body.target_dict,
            session=db,
        )
        return {
            "status": "SUCCESS",
            "execution_id": str(exec_record.id),
            "external_operation_id": exec_record.external_operation_id,
            "raw_outcome": exec_record.raw_outcome.value,
            "verification_outcome": verif_result.outcome.value,
            "observed_state": verif_result.observed_target_state,
            "proof_hash": verif_result.proof_hash,
        }
    except TargetStateMismatchError as ex:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(ex))
    except Exception as ex:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ex))


@router.get("/requests/{request_id}", dependencies=[Depends(require_role("SECURITY_OFFICER", "SUPER_ADMIN"))])
async def get_containment_request(
    request_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Fetch containment request status, execution records, and verification proofs.
    """
    req = await db.get(ContainmentRequest, request_id)
    if not req:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Request '{request_id}' not found.")

    stmt_intent = select(ContainmentIntent).where(ContainmentIntent.intent_key == req.intent_key)
    res_intent = await db.execute(stmt_intent)
    intent = res_intent.scalar_one_or_none()

    stmt_exec = select(ContainmentExecutionRecord).where(ContainmentExecutionRecord.request_id == req.id)
    res_exec = await db.execute(stmt_exec)
    exec_records = res_exec.scalars().all()

    return {
        "request_id": str(req.id),
        "request_key": req.request_key,
        "intent_key": req.intent_key,
        "status": req.status.value,
        "policy_decision": req.policy_decision,
        "policy_version": req.policy_version,
        "requester_id": str(req.requester_id),
        "intent": {
            "action_type": intent.action_type.value if intent else None,
            "canonical_target_urn": intent.canonical_target_urn if intent else None,
            "risk_tier": intent.risk_tier.value if intent else None,
            "status": intent.status.value if intent else None,
        } if intent else None,
        "execution_records_count": len(exec_records),
    }


@router.post("/break-glass/issue", dependencies=[Depends(require_role("SUPER_ADMIN"))])
async def issue_break_glass_token(
    body: BreakGlassIssueRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Issue an emergency single-use Break-Glass token. (SUPER_ADMIN only).
    """
    try:
        action_type = ContainmentActionType(body.action_type)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid action_type '{body.action_type}'.")

    service = ContainmentCoordinatorService(db_session=db)
    try:
        token = await service.issue_break_glass_token(
            issuer=current_user,
            action_type=action_type,
            incident_id=body.incident_id,
            target_dict=body.target_dict,
            fido2_assertion_payload=body.fido2_assertion,
            is_exam_in_progress=body.is_exam_in_progress,
            session=db,
        )
        return {
            "status": "SUCCESS",
            "token_id": str(token.id),
            "token_nonce": token.token_nonce,
            "intent_key": token.intent_key,
            "action_type": token.action_type.value,
            "expires_at": token.expires_at.isoformat(),
        }
    except BreakGlassCriticalProhibitedError as ex:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(ex))
    except BreakGlassError as ex:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ex))


@router.post("/break-glass/execute", dependencies=[Depends(require_role("SUPER_ADMIN"))])
async def execute_break_glass(
    body: BreakGlassExecuteRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Execute emergency Break-Glass containment. Atomically consumes token.
    """
    service = ContainmentCoordinatorService(db_session=db)
    try:
        exec_record, verif_result = await service.execute_break_glass(
            token_id=body.token_id,
            executor=current_user,
            target_dict=body.target_dict,
            justification=body.justification,
            session=db,
        )
        return {
            "status": "SUCCESS",
            "execution_id": str(exec_record.id),
            "raw_outcome": exec_record.raw_outcome.value,
            "verification_outcome": verif_result.outcome.value,
            "proof_hash": verif_result.proof_hash,
        }
    except (BreakGlassTokenExpiredError, BreakGlassReplayError) as ex:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(ex))
    except Exception as ex:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ex))


@router.post("/reconcile", dependencies=[Depends(require_role("SECURITY_OFFICER", "SUPER_ADMIN"))])
async def reconcile_external_mutation(
    body: ReconcileRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Reconstruct and reconcile an execution record when PostgreSQL rolled back after dispatch.
    """
    try:
        action_type = ContainmentActionType(body.action_type)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid action_type '{body.action_type}'.")

    audit = AuditService()
    record = await ReconciliationService.reconcile_external_mutation(
        session=db,
        request_id=body.request_id,
        external_operation_id=body.external_operation_id,
        action_type=action_type,
        canonical_target_urn=body.canonical_target_urn,
        audit_service=audit,
    )
    return {
        "status": "SUCCESS",
        "reconciled": record is not None,
        "execution_id": str(record.id) if record else None,
    }


@router.post("/attest", dependencies=[Depends(require_role("SECURITY_OFFICER", "SUPER_ADMIN"))])
async def submit_manual_attestation(
    body: ManualAttestationRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Submit manual Security Officer attestation for QUARANTINED containment requests.
    """
    audit = AuditService()
    req = await ReconciliationService.submit_manual_attestation(
        session=db,
        request_id=body.request_id,
        officer=current_user,
        attestation_status=body.attestation_status,
        notes=body.notes,
        audit_service=audit,
    )
    return {
        "status": "SUCCESS",
        "request_id": str(req.id),
        "new_status": req.status.value,
    }
