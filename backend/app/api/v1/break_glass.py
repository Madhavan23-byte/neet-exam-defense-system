"""
B-SEA — Phase 3B Break-Glass & Controlled Complete-Paper Exception API
Protected endpoints for emergency complete-paper access.
"""
from __future__ import annotations

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.core.dependencies import (
    get_current_user,
    get_current_session_id,
    require_permission,
)
from app.core.models import (
    BreakGlassRequest,
    BreakGlassApproval,
    BreakGlassRequestStatus,
    BreakGlassApprovalDecision,
    User,
    UserRoleEnum,
)
from app.modules.break_glass.schemas import (
    CreateBreakGlassRequest,
    SubmitApprovalRequest,
    RevokeBreakGlassRequest,
    BreakGlassRequestResponse,
    BreakGlassApprovalResponse,
    AssembledPaperResponse,
)
from app.modules.break_glass.service import BreakGlassService

router = APIRouter()


def _serialize_request(req: BreakGlassRequest, approvals: Optional[List[BreakGlassApproval]] = None) -> BreakGlassRequestResponse:
    if approvals is None:
        try:
            from sqlalchemy.orm import attributes
            state = attributes.instance_state(req)
            if "approvals" in state.dict and state.dict["approvals"] is not None:
                approvals = state.dict["approvals"]
            else:
                approvals = []
        except Exception:
            approvals = []

    approvals = approvals or []
    valid_approvals = [a for a in approvals if a.is_valid and a.decision == BreakGlassApprovalDecision.APPROVE]
    distinct_roles = {a.approver_role for a in valid_approvals}

    return BreakGlassRequestResponse(
        id=req.id,
        exam_id=req.exam_id,
        blueprint_id=req.blueprint_id,
        exam_version=req.exam_version,
        blueprint_hash=req.blueprint_hash,
        requester_id=req.requester_id,
        scope=req.scope,
        form_label=req.form_label,
        justification=req.justification,
        incident_id=req.incident_id,
        required_quorum=req.required_quorum,
        min_distinct_roles=req.min_distinct_roles,
        status=req.status,
        requested_duration_minutes=req.requested_duration_minutes,
        activation_session_id=req.activation_session_id,
        content_fingerprint=req.content_fingerprint,
        policy_version=req.policy_version,
        created_at=req.created_at,
        approved_at=req.approved_at,
        activated_at=req.activated_at,
        expires_at=req.expires_at,
        revoked_at=req.revoked_at,
        revoked_by=req.revoked_by,
        revocation_reason=req.revocation_reason,
        correlation_id=req.correlation_id,
        approvals_count=len(valid_approvals),
        distinct_roles_count=len(distinct_roles),
        approvals=[
            BreakGlassApprovalResponse(
                id=a.id,
                request_id=a.request_id,
                approver_id=a.approver_id,
                approver_role=a.approver_role,
                decision=a.decision,
                comments=a.comments,
                nonce=a.nonce,
                request_fingerprint=a.request_fingerprint,
                digital_signature=a.digital_signature,
                is_valid=a.is_valid,
                created_at=a.created_at,
            )
            for a in approvals
        ],
    )


@router.post(
    "/requests",
    response_model=BreakGlassRequestResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("break_glass:request"))],
)
async def create_break_glass_request(
    body: CreateBreakGlassRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Create a new Break-Glass emergency access request.
    Binds to requester user identity. Does not bind session JTI until activation.
    """
    service = BreakGlassService(db)
    req = await service.create_request(
        requester=current_user,
        exam_id=body.exam_id,
        scope=body.scope,
        justification=body.justification,
        form_label=body.form_label,
        incident_id=body.incident_id,
        requested_duration_minutes=body.requested_duration_minutes,
    )
    return _serialize_request(req, approvals=[])


@router.get(
    "/requests",
    response_model=List[BreakGlassRequestResponse],
    dependencies=[Depends(require_permission("break_glass:view"))],
)
async def list_break_glass_requests(
    exam_id: Optional[str] = None,
    status_filter: Optional[BreakGlassRequestStatus] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List break-glass requests with optional filtering."""
    query = (
        select(BreakGlassRequest)
        .options(selectinload(BreakGlassRequest.approvals))
        .order_by(BreakGlassRequest.created_at.desc())
    )

    if exam_id:
        query = query.where(BreakGlassRequest.exam_id == exam_id)
    if status_filter:
        query = query.where(BreakGlassRequest.status == status_filter)

    result = await db.execute(query)
    requests = result.scalars().all()
    from app.core.models import utcnow
    now = utcnow()
    changed = False
    for r in requests:
        if r.status == BreakGlassRequestStatus.ACTIVATED and r.expires_at and now >= r.expires_at:
            r.status = BreakGlassRequestStatus.EXPIRED
            changed = True
    if changed:
        await db.commit()
    return [_serialize_request(r) for r in requests]


@router.get(
    "/requests/{request_id}",
    response_model=BreakGlassRequestResponse,
    dependencies=[Depends(require_permission("break_glass:view"))],
)
async def get_break_glass_request(
    request_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get details of a specific break-glass request including approval progress."""
    query = (
        select(BreakGlassRequest)
        .options(selectinload(BreakGlassRequest.approvals))
        .where(BreakGlassRequest.id == request_id)
    )
    result = await db.execute(query)
    req = result.scalar_one_or_none()
    if not req:
        raise HTTPException(status_code=404, detail="Break-glass request not found")

    from app.core.models import utcnow
    if req.status == BreakGlassRequestStatus.ACTIVATED and req.expires_at and utcnow() >= req.expires_at:
        req.status = BreakGlassRequestStatus.EXPIRED
        await db.commit()

    return _serialize_request(req)


@router.post(
    "/requests/{request_id}/approve",
    response_model=BreakGlassApprovalResponse,
    dependencies=[Depends(require_permission("break_glass:approve"))],
)
async def approve_break_glass_request(
    request_id: str,
    body: SubmitApprovalRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Submit a signed approval vote for a break-glass request.
    Enforces separation of duties and evaluates headcount quorum & role diversity.
    """
    service = BreakGlassService(db)
    approval = await service.submit_approval(
        approver=current_user,
        request_id=request_id,
        decision=BreakGlassApprovalDecision.APPROVE,
        comments=body.comments,
    )
    return BreakGlassApprovalResponse(
        id=approval.id,
        request_id=approval.request_id,
        approver_id=approval.approver_id,
        approver_role=approval.approver_role,
        decision=approval.decision,
        comments=approval.comments,
        nonce=approval.nonce,
        request_fingerprint=approval.request_fingerprint,
        digital_signature=approval.digital_signature,
        is_valid=approval.is_valid,
        created_at=approval.created_at,
    )


@router.post(
    "/requests/{request_id}/reject",
    response_model=BreakGlassApprovalResponse,
    dependencies=[Depends(require_permission("break_glass:approve"))],
)
async def reject_break_glass_request(
    request_id: str,
    body: SubmitApprovalRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Reject a pending break-glass request.
    Marks the request immediately as terminal REJECTED.
    """
    service = BreakGlassService(db)
    approval = await service.submit_approval(
        approver=current_user,
        request_id=request_id,
        decision=BreakGlassApprovalDecision.REJECT,
        comments=body.comments,
    )
    return BreakGlassApprovalResponse(
        id=approval.id,
        request_id=approval.request_id,
        approver_id=approval.approver_id,
        approver_role=approval.approver_role,
        decision=approval.decision,
        comments=approval.comments,
        nonce=approval.nonce,
        request_fingerprint=approval.request_fingerprint,
        digital_signature=approval.digital_signature,
        is_valid=approval.is_valid,
        created_at=approval.created_at,
    )


@router.post(
    "/requests/{request_id}/activate",
    response_model=BreakGlassRequestResponse,
)
async def activate_break_glass_request(
    request_id: str,
    current_user: User = Depends(get_current_user),
    session_id: Optional[str] = Depends(get_current_session_id),
    db: AsyncSession = Depends(get_db),
):
    """
    Activate an APPROVED break-glass request.
    Binds the requester's fresh JWT JTI session to the request and starts the countdown timer.
    """
    if not session_id:
        raise HTTPException(
            status_code=400,
            detail="Valid authenticated session JTI required for break-glass activation",
        )
    service = BreakGlassService(db)
    req = await service.activate_request(
        actor=current_user,
        request_id=request_id,
        current_jwt_jti=session_id,
    )

    # Re-query with approvals loaded
    query = (
        select(BreakGlassRequest)
        .options(selectinload(BreakGlassRequest.approvals))
        .where(BreakGlassRequest.id == req.id)
    )
    res = await db.execute(query)
    full_req = res.scalar_one()
    return _serialize_request(full_req)


@router.get(
    "/requests/{request_id}/assembled-paper",
    response_model=AssembledPaperResponse,
)
async def get_assembled_paper(
    request_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    session_id: Optional[str] = Depends(get_current_session_id),
    db: AsyncSession = Depends(get_db),
):
    """
    Assemble and deliver ephemeral paper content strictly in memory.
    Every read independently revalidates full security context, enforces
    Server-Side No-Persistent-Plaintext Invariant, excludes answer keys,
    applies attribution-oriented dynamic watermarking, and logs audit event.
    """
    if not session_id:
        raise HTTPException(
            status_code=401,
            detail="Valid authenticated session JTI required",
        )

    client_ip = request.client.host if request.client else None
    service = BreakGlassService(db)
    result = await service.get_assembled_paper(
        actor=current_user,
        request_id=request_id,
        current_jwt_jti=session_id,
        client_ip=client_ip,
    )
    return result


@router.post(
    "/requests/{request_id}/revoke",
    response_model=BreakGlassRequestResponse,
)
async def revoke_break_glass_request(
    request_id: str,
    body: RevokeBreakGlassRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Explicitly revoke an active or approved break-glass request.
    Immediately prevents all subsequent server-authorized access.
    """
    service = BreakGlassService(db)
    req = await service.revoke_request(
        actor=current_user,
        request_id=request_id,
        reason=body.reason,
    )

    query = (
        select(BreakGlassRequest)
        .options(selectinload(BreakGlassRequest.approvals))
        .where(BreakGlassRequest.id == req.id)
    )
    res = await db.execute(query)
    full_req = res.scalar_one()
    return _serialize_request(full_req)
