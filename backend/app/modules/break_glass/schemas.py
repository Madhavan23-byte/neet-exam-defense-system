"""
B-SEA — Phase 3B Break-Glass Schemas
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field

from app.core.models import (
    BreakGlassScope,
    BreakGlassRequestStatus,
    BreakGlassApprovalDecision,
    UserRoleEnum,
)


class CreateBreakGlassRequest(BaseModel):
    exam_id: str
    scope: BreakGlassScope = BreakGlassScope.COMPLETE_EXAM_PAPER
    form_label: Optional[str] = None
    justification: str = Field(..., min_length=20, description="Minimum 20 characters required justifying emergency access")
    incident_id: Optional[str] = None
    requested_duration_minutes: Optional[int] = None


class SubmitApprovalRequest(BaseModel):
    decision: BreakGlassApprovalDecision
    comments: Optional[str] = None


class RevokeBreakGlassRequest(BaseModel):
    reason: str = Field(..., min_length=5, description="Revocation justification")


class BreakGlassApprovalResponse(BaseModel):
    id: str
    request_id: str
    approver_id: str
    approver_role: UserRoleEnum
    decision: BreakGlassApprovalDecision
    comments: Optional[str]
    nonce: str
    request_fingerprint: str
    digital_signature: str
    is_valid: bool
    created_at: datetime


class BreakGlassRequestResponse(BaseModel):
    id: str
    exam_id: str
    blueprint_id: Optional[str]
    exam_version: int
    blueprint_hash: str
    requester_id: str
    scope: BreakGlassScope
    form_label: Optional[str]
    justification: str
    incident_id: Optional[str]
    required_quorum: int
    min_distinct_roles: int
    status: BreakGlassRequestStatus
    requested_duration_minutes: int
    activation_session_id: Optional[str]
    content_fingerprint: str
    policy_version: str
    created_at: datetime
    approved_at: Optional[datetime]
    activated_at: Optional[datetime]
    expires_at: Optional[datetime]
    revoked_at: Optional[datetime]
    revoked_by: Optional[str]
    revocation_reason: Optional[str]
    correlation_id: Optional[str]
    approvals_count: int = 0
    distinct_roles_count: int = 0
    approvals: List[BreakGlassApprovalResponse] = []


class QuestionContent(BaseModel):
    id: str
    subject: str
    section: Optional[str] = None
    difficulty: str
    content: str
    options: List[str]
    marks: float = 4.0


class AttributionWatermark(BaseModel):
    requester_username: str
    requester_user_id: str
    request_id: str
    activation_session_id: str
    assembled_at_utc: str
    expires_at_utc: str
    audit_ip_hash: Optional[str] = None
    security_notice: str = (
        "RESTRICTED MATERIAL: Attribution-oriented dynamic watermark. "
        "All access logged and forensically attributed."
    )


class AssembledPaperResponse(BaseModel):
    exam_id: str
    exam_title: str
    scope: BreakGlassScope
    form_label: Optional[str] = None
    question_count: int
    questions: List[QuestionContent]
    attribution_watermark: AttributionWatermark
    security_invariant: str = (
        "Server-Side No-Persistent-Plaintext Invariant: Assembled strictly in memory. "
        "Answer keys isolated."
    )
