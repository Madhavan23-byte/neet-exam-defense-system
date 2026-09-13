"""
B-SEA — Deterministic Risk Evaluation Hook
Phase 3A: Dynamic & Ephemeral Question Access Control

Provides a conservative, explainable risk evaluation interface.
IMPORTANT INVARIANT:
Risk evaluation is an additional deterministic security signal.
It NEVER overrides, softens, or bypasses hard authorization failures.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from app.core.models import (
    User,
    Question,
    QuestionAssignment,
    QuestionAssignmentStatus,
    QuestionAccessGrant,
    QuestionOperation,
    ReviewPurpose,
    ExamStatus,
)


@dataclass
class RiskContext:
    actor: User
    question: Question
    operation: QuestionOperation
    purpose: Optional[ReviewPurpose] = None
    assignment: Optional[QuestionAssignment] = None
    grant: Optional[QuestionAccessGrant] = None
    session_id: Optional[str] = None
    exam_status: Optional[ExamStatus] = None


@dataclass
class RiskDecision:
    risk_score: float
    flags: List[str] = field(default_factory=list)
    should_block: bool = False
    reason: str = ""


def evaluate_access_risk(context: RiskContext) -> RiskDecision:
    """
    Deterministic rule-based risk evaluation.
    Flags high-risk anomalies for forensics and enforces secondary blocks.
    """
    flags: List[str] = []
    score = 0.0

    # 1. Assignment Revocation Anomaly
    if context.assignment and context.assignment.status == QuestionAssignmentStatus.REVOKED:
        flags.append("REVOKED_ASSIGNMENT_ACCESS_ATTEMPT")
        score += 1.0

    # 2. Completed Assignment Anomaly
    if context.assignment and context.assignment.status == QuestionAssignmentStatus.COMPLETED:
        flags.append("COMPLETED_ASSIGNMENT_OPERATION_ATTEMPT")
        score += 0.8

    # 3. Exam State Incompatibility
    if context.exam_status in [ExamStatus.CANCELLED, ExamStatus.FROZEN, ExamStatus.COMPLETED]:
        flags.append(f"INCOMPATIBLE_EXAM_STATE_{context.exam_status.value}")
        score += 0.9

    # 4. Identity / Session Context Mismatch
    if context.grant and context.session_id and context.grant.session_id != context.session_id:
        flags.append("SESSION_CONTEXT_MISMATCH")
        score += 0.9

    # 5. Operation Escalation Anomaly
    if context.grant and context.grant.operation != context.operation:
        flags.append(f"GRANT_OPERATION_ESCALATION_{context.grant.operation.value}_TO_{context.operation.value}")
        score += 1.0

    # 6. Author Review Conflict
    if context.question and context.actor and context.question.author_id == context.actor.id:
        flags.append("AUTHOR_SELF_REVIEW_ATTEMPT")
        score += 1.0

    # Determine decision
    risk_score = min(score, 1.0)
    should_block = risk_score >= 0.8

    reason = "; ".join(flags) if flags else "Normal risk profile"
    return RiskDecision(
        risk_score=risk_score,
        flags=flags,
        should_block=should_block,
        reason=reason,
    )
