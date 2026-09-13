"""
B-SEA — Question Service
Secure question authoring, encryption, sharding, review, and lifecycle management.

Security principles:
- Questions are encrypted immediately upon approval
- Plaintext content is cleared from DB after encryption
- Each question has Ed25519 signature + SHA-3 integrity hash
- Question setters can only access their own questions
- Reviewers and moderators can only access their actively assigned question shards
- 4-Factor authorization on review actions (Role + Permission + Active Assignment + Purpose)
- Assignment scoping on direct object retrieval, listings, and review actions (preventing IDOR)
- Reassignment is fully transactional with audit trail
- No bulk export endpoint exists
"""
from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import and_, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.models import (
    AccessGrantStatus,
    AnswerKey,
    AuditResult,
    Exam,
    ExamStatus,
    Question,
    QuestionAccessGrant,
    QuestionAssignment,
    QuestionAssignmentStatus,
    QuestionOperation,
    QuestionReview,
    QuestionStatus,
    ReviewPurpose,
    User,
    UserRoleEnum,
)
from app.core.security import hash_ip
from app.crypto.kms_interface import (
    EncryptedBlob,
    compute_integrity_hash,
    get_kms,
)
from app.modules.audit.service import AuditService
from app.modules.auth.service import has_permission
from app.modules.questions.policy import validate_operation_entitlement
from app.modules.questions.risk import evaluate_access_risk, RiskContext


class QuestionService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.audit = AuditService(db)
        self.kms = get_kms()

    def _question_context(self, question_id: str, exam_id: str) -> str:
        """Build KMS context string for question encryption."""
        return f"question:{question_id}:exam:{exam_id}"

    # ── AUTHORIZATION PREDICATE ───────────────────────────────────────────────

    async def check_question_access(
        self,
        actor: User,
        question_id: str,
        required_purpose: Optional[ReviewPurpose] = None,
        required_permission: Optional[str] = None,
    ) -> Tuple[bool, Optional[Question], Optional[QuestionAssignment], str]:
        """
        Reusable server-side authorization check enforcing:
        Role + Permission + Active Assignment + Purpose.

        Returns: (is_authorized, question, active_assignment, failure_reason)
        """
        result = await self.db.execute(select(Question).where(Question.id == question_id))
        question = result.scalar_one_or_none()
        if not question:
            return False, None, None, "Question not found"

        # Permission check if specified
        if required_permission and not has_permission(actor.role.value, required_permission):
            return False, question, None, f"Insufficient permissions: {required_permission} required"

        # Role-based evaluation
        if actor.role == UserRoleEnum.QUESTION_SETTER:
            if question.author_id != actor.id:
                return False, question, None, "Access denied: not question author"
            return True, question, None, ""

        if actor.role in [UserRoleEnum.REVIEWER, UserRoleEnum.MODERATOR]:
            # Normal review access MUST have an active or in-review assignment
            assign_query = select(QuestionAssignment).where(
                QuestionAssignment.question_id == question_id,
                QuestionAssignment.reviewer_id == actor.id,
                QuestionAssignment.status.in_([
                    QuestionAssignmentStatus.ACTIVE,
                    QuestionAssignmentStatus.IN_REVIEW,
                ]),
            )
            assign_res = await self.db.execute(assign_query)
            assignment = assign_res.scalar_one_or_none()

            if not assignment:
                return False, question, None, "Access denied: no active assignment for this question"

            if required_purpose and assignment.purpose != required_purpose:
                return (
                    False,
                    question,
                    assignment,
                    f"Assignment purpose mismatch: {assignment.purpose.value} does not permit {required_purpose.value}",
                )

            return True, question, assignment, ""

        if actor.role in [UserRoleEnum.SUPER_ADMIN, UserRoleEnum.EXAM_AUTHORITY]:
            # Metadata privileges only by default. Full-paper access belongs to later Complete-Paper Exception.
            # However, administrative actions with explicit permissions (e.g. assigning) are permitted.
            return True, question, None, ""

        return False, question, None, f"Role {actor.role.value} not authorized to access questions"

    # ── EPHEMERAL AUTHORIZATION ENGINE (PHASE 3A) ─────────────────────────────

    async def request_question_access(
        self,
        actor: User,
        question_id: str,
        operation: QuestionOperation,
        purpose: Optional[ReviewPurpose] = None,
        session_id: Optional[str] = None,
        expires_in_minutes: Optional[int] = 30,
    ) -> QuestionAccessGrant:
        """
        Phase A: Request an ephemeral access grant for a specific operation.
        Validates the multi-factor security context and issues/activates a QuestionAccessGrant.
        """
        # 1. Fetch Question and Exam
        q_res = await self.db.execute(select(Question).where(Question.id == question_id))
        question = q_res.scalar_one_or_none()
        if not question:
            raise ValueError("Question not found")

        exam_res = await self.db.execute(select(Exam).where(Exam.id == question.exam_id))
        exam = exam_res.scalar_one_or_none()
        if not exam:
            raise ValueError("Exam not found")

        if exam.status in [ExamStatus.CANCELLED, ExamStatus.FROZEN, ExamStatus.COMPLETED]:
            raise PermissionError(f"Exam status is {exam.status.value}; question access is blocked")

        # 2. Conflict of interest: author cannot review own question
        if question.author_id == actor.id:
            await self.audit.log(
                event_type="ACCESS_DENIED",
                result=AuditResult.FAILURE,
                actor_id=actor.id,
                actor_role=actor.role.value,
                resource_type="question",
                resource_id=question.id,
                metadata={"reason": "Author self-review conflict of interest"},
            )
            raise PermissionError("Conflict of interest: Question setter cannot review or approve own question")

        # 3. Role check
        if actor.role not in [UserRoleEnum.REVIEWER, UserRoleEnum.MODERATOR]:
            await self.audit.log(
                event_type="ACCESS_DENIED",
                result=AuditResult.FAILURE,
                actor_id=actor.id,
                actor_role=actor.role.value,
                resource_type="question",
                resource_id=question.id,
                metadata={"reason": f"Role {actor.role.value} cannot obtain reviewer access grants"},
            )
            raise PermissionError(f"Role {actor.role.value} not authorized for reviewer access grants")

        # 4. Fetch Assignment
        assign_res = await self.db.execute(
            select(QuestionAssignment).where(
                QuestionAssignment.question_id == question_id,
                QuestionAssignment.reviewer_id == actor.id,
                QuestionAssignment.exam_id == question.exam_id,
            )
        )
        assignment = assign_res.scalar_one_or_none()
        if not assignment:
            await self.audit.log(
                event_type="ACCESS_DENIED",
                result=AuditResult.FAILURE,
                actor_id=actor.id,
                actor_role=actor.role.value,
                resource_type="question",
                resource_id=question.id,
                metadata={"reason": "No assignment found for this question"},
            )
            raise PermissionError("Access denied: no assignment found for this question")

        # 5. Check Assignment Status
        if assignment.status == QuestionAssignmentStatus.REVOKED:
            await self.audit.log(
                event_type="ACCESS_DENIED",
                result=AuditResult.FAILURE,
                actor_id=actor.id,
                actor_role=actor.role.value,
                resource_type="question",
                resource_id=question.id,
                metadata={"reason": "Assignment is revoked"},
                risk_score=1.0,
            )
            raise PermissionError("Access denied: assignment has been revoked")

        if assignment.status == QuestionAssignmentStatus.COMPLETED:
            await self.audit.log(
                event_type="ACCESS_DENIED",
                result=AuditResult.FAILURE,
                actor_id=actor.id,
                actor_role=actor.role.value,
                resource_type="question",
                resource_id=question.id,
                metadata={"reason": "Assignment is completed"},
            )
            raise PermissionError("Access denied: assignment has already been completed")

        if assignment.status not in [QuestionAssignmentStatus.ACTIVE, QuestionAssignmentStatus.IN_REVIEW]:
            raise PermissionError(f"Access denied: assignment status is {assignment.status.value}")

        # 6. Purpose check
        target_purpose = purpose or assignment.purpose
        if target_purpose != assignment.purpose:
            await self.audit.log(
                event_type="ACCESS_DENIED",
                result=AuditResult.FAILURE,
                actor_id=actor.id,
                actor_role=actor.role.value,
                resource_type="question",
                resource_id=question.id,
                metadata={
                    "reason": f"Purpose mismatch: assigned {assignment.purpose.value}, requested {target_purpose.value}"
                },
            )
            raise PermissionError(f"Access denied: purpose mismatch - assigned purpose is {assignment.purpose.value}, requested {target_purpose.value}")

        # 7. Intersectional entitlement policy check
        is_entitled, err_msg = validate_operation_entitlement(target_purpose, operation, actor)
        if not is_entitled:
            await self.audit.log(
                event_type="ACCESS_DENIED",
                result=AuditResult.FAILURE,
                actor_id=actor.id,
                actor_role=actor.role.value,
                resource_type="question",
                resource_id=question.id,
                metadata={"reason": err_msg},
            )
            raise PermissionError(err_msg)

        # 8. Deterministic Risk Evaluation Hook
        risk_ctx = RiskContext(
            actor=actor,
            question=question,
            operation=operation,
            purpose=target_purpose,
            assignment=assignment,
            session_id=session_id,
            exam_status=exam.status,
        )
        risk_dec = evaluate_access_risk(risk_ctx)
        if risk_dec.should_block:
            await self.audit.log(
                event_type="ACCESS_DENIED",
                result=AuditResult.FAILURE,
                actor_id=actor.id,
                actor_role=actor.role.value,
                resource_type="question",
                resource_id=question.id,
                metadata={"risk_flags": risk_dec.flags, "reason": risk_dec.reason},
                risk_score=risk_dec.risk_score,
            )
            raise PermissionError(f"Access blocked by security policy: {risk_dec.reason}")

        # 9. Existing Active Grant Check
        now = datetime.now(timezone.utc)
        existing_res = await self.db.execute(
            select(QuestionAccessGrant).where(
                QuestionAccessGrant.assignment_id == assignment.id,
                QuestionAccessGrant.operation == operation,
                QuestionAccessGrant.status.in_([
                    AccessGrantStatus.GRANTED,
                    AccessGrantStatus.ACTIVE,
                ]),
            )
        )
        existing_grant = existing_res.scalar_one_or_none()

        if existing_grant:
            if existing_grant.expires_at and now >= existing_grant.expires_at:
                existing_grant.status = AccessGrantStatus.EXPIRED
                await self.audit.log(
                    event_type="ACCESS_EXPIRED",
                    result=AuditResult.SUCCESS,
                    actor_id=actor.id,
                    actor_role=actor.role.value,
                    resource_type="question_access_grant",
                    resource_id=existing_grant.id,
                    metadata={"assignment_id": assignment.id, "operation": operation.value},
                )
                await self.db.flush()
            else:
                if session_id and existing_grant.session_id != session_id:
                    existing_grant.session_id = session_id
                    await self.db.flush()
                return existing_grant

        # 10. Issue new QuestionAccessGrant
        expires_at = None
        if expires_in_minutes is not None:
            expires_at = now + timedelta(minutes=expires_in_minutes)

        correlation_id = secrets.token_hex(16)
        grant = QuestionAccessGrant(
            question_id=question.id,
            exam_id=question.exam_id,
            reviewer_id=actor.id,
            assignment_id=assignment.id,
            purpose=target_purpose,
            operation=operation,
            status=AccessGrantStatus.GRANTED,
            issued_at=now,
            expires_at=expires_at,
            session_id=session_id,
            created_by=actor.id,
            correlation_id=correlation_id,
        )
        self.db.add(grant)

        await self.audit.log(
            event_type="ACCESS_REQUESTED",
            result=AuditResult.SUCCESS,
            actor_id=actor.id,
            actor_role=actor.role.value,
            resource_type="question_access_grant",
            resource_id=grant.id,
            metadata={
                "question_id": question.id,
                "exam_id": question.exam_id,
                "assignment_id": assignment.id,
                "purpose": target_purpose.value,
                "operation": operation.value,
                "correlation_id": correlation_id,
                "session_id": session_id,
            },
            risk_score=risk_dec.risk_score,
        )

        await self.audit.log(
            event_type="ACCESS_GRANTED",
            result=AuditResult.SUCCESS,
            actor_id=actor.id,
            actor_role=actor.role.value,
            resource_type="question_access_grant",
            resource_id=grant.id,
            metadata={
                "question_id": question.id,
                "assignment_id": assignment.id,
                "operation": operation.value,
                "correlation_id": correlation_id,
            },
        )

        target_assignment_id = assignment.id
        try:
            await self.db.commit()
            await self.db.refresh(grant)
            return grant
        except IntegrityError:
            await self.db.rollback()
            existing_res = await self.db.execute(
                select(QuestionAccessGrant).where(
                    QuestionAccessGrant.assignment_id == target_assignment_id,
                    QuestionAccessGrant.operation == operation,
                    QuestionAccessGrant.status.in_([
                        AccessGrantStatus.GRANTED,
                        AccessGrantStatus.ACTIVE,
                    ]),
                )
            )
            existing_grant = existing_res.scalar_one_or_none()
            if existing_grant:
                return existing_grant
            raise

    async def authorize_question_operation(
        self,
        actor: User,
        question_id: str,
        operation: QuestionOperation,
        grant_id: Optional[str],
        session_id: Optional[str] = None,
    ) -> Tuple[Question, QuestionAssignment, QuestionAccessGrant]:
        """
        Phase B: Revalidates the complete security context before allowing a protected operation:
        - grant_id must be provided (grant_id alone is NOT sufficient)
        - Grant status must be GRANTED or ACTIVE (not EXPIRED, not REVOKED)
        - Deterministic lazy expiration check
        - Grant must belong to requesting actor
        - Session context must match (jti)
        - Question ID and Exam ID must match
        - Operation must match
        - Underlying QuestionAssignment must still be valid (ACTIVE or IN_REVIEW)
        - Exam must not be FROZEN, CANCELLED, or COMPLETED
        - Intersectional policy must still permit the operation
        - Activates grant on first use (GRANTED -> ACTIVE)
        """
        if not grant_id:
            await self.audit.log(
                event_type="ACCESS_DENIED",
                result=AuditResult.FAILURE,
                actor_id=actor.id,
                actor_role=actor.role.value,
                resource_type="question",
                resource_id=question_id,
                metadata={"reason": "Missing required grant_id for protected operation", "operation": operation.value},
            )
            raise PermissionError("Access denied: grant_id is required for protected operations")

        # 1. Fetch Grant
        g_res = await self.db.execute(
            select(QuestionAccessGrant).where(QuestionAccessGrant.id == grant_id)
        )
        grant = g_res.scalar_one_or_none()
        if not grant:
            await self.audit.log(
                event_type="ACCESS_DENIED",
                result=AuditResult.FAILURE,
                actor_id=actor.id,
                actor_role=actor.role.value,
                resource_type="question_access_grant",
                resource_id=grant_id,
                metadata={"reason": "Invalid or non-existent grant_id"},
            )
            raise PermissionError("Access denied: invalid access grant")

        now = datetime.now(timezone.utc)

        # 2. Status and Expiration
        if grant.status == AccessGrantStatus.REVOKED:
            raise PermissionError("Access denied: grant has been revoked")

        if grant.status == AccessGrantStatus.EXPIRED:
            raise PermissionError("Access denied: grant has expired")

        if grant.expires_at and now >= grant.expires_at:
            grant.status = AccessGrantStatus.EXPIRED
            await self.audit.log(
                event_type="ACCESS_EXPIRED",
                result=AuditResult.SUCCESS,
                actor_id=actor.id,
                actor_role=actor.role.value,
                resource_type="question_access_grant",
                resource_id=grant.id,
                metadata={"reason": "Grant expired based on expires_at"},
            )
            await self.db.commit()
            raise PermissionError("Access denied: access grant has expired")

        if grant.status not in [AccessGrantStatus.GRANTED, AccessGrantStatus.ACTIVE]:
            raise PermissionError(f"Access denied: grant status is {grant.status.value}")

        # 3. Actor Identity Binding
        if grant.reviewer_id != actor.id:
            await self.audit.log(
                event_type="ACCESS_DENIED",
                result=AuditResult.FAILURE,
                actor_id=actor.id,
                actor_role=actor.role.value,
                resource_type="question_access_grant",
                resource_id=grant.id,
                metadata={"reason": "Grant belongs to another user", "target_user": grant.reviewer_id},
                risk_score=1.0,
            )
            raise PermissionError("Access denied: grant was issued to a different user")

        # 4. Session Context Binding
        if grant.session_id and session_id and grant.session_id != session_id:
            await self.audit.log(
                event_type="ACCESS_DENIED",
                result=AuditResult.FAILURE,
                actor_id=actor.id,
                actor_role=actor.role.value,
                resource_type="question_access_grant",
                resource_id=grant.id,
                metadata={"reason": "Session context mismatch", "expected": grant.session_id, "actual": session_id},
                risk_score=0.9,
            )
            raise PermissionError("Access denied: session context mismatch")

        # 5. Question & Operation Match
        if grant.question_id != question_id:
            await self.audit.log(
                event_type="ACCESS_DENIED",
                result=AuditResult.FAILURE,
                actor_id=actor.id,
                actor_role=actor.role.value,
                resource_type="question_access_grant",
                resource_id=grant.id,
                metadata={"reason": "Grant question_id mismatch", "grant_q": grant.question_id, "target_q": question_id},
            )
            raise PermissionError("Access denied: grant does not apply to this question")

        if grant.operation != operation:
            await self.audit.log(
                event_type="ACCESS_DENIED",
                result=AuditResult.FAILURE,
                actor_id=actor.id,
                actor_role=actor.role.value,
                resource_type="question_access_grant",
                resource_id=grant.id,
                metadata={"reason": "Grant operation mismatch", "grant_op": grant.operation.value, "target_op": operation.value},
            )
            raise PermissionError(f"Access denied: grant operation is {grant.operation.value}, requested {operation.value}")

        # 6. Revalidate Underlying Assignment
        assign_res = await self.db.execute(
            select(QuestionAssignment).where(QuestionAssignment.id == grant.assignment_id)
        )
        assignment = assign_res.scalar_one_or_none()
        if not assignment:
            raise PermissionError("Access denied: underlying assignment no longer exists")

        if assignment.reviewer_id != actor.id or assignment.question_id != question_id:
            raise PermissionError("Access denied: assignment relationship mismatch")

        if assignment.status == QuestionAssignmentStatus.REVOKED:
            grant.status = AccessGrantStatus.REVOKED
            grant.revoked_at = now
            grant.revocation_reason = "Underlying assignment is revoked"
            await self.audit.log(
                event_type="ACCESS_REVOKED",
                result=AuditResult.SUCCESS,
                actor_id=actor.id,
                actor_role=actor.role.value,
                resource_type="question_access_grant",
                resource_id=grant.id,
                metadata={"reason": "Underlying assignment is revoked"},
            )
            await self.db.commit()
            raise PermissionError("Access denied: underlying assignment has been revoked")

        if assignment.status == QuestionAssignmentStatus.COMPLETED:
            raise PermissionError("Access denied: underlying assignment has been completed")

        if assignment.status not in [QuestionAssignmentStatus.ACTIVE, QuestionAssignmentStatus.IN_REVIEW]:
            raise PermissionError(f"Access denied: assignment status is {assignment.status.value}")

        # 7. Revalidate Question & Exam
        q_res = await self.db.execute(select(Question).where(Question.id == question_id))
        question = q_res.scalar_one_or_none()
        if not question:
            raise ValueError("Question not found")

        exam_res = await self.db.execute(select(Exam).where(Exam.id == question.exam_id))
        exam = exam_res.scalar_one_or_none()
        if not exam:
            raise ValueError("Exam not found")

        if exam.status in [ExamStatus.CANCELLED, ExamStatus.FROZEN, ExamStatus.COMPLETED]:
            raise PermissionError(f"Exam status is {exam.status.value}; question operations are blocked")

        if grant.exam_id != question.exam_id:
            raise PermissionError("Access denied: grant exam_id mismatch")

        # 8. Intersectional Policy
        is_entitled, err_msg = validate_operation_entitlement(grant.purpose, operation, actor)
        if not is_entitled:
            raise PermissionError(err_msg)

        # 9. Transition GRANTED -> ACTIVE
        if grant.status == AccessGrantStatus.GRANTED:
            grant.status = AccessGrantStatus.ACTIVE
            grant.activated_at = now
            await self.db.commit()

        return question, assignment, grant

    async def revoke_access_grant(
        self,
        grant_id: str,
        actor: User,
        reason: str = "Manually revoked",
    ) -> QuestionAccessGrant:
        """Explicitly revoke an active access grant."""
        res = await self.db.execute(
            select(QuestionAccessGrant).where(QuestionAccessGrant.id == grant_id)
        )
        grant = res.scalar_one_or_none()
        if not grant:
            raise ValueError("Grant not found")

        if grant.reviewer_id != actor.id and actor.role not in [
            UserRoleEnum.SUPER_ADMIN,
            UserRoleEnum.EXAM_AUTHORITY,
            UserRoleEnum.MODERATOR,
        ]:
            raise PermissionError("Not authorized to revoke this grant")

        grant.status = AccessGrantStatus.REVOKED
        grant.revoked_at = datetime.now(timezone.utc)
        grant.revocation_reason = reason

        await self.audit.log(
            event_type="ACCESS_REVOKED",
            result=AuditResult.SUCCESS,
            actor_id=actor.id,
            actor_role=actor.role.value,
            resource_type="question_access_grant",
            resource_id=grant.id,
            metadata={"reason": reason, "assignment_id": grant.assignment_id},
        )
        await self.db.commit()
        await self.db.refresh(grant)
        return grant

    # ── QUESTION CREATION & AUTHORING ─────────────────────────────────────────

    async def create_question(
        self,
        exam_id: str,
        author: User,
        subject: str,
        topic: Optional[str],
        difficulty: str,
        bloom_level: Optional[str],
        content: str,
        correct_option: int,
        marks_positive: float = 4.0,
        marks_negative: float = 1.0,
        ip: str = "",
    ) -> Question:
        """Create a new question in DRAFT status."""
        question = Question(
            exam_id=exam_id,
            author_id=author.id,
            subject=subject,
            topic=topic,
            difficulty=difficulty,
            bloom_level=bloom_level,
            question_format="MCQ",
            marks_positive=marks_positive,
            marks_negative=marks_negative,
            status=QuestionStatus.DRAFT,
            version=1,
            plaintext_content=content,
        )
        self.db.add(question)
        await self.db.flush()

        # Store answer key separately (isolated from candidate/reviewer APIs)
        key_data = f"{question.id}:{correct_option}:{marks_positive}:{marks_negative}"
        answer_key = AnswerKey(
            question_id=question.id,
            correct_option=correct_option,
            marks_positive=marks_positive,
            marks_negative=marks_negative,
            key_hash=hashlib.sha3_256(key_data.encode()).hexdigest(),
            created_by=author.id,
        )
        self.db.add(answer_key)

        await self.audit.log(
            event_type="QUESTION_CREATED",
            result=AuditResult.SUCCESS,
            actor_id=author.id,
            actor_role=author.role.value,
            resource_type="question",
            resource_id=question.id,
            ip_hash=hash_ip(ip) if ip else None,
        )

        return question

    async def submit_question(self, question_id: str, author: User) -> Question:
        """Submit a DRAFT question for review."""
        question = await self._get_question_owned(question_id, author)

        if question.status != QuestionStatus.DRAFT:
            raise ValueError(f"Cannot submit question in status {question.status}")

        question.status = QuestionStatus.SUBMITTED

        await self.audit.log(
            event_type="QUESTION_SUBMITTED",
            result=AuditResult.SUCCESS,
            actor_id=author.id,
            actor_role=author.role.value,
            resource_type="question",
            resource_id=question_id,
        )
        return question

    # ── QUESTION ASSIGNMENT & SHARDING ────────────────────────────────────────

    async def assign_question(
        self,
        question_id: str,
        reviewer_id: str,
        assigned_by: User,
        purpose: ReviewPurpose = ReviewPurpose.TECHNICAL_REVIEW,
    ) -> QuestionAssignment:
        """
        Manually assign a question to a reviewer with strict conflict-of-interest check.
        """
        # 1. Authority check
        if assigned_by.role not in [UserRoleEnum.SUPER_ADMIN, UserRoleEnum.EXAM_AUTHORITY]:
            raise PermissionError("Only SUPER_ADMIN or EXAM_AUTHORITY can assign questions")

        # 2. Fetch question
        q_res = await self.db.execute(select(Question).where(Question.id == question_id))
        question = q_res.scalar_one_or_none()
        if not question:
            raise ValueError("Question not found")

        # 3. Fetch reviewer
        rev_res = await self.db.execute(select(User).where(User.id == reviewer_id))
        reviewer = rev_res.scalar_one_or_none()
        # 3. Conflict of interest: Question setter cannot review their own question
        if question.author_id == reviewer.id:
            raise ValueError("Conflict of interest: author cannot be assigned to review own question")

        # 4. Check reviewer role
        if reviewer.role not in [UserRoleEnum.REVIEWER, UserRoleEnum.MODERATOR]:
            raise ValueError(f"User {reviewer.username} lacks REVIEWER or MODERATOR role")

        # 5. Check active duplicate assignment
        existing = await self.db.execute(
            select(QuestionAssignment).where(
                QuestionAssignment.question_id == question_id,
                QuestionAssignment.reviewer_id == reviewer_id,
                QuestionAssignment.status.in_([
                    QuestionAssignmentStatus.ACTIVE,
                    QuestionAssignmentStatus.IN_REVIEW,
                ]),
            )
        )
        if existing.scalar_one_or_none():
            raise ValueError("An active assignment already exists for this reviewer on this question")

        assignment = QuestionAssignment(
            question_id=question_id,
            reviewer_id=reviewer_id,
            exam_id=question.exam_id,
            assigned_by=assigned_by.id,
            purpose=purpose,
            status=QuestionAssignmentStatus.ACTIVE,
            assigned_at=datetime.now(timezone.utc),
        )
        self.db.add(assignment)

        if question.status == QuestionStatus.SUBMITTED:
            question.status = QuestionStatus.UNDER_REVIEW

        await self.audit.log(
            event_type="QUESTION_ASSIGNED",
            result=AuditResult.SUCCESS,
            actor_id=assigned_by.id,
            actor_role=assigned_by.role.value,
            resource_type="question_assignment",
            resource_id=assignment.id,
            metadata={
                "question_id": question_id,
                "reviewer_id": reviewer_id,
                "purpose": purpose.value,
            },
        )
        try:
            await self.db.commit()
            await self.db.refresh(assignment)
            return assignment
        except IntegrityError:
            await self.db.rollback()
            raise ValueError("An active assignment already exists for this reviewer on this question")


    async def shard_exam_questions(
        self,
        exam_id: str,
        reviewer_ids: List[str],
        assigned_by: User,
        shard_size: Optional[int] = None,
        redundancy: int = 1,
        purpose: ReviewPurpose = ReviewPurpose.TECHNICAL_REVIEW,
    ) -> Dict[str, Any]:
        """
        Batch-shard submitted exam questions across eligible reviewers using OS-backed CSPRNG.
        Supports configurable shard sizes, configurable redundancy, and strict conflict exclusion.
        """
        if assigned_by.role not in [UserRoleEnum.SUPER_ADMIN, UserRoleEnum.EXAM_AUTHORITY]:
            raise PermissionError("Only SUPER_ADMIN or EXAM_AUTHORITY can shard questions")

        if redundancy < 1:
            raise ValueError("Redundancy must be at least 1")

        if not reviewer_ids:
            raise ValueError("Reviewer pool cannot be empty")

        # 1. Fetch & validate reviewers
        rev_res = await self.db.execute(
            select(User).where(
                User.id.in_(reviewer_ids),
                User.is_active == True,
                User.is_locked == False,
                User.role.in_([UserRoleEnum.REVIEWER, UserRoleEnum.MODERATOR]),
            )
        )
        reviewers = rev_res.scalars().all()
        if len(reviewers) < len(reviewer_ids):
            raise ValueError("One or more specified reviewers are invalid, inactive, or lack reviewer role")

        if len(reviewers) < redundancy:
            raise ValueError(
                f"Mathematical infeasibility: pool has {len(reviewers)} reviewers, "
                f"but redundancy={redundancy} requires at least {redundancy} distinct reviewers."
            )

        # 2. Fetch SUBMITTED questions
        q_res = await self.db.execute(
            select(Question).where(
                Question.exam_id == exam_id,
                Question.status.in_([QuestionStatus.SUBMITTED, QuestionStatus.UNDER_REVIEW]),
            )
        )
        questions = q_res.scalars().all()
        if not questions:
            return {
                "success": True,
                "message": "No submitted or under-review questions available for sharding",
                "questions_sharded": 0,
                "assignments_created": 0,
            }

        # 3. Workload feasibility check if shard_size specified
        total_slots_needed = len(questions) * redundancy
        if shard_size is not None:
            max_capacity = len(reviewers) * shard_size
            if max_capacity < total_slots_needed:
                raise ValueError(
                    f"Mathematical infeasibility: {len(reviewers)} reviewers with shard_size={shard_size} "
                    f"can handle at most {max_capacity} assignments, but {total_slots_needed} are required."
                )

        rng = secrets.SystemRandom()
        assignments_created = []
        reviewer_workload = {r.id: 0 for r in reviewers}

        for q in questions:
            # Eligible reviewers must NOT be the question author
            eligible = [r for r in reviewers if r.id != q.author_id]

            if shard_size is not None:
                eligible = [r for r in eligible if reviewer_workload[r.id] < shard_size]

            if len(eligible) < redundancy:
                raise ValueError(
                    f"Constraint infeasibility: question {q.id} has only {len(eligible)} eligible reviewers "
                    f"under conflict-of-interest and workload limits, but redundancy={redundancy} is required."
                )

            # CSPRNG selection
            chosen_reviewers = rng.sample(eligible, redundancy)

            for reviewer in chosen_reviewers:
                # Check for existing active assignment to prevent duplicate
                existing = await self.db.execute(
                    select(QuestionAssignment).where(
                        QuestionAssignment.question_id == q.id,
                        QuestionAssignment.reviewer_id == reviewer.id,
                        QuestionAssignment.status.in_([
                            QuestionAssignmentStatus.ACTIVE,
                            QuestionAssignmentStatus.IN_REVIEW,
                        ]),
                    )
                )
                if not existing.scalar_one_or_none():
                    assignment = QuestionAssignment(
                        question_id=q.id,
                        reviewer_id=reviewer.id,
                        exam_id=exam_id,
                        assigned_by=assigned_by.id,
                        purpose=purpose,
                        status=QuestionAssignmentStatus.ACTIVE,
                        assigned_at=datetime.now(timezone.utc),
                    )
                    self.db.add(assignment)
                    assignments_created.append(assignment)
                    reviewer_workload[reviewer.id] += 1

            q.status = QuestionStatus.UNDER_REVIEW

        await self.audit.log(
            event_type="QUESTIONS_SHARDED",
            result=AuditResult.SUCCESS,
            actor_id=assigned_by.id,
            actor_role=assigned_by.role.value,
            resource_type="exam",
            resource_id=exam_id,
            metadata={
                "questions_count": len(questions),
                "reviewers_count": len(reviewers),
                "assignments_created": len(assignments_created),
                "redundancy": redundancy,
                "purpose": purpose.value,
            },
        )
        await self.db.commit()

        return {
            "success": True,
            "exam_id": exam_id,
            "questions_sharded": len(questions),
            "assignments_created": len(assignments_created),
            "redundancy": redundancy,
        }

    # ── TRANSACTIONAL REASSIGNMENT ────────────────────────────────────────────

    async def reassign_question(
        self,
        assignment_id: str,
        new_reviewer_id: str,
        reassigned_by: User,
        reason: str,
    ) -> QuestionAssignment:
        """
        Atomically revoke an active assignment and create a replacement assignment
        with full audit logging and conflict verification.
        """
        if reassigned_by.role not in [UserRoleEnum.SUPER_ADMIN, UserRoleEnum.EXAM_AUTHORITY]:
            raise PermissionError("Only SUPER_ADMIN or EXAM_AUTHORITY can reassign questions")

        # 1. Row-lock current assignment
        res = await self.db.execute(
            select(QuestionAssignment)
            .where(QuestionAssignment.id == assignment_id)
            .with_for_update()
        )
        current_assign = res.scalar_one_or_none()
        if not current_assign:
            raise ValueError("Assignment not found")

        if current_assign.status not in [QuestionAssignmentStatus.ACTIVE, QuestionAssignmentStatus.IN_REVIEW]:
            raise ValueError(f"Cannot reassign: assignment status is {current_assign.status.value}")

        # 2. Fetch & validate new reviewer
        rev_res = await self.db.execute(select(User).where(User.id == new_reviewer_id))
        new_reviewer = rev_res.scalar_one_or_none()
        if not new_reviewer or not new_reviewer.is_active or new_reviewer.is_locked:
            raise ValueError("New reviewer not found or inactive")
        if new_reviewer.role not in [UserRoleEnum.REVIEWER, UserRoleEnum.MODERATOR]:
            raise ValueError("New reviewer lacks REVIEWER or MODERATOR role")

        # 3. Conflict of interest check
        q_res = await self.db.execute(select(Question).where(Question.id == current_assign.question_id))
        question = q_res.scalar_one_or_none()
        if not question:
            raise ValueError("Associated question not found")
        if question.author_id == new_reviewer_id:
            raise ValueError("Conflict of interest: author cannot review their own question")

        # 4. Duplicate active assignment check on new reviewer
        existing = await self.db.execute(
            select(QuestionAssignment).where(
                QuestionAssignment.question_id == question.id,
                QuestionAssignment.reviewer_id == new_reviewer_id,
                QuestionAssignment.status.in_([
                    QuestionAssignmentStatus.ACTIVE,
                    QuestionAssignmentStatus.IN_REVIEW,
                ]),
            )
        )
        if existing.scalar_one_or_none():
            raise ValueError("New reviewer already has an active assignment for this question")

        # 5. Revoke old assignment
        old_reviewer_id = current_assign.reviewer_id
        current_assign.status = QuestionAssignmentStatus.REVOKED
        current_assign.revoked_at = datetime.now(timezone.utc)
        current_assign.revocation_reason = reason

        await self.audit.log(
            event_type="QUESTION_ASSIGNMENT_REVOKED",
            result=AuditResult.SUCCESS,
            actor_id=reassigned_by.id,
            actor_role=reassigned_by.role.value,
            resource_type="question_assignment",
            resource_id=current_assign.id,
            metadata={
                "question_id": question.id,
                "previous_reviewer_id": old_reviewer_id,
                "reason": reason,
            },
        )

        # 5b. Cascade atomic revocation to all active/granted access grants
        active_grants_res = await self.db.execute(
            select(QuestionAccessGrant).where(
                QuestionAccessGrant.assignment_id == current_assign.id,
                QuestionAccessGrant.status.in_([
                    AccessGrantStatus.GRANTED,
                    AccessGrantStatus.ACTIVE,
                ]),
            )
        )
        for grant in active_grants_res.scalars():
            grant.status = AccessGrantStatus.REVOKED
            grant.revoked_at = datetime.now(timezone.utc)
            grant.revocation_reason = f"Assignment reassigned: {reason}"
            await self.audit.log(
                event_type="ACCESS_REVOKED",
                result=AuditResult.SUCCESS,
                actor_id=reassigned_by.id,
                actor_role=reassigned_by.role.value,
                resource_type="question_access_grant",
                resource_id=grant.id,
                metadata={
                    "assignment_id": current_assign.id,
                    "question_id": question.id,
                    "reason": reason,
                },
            )

        # 6. Create replacement assignment
        new_assignment = QuestionAssignment(
            question_id=question.id,
            reviewer_id=new_reviewer_id,
            exam_id=current_assign.exam_id,
            assigned_by=reassigned_by.id,
            purpose=current_assign.purpose,
            status=QuestionAssignmentStatus.ACTIVE,
            assigned_at=datetime.now(timezone.utc),
        )
        self.db.add(new_assignment)

        await self.audit.log(
            event_type="QUESTION_ASSIGNED",
            result=AuditResult.SUCCESS,
            actor_id=reassigned_by.id,
            actor_role=reassigned_by.role.value,
            resource_type="question_assignment",
            resource_id=new_assignment.id,
            metadata={
                "question_id": question.id,
                "reviewer_id": new_reviewer_id,
                "reassigned_from": assignment_id,
                "purpose": new_assignment.purpose.value,
            },
        )

        await self.db.commit()
        await self.db.refresh(new_assignment)
        return new_assignment

    # ── REVIEW LIFECYCLE ──────────────────────────────────────────────────────

    async def start_review(
        self,
        assignment_id: str,
        actor: User,
        grant_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> QuestionAssignment:
        """Atomically transition assignment from ACTIVE to IN_REVIEW."""
        res = await self.db.execute(
            select(QuestionAssignment)
            .where(QuestionAssignment.id == assignment_id)
            .with_for_update()
        )
        assignment = res.scalar_one_or_none()
        if not assignment:
            raise ValueError("Assignment not found")

        if assignment.reviewer_id != actor.id:
            raise PermissionError("Assignment does not belong to requesting user")

        if grant_id:
            await self.authorize_question_operation(
                actor=actor,
                question_id=assignment.question_id,
                operation=QuestionOperation.REVIEW,
                grant_id=grant_id,
                session_id=session_id,
            )

        if assignment.status == QuestionAssignmentStatus.IN_REVIEW:
            return assignment

        if assignment.status != QuestionAssignmentStatus.ACTIVE:
            raise ValueError(f"Cannot start review: assignment status is {assignment.status.value}")

        assignment.status = QuestionAssignmentStatus.IN_REVIEW
        assignment.started_at = datetime.now(timezone.utc)

        await self.audit.log(
            event_type="QUESTION_REVIEW_STARTED",
            result=AuditResult.SUCCESS,
            actor_id=actor.id,
            actor_role=actor.role.value,
            resource_type="question_assignment",
            resource_id=assignment.id,
            metadata={"question_id": assignment.question_id, "grant_id": grant_id},
        )
        await self.db.commit()
        await self.db.refresh(assignment)
        return assignment

    async def submit_review(
        self,
        assignment_id: str,
        actor: User,
        verdict: str,
        comments: Optional[str] = None,
        grant_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> QuestionReview:
        """Submit review verdict and transition assignment to COMPLETED."""
        res = await self.db.execute(
            select(QuestionAssignment)
            .where(QuestionAssignment.id == assignment_id)
            .with_for_update()
        )
        assignment = res.scalar_one_or_none()
        if not assignment:
            raise ValueError("Assignment not found")

        if assignment.reviewer_id != actor.id:
            raise PermissionError("Assignment does not belong to requesting user")

        if grant_id:
            await self.authorize_question_operation(
                actor=actor,
                question_id=assignment.question_id,
                operation=QuestionOperation.REVIEW,
                grant_id=grant_id,
                session_id=session_id,
            )

        if assignment.status != QuestionAssignmentStatus.IN_REVIEW:
            raise ValueError(f"Cannot submit review: assignment must be IN_REVIEW (status: {assignment.status.value})")

        review = QuestionReview(
            question_id=assignment.question_id,
            reviewer_id=actor.id,
            verdict=verdict,
            comments=comments,
            reviewed_at=datetime.now(timezone.utc),
        )
        self.db.add(review)

        assignment.status = QuestionAssignmentStatus.COMPLETED
        assignment.completed_at = datetime.now(timezone.utc)

        # Invalidate/expire active grants for the completed assignment
        active_grants_res = await self.db.execute(
            select(QuestionAccessGrant).where(
                QuestionAccessGrant.assignment_id == assignment.id,
                QuestionAccessGrant.status.in_([AccessGrantStatus.GRANTED, AccessGrantStatus.ACTIVE]),
            )
        )
        for g in active_grants_res.scalars():
            g.status = AccessGrantStatus.EXPIRED
            g.revoked_at = datetime.now(timezone.utc)
            g.revocation_reason = "Assignment completed"

        await self.audit.log(
            event_type="QUESTION_REVIEW_COMPLETED",
            result=AuditResult.SUCCESS,
            actor_id=actor.id,
            actor_role=actor.role.value,
            resource_type="question",
            resource_id=assignment.question_id,
            metadata={"verdict": verdict, "assignment_id": assignment.id, "grant_id": grant_id},
        )
        await self.db.commit()
        await self.db.refresh(review)
        return review

    # ── APPROVAL & REJECTION ──────────────────────────────────────────────────

    async def approve_question(
        self,
        question_id: str,
        moderator: User,
        comments: str = "",
        grant_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Question:
        """
        Approve question and trigger immediate encryption.
        Requires active assignment for the moderator and valid grant if grant_id provided.
        """
        if grant_id:
            question, assignment, grant = await self.authorize_question_operation(
                actor=moderator,
                question_id=question_id,
                operation=QuestionOperation.APPROVE,
                grant_id=grant_id,
                session_id=session_id,
            )
        else:
            is_auth, question, assignment, err = await self.check_question_access(
                moderator,
                question_id,
                required_permission="questions:approve",
            )
            if not is_auth:
                raise PermissionError(err or "Access denied: moderator not assigned to question")

        if question.status not in [QuestionStatus.SUBMITTED, QuestionStatus.UNDER_REVIEW]:
            raise ValueError(f"Cannot approve question in status {question.status}")

        review = QuestionReview(
            question_id=question_id,
            reviewer_id=moderator.id,
            verdict="APPROVED",
            comments=comments,
            reviewed_at=datetime.now(timezone.utc),
        )
        self.db.add(review)

        if assignment:
            assignment.status = QuestionAssignmentStatus.COMPLETED
            assignment.completed_at = datetime.now(timezone.utc)

            # Invalidate active grants for completed assignment
            active_grants_res = await self.db.execute(
                select(QuestionAccessGrant).where(
                    QuestionAccessGrant.assignment_id == assignment.id,
                    QuestionAccessGrant.status.in_([AccessGrantStatus.GRANTED, AccessGrantStatus.ACTIVE]),
                )
            )
            for g in active_grants_res.scalars():
                g.status = AccessGrantStatus.EXPIRED
                g.revoked_at = datetime.now(timezone.utc)
                g.revocation_reason = "Assignment completed"

        question.status = QuestionStatus.APPROVED
        question.approved_by = moderator.id
        question.approved_at = datetime.now(timezone.utc)

        await self.audit.log(
            event_type="QUESTION_APPROVED",
            result=AuditResult.SUCCESS,
            actor_id=moderator.id,
            actor_role=moderator.role.value,
            resource_type="question",
            resource_id=question_id,
            metadata={"grant_id": grant_id} if grant_id else None,
        )

        # Immediately encrypt after approval
        await self._encrypt_question(question)
        await self.db.commit()
        return question

    async def reject_question(
        self,
        question_id: str,
        moderator: User,
        reason: str,
        grant_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Question:
        """Reject question and return to author. Requires active assignment and valid grant if grant_id provided."""
        if grant_id:
            question, assignment, grant = await self.authorize_question_operation(
                actor=moderator,
                question_id=question_id,
                operation=QuestionOperation.REJECT,
                grant_id=grant_id,
                session_id=session_id,
            )
        else:
            is_auth, question, assignment, err = await self.check_question_access(
                moderator,
                question_id,
                required_permission="questions:reject",
            )
            if not is_auth:
                raise PermissionError(err or "Access denied: moderator not assigned to question")

        review = QuestionReview(
            question_id=question_id,
            reviewer_id=moderator.id,
            verdict="REJECTED",
            comments=reason,
            reviewed_at=datetime.now(timezone.utc),
        )
        self.db.add(review)

        if assignment:
            assignment.status = QuestionAssignmentStatus.COMPLETED
            assignment.completed_at = datetime.now(timezone.utc)

            # Invalidate active grants for completed assignment
            active_grants_res = await self.db.execute(
                select(QuestionAccessGrant).where(
                    QuestionAccessGrant.assignment_id == assignment.id,
                    QuestionAccessGrant.status.in_([AccessGrantStatus.GRANTED, AccessGrantStatus.ACTIVE]),
                )
            )
            for g in active_grants_res.scalars():
                g.status = AccessGrantStatus.EXPIRED
                g.revoked_at = datetime.now(timezone.utc)
                g.revocation_reason = "Assignment completed"

        question.status = QuestionStatus.REJECTED
        question.rejection_reason = reason

        await self.audit.log(
            event_type="QUESTION_REJECTED",
            result=AuditResult.SUCCESS,
            actor_id=moderator.id,
            actor_role=moderator.role.value,
            resource_type="question",
            resource_id=question_id,
            metadata={"reason": reason, "grant_id": grant_id},
        )
        await self.db.commit()
        return question

    # ── ENCRYPTION / KMS ──────────────────────────────────────────────────────

    async def _encrypt_question(self, question: Question) -> None:
        """Encrypt question content using KMS and clear plaintext from DB."""
        if not question.plaintext_content:
            return

        context = self._question_context(question.id, question.exam_id)
        content_bytes = question.plaintext_content.encode("utf-8")
        encrypted_blob = self.kms.encrypt(content_bytes, context)

        integrity_data = f"{question.id}:{question.version}:{encrypted_blob.ciphertext_b64}"
        integrity_hash = compute_integrity_hash(integrity_data.encode("utf-8"))
        signed = self.kms.sign(integrity_hash.encode("utf-8"))

        question.encrypted_content = encrypted_blob.ciphertext_b64
        question.key_reference = encrypted_blob.key_reference
        question.content_hash = integrity_hash
        question.digital_signature = signed.signature_b64
        question.status = QuestionStatus.ENCRYPTED
        question.plaintext_content = None

        await self.audit.log(
            event_type="QUESTION_ENCRYPTED",
            result=AuditResult.SUCCESS,
            resource_type="question",
            resource_id=question.id,
            metadata={"key_reference": encrypted_blob.key_reference},
        )

    # ── RETRIEVAL & LISTING ───────────────────────────────────────────────────

    async def list_questions(self, actor: User, exam_id: str) -> List[Question]:
        """
        List questions strictly scoped by role and active assignment:
        - QUESTION_SETTER: only own questions
        - REVIEWER / MODERATOR: only actively assigned question shards
        - SUPER_ADMIN / EXAM_AUTHORITY: metadata overview
        """
        query = select(Question).where(Question.exam_id == exam_id)

        if actor.role == UserRoleEnum.QUESTION_SETTER:
            query = query.where(Question.author_id == actor.id)
        elif actor.role in [UserRoleEnum.REVIEWER, UserRoleEnum.MODERATOR]:
            query = query.join(
                QuestionAssignment,
                and_(
                    QuestionAssignment.question_id == Question.id,
                    QuestionAssignment.reviewer_id == actor.id,
                    QuestionAssignment.status.in_([
                        QuestionAssignmentStatus.ACTIVE,
                        QuestionAssignmentStatus.IN_REVIEW,
                    ]),
                ),
            )

        result = await self.db.execute(query)
        questions = result.scalars().all()

        await self.audit.log(
            event_type="QUESTION_LIST_ACCESSED",
            result=AuditResult.SUCCESS,
            actor_id=actor.id,
            actor_role=actor.role.value,
            resource_type="question_bank",
            resource_id=exam_id,
            metadata={"count": len(questions)},
        )
        return questions

    async def get_reviewer_assignments(
        self,
        reviewer: User,
        exam_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch all assigned items for the authenticated reviewer."""
        query = (
            select(QuestionAssignment, Question)
            .join(Question, QuestionAssignment.question_id == Question.id)
            .where(
                QuestionAssignment.reviewer_id == reviewer.id,
                QuestionAssignment.status.in_([
                    QuestionAssignmentStatus.ACTIVE,
                    QuestionAssignmentStatus.IN_REVIEW,
                    QuestionAssignmentStatus.COMPLETED,
                ]),
            )
        )
        if exam_id:
            query = query.where(QuestionAssignment.exam_id == exam_id)

        query = query.order_by(QuestionAssignment.assigned_at.desc())
        res = await self.db.execute(query)
        rows = res.all()

        results = []
        for assign, q in rows:
            results.append({
                "assignment_id": assign.id,
                "question_id": q.id,
                "exam_id": assign.exam_id,
                "purpose": assign.purpose.value,
                "assignment_status": assign.status.value,
                "assigned_at": assign.assigned_at.isoformat(),
                "started_at": assign.started_at.isoformat() if assign.started_at else None,
                "completed_at": assign.completed_at.isoformat() if assign.completed_at else None,
                "question": {
                    "id": q.id,
                    "subject": q.subject,
                    "topic": q.topic,
                    "difficulty": q.difficulty,
                    "status": q.status.value,
                    "marks_positive": q.marks_positive,
                    "marks_negative": q.marks_negative,
                },
            })
        return results

    async def get_question_detail(
        self,
        actor: User,
        question_id: str,
        grant_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Retrieve question content for review with strict IDOR defense.
        Answer keys are strictly isolated and never returned.
        If grant_id is provided, executes Phase 3A ephemeral authorization revalidation.
        """
        grant = None
        if grant_id:
            question, assignment, grant = await self.authorize_question_operation(
                actor=actor,
                question_id=question_id,
                operation=QuestionOperation.VIEW,
                grant_id=grant_id,
                session_id=session_id,
            )
            await self.audit.log(
                event_type="QUESTION_VIEWED",
                result=AuditResult.SUCCESS,
                actor_id=actor.id,
                actor_role=actor.role.value,
                resource_type="question",
                resource_id=question.id,
                metadata={"grant_id": grant.id, "assignment_id": assignment.id},
            )
        else:
            is_auth, question, assignment, err = await self.check_question_access(actor, question_id)
            if not is_auth:
                raise PermissionError(err or "Access denied to question")

        # Parse plaintext content if available
        content_dict = None
        if question.plaintext_content:
            try:
                content_dict = json.loads(question.plaintext_content)
            except Exception:
                content_dict = {"text": question.plaintext_content}

        return {
            "id": question.id,
            "exam_id": question.exam_id,
            "subject": question.subject,
            "topic": question.topic,
            "difficulty": question.difficulty,
            "bloom_level": question.bloom_level,
            "question_format": question.question_format,
            "marks_positive": question.marks_positive,
            "marks_negative": question.marks_negative,
            "status": question.status.value,
            "version": question.version,
            "content": content_dict,
            "assignment": {
                "id": assignment.id,
                "purpose": assignment.purpose.value,
                "status": assignment.status.value,
            } if assignment else None,
            "grant": {
                "id": grant.id,
                "status": grant.status.value,
                "operation": grant.operation.value,
                "expires_at": grant.expires_at.isoformat() if grant.expires_at else None,
            } if grant else None,
        }

    async def _get_question_owned(self, question_id: str, author: User) -> Question:
        """Get a question that must be owned by the requesting author."""
        result = await self.db.execute(
            select(Question).where(
                Question.id == question_id,
                Question.author_id == author.id,
            )
        )
        question = result.scalar_one_or_none()
        if not question:
            raise PermissionError("Question not found or access denied")
        return question
