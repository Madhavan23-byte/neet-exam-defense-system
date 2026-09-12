"""
B-SEA — Question Service
Secure question authoring, encryption, review, and lifecycle management.

Security principles:
- Questions are encrypted immediately upon approval
- Plaintext content is cleared from DB after encryption
- Each question has Ed25519 signature + SHA-3 integrity hash
- Question setters can only access their own questions
- Reviewers can only access assigned questions
- No bulk export endpoint exists
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.models import (
    AuditResult,
    AnswerKey,
    Question,
    QuestionReview,
    QuestionStatus,
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
from app.modules.security.service import SecurityService


class QuestionService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.audit = AuditService(db)
        self.kms = get_kms()

    def _question_context(self, question_id: str, exam_id: str) -> str:
        """Build KMS context string for question encryption."""
        return f"question:{question_id}:exam:{exam_id}"

    async def create_question(
        self,
        exam_id: str,
        author: User,
        subject: str,
        topic: Optional[str],
        difficulty: str,
        bloom_level: Optional[str],
        content: str,  # Question text + options (JSON)
        correct_option: int,
        marks_positive: float = 4.0,
        marks_negative: float = 1.0,
        ip: str = "",
    ) -> Question:
        """
        Create a new question in DRAFT status.
        Content is stored as plaintext only in DRAFT status.
        """
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
            plaintext_content=content,  # Temporary — cleared on encrypt
        )
        self.db.add(question)
        await self.db.flush()

        # Store answer key separately (protected table)
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
            ip_hash=hash_ip(ip),
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

    async def approve_question(
        self, question_id: str, moderator: User, comments: str = ""
    ) -> Question:
        """Approve a question and immediately encrypt it."""
        result = await self.db.execute(
            select(Question).where(Question.id == question_id)
        )
        question = result.scalar_one_or_none()

        if not question:
            raise ValueError("Question not found")

        if question.status not in [QuestionStatus.SUBMITTED, QuestionStatus.UNDER_REVIEW]:
            raise ValueError(f"Cannot approve question in status {question.status}")

        # Create review record
        review = QuestionReview(
            question_id=question_id,
            reviewer_id=moderator.id,
            verdict="APPROVED",
            comments=comments,
        )
        self.db.add(review)

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
        )

        # Immediately encrypt after approval
        await self._encrypt_question(question)

        return question

    async def reject_question(
        self, question_id: str, moderator: User, reason: str
    ) -> Question:
        """Reject a question and return to author for revision."""
        result = await self.db.execute(
            select(Question).where(Question.id == question_id)
        )
        question = result.scalar_one_or_none()

        if not question:
            raise ValueError("Question not found")

        review = QuestionReview(
            question_id=question_id,
            reviewer_id=moderator.id,
            verdict="REJECTED",
            comments=reason,
        )
        self.db.add(review)

        question.status = QuestionStatus.REJECTED
        question.rejection_reason = reason

        await self.audit.log(
            event_type="QUESTION_REJECTED",
            result=AuditResult.SUCCESS,
            actor_id=moderator.id,
            actor_role=moderator.role.value,
            resource_type="question",
            resource_id=question_id,
            metadata={"reason": reason},
        )
        return question

    async def _encrypt_question(self, question: Question) -> None:
        """
        Encrypt question content using KMS.
        Clears plaintext content after encryption.
        Computes integrity hash and digital signature.

        This is the critical security operation:
        After this step, the question content is only accessible
        through the KMS, which enforces access policies.
        """
        if not question.plaintext_content:
            return

        context = self._question_context(question.id, question.exam_id)

        # Encrypt the question content
        content_bytes = question.plaintext_content.encode("utf-8")
        encrypted_blob = self.kms.encrypt(content_bytes, context)

        # Compute integrity hash over encrypted content
        integrity_data = f"{question.id}:{question.version}:{encrypted_blob.ciphertext_b64}"
        integrity_hash = compute_integrity_hash(integrity_data.encode("utf-8"))

        # Sign the integrity hash
        signed = self.kms.sign(integrity_hash.encode("utf-8"))

        # Update question record
        question.encrypted_content = encrypted_blob.ciphertext_b64
        question.key_reference = encrypted_blob.key_reference
        question.content_hash = integrity_hash
        question.digital_signature = signed.signature_b64
        question.status = QuestionStatus.ENCRYPTED

        # CRITICAL: Clear plaintext from database
        question.plaintext_content = None

        await self.audit.log(
            event_type="QUESTION_ENCRYPTED",
            result=AuditResult.SUCCESS,
            resource_type="question",
            resource_id=question.id,
            metadata={"key_reference": encrypted_blob.key_reference},
        )

    async def decrypt_question_for_delivery(
        self, question_id: str, session_id: str, exam_id: str
    ) -> Optional[dict]:
        """
        Decrypt a question for delivery to an authorized candidate session.
        Only call this from the delivery service with a validated session.
        """
        result = await self.db.execute(
            select(Question).where(Question.id == question_id)
        )
        question = result.scalar_one_or_none()

        if not question or not question.encrypted_content:
            return None

        # Verify integrity before decryption
        integrity_data = f"{question.id}:{question.version}:{question.encrypted_content}"
        expected_hash = compute_integrity_hash(integrity_data.encode("utf-8"))

        if expected_hash != question.content_hash:
            await self.audit.log(
                event_type="QUESTION_INTEGRITY_FAILURE",
                result=AuditResult.FAILURE,
                resource_type="question",
                resource_id=question_id,
                risk_score=0.9,
            )
            raise ValueError("QUESTION INTEGRITY CHECK FAILED — possible tampering detected")

        context = self._question_context(question.id, question.exam_id)
        blob = EncryptedBlob(
            ciphertext_b64=question.encrypted_content,
            key_reference=question.key_reference or "",
        )

        plaintext = self.kms.decrypt(blob, context)

        await self.audit.log(
            event_type="QUESTION_DECRYPTED",
            result=AuditResult.SUCCESS,
            resource_type="question",
            resource_id=question_id,
            metadata={"session_id": session_id},
        )

        return json.loads(plaintext.decode("utf-8"))

    async def list_questions(
        self, actor: User, exam_id: str
    ) -> List[Question]:
        """
        List questions. Access is scoped by role:
        - QUESTION_SETTER: only own questions
        - REVIEWER/MODERATOR: assigned questions (all submitted for now in prototype)
        - EXAM_AUTHORITY/SUPER_ADMIN/AUDITOR: metadata only (no content)
        """
        query = select(Question).where(Question.exam_id == exam_id)

        if actor.role == UserRoleEnum.QUESTION_SETTER:
            query = query.where(Question.author_id == actor.id)
        elif actor.role in [UserRoleEnum.REVIEWER, UserRoleEnum.MODERATOR]:
            query = query.where(
                Question.status.in_([
                    QuestionStatus.SUBMITTED,
                    QuestionStatus.UNDER_REVIEW,
                ])
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

    async def _get_question_owned(self, question_id: str, author: User) -> Question:
        """Get a question that must be owned by the requesting user."""
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
