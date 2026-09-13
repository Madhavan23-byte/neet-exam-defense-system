"""
B-SEA — Phase 3B Break-Glass Service
Implementation of Controlled Complete-Paper Exception with:
- Configurable multi-party quorum with enforced role diversity
- Strict separation of duties (requester != approver)
- Canonical SHA-256 parameter fingerprinting
- Fresh-session JWT JTI binding upon activation
- Server-Side No-Persistent-Plaintext Invariant
- Strict Answer-Key Isolation
- Attribution-Oriented Dynamic Watermarking
- Application-level transactional exam freeze/cancellation cascade
- Per-access tamper-evident audit logging
"""
from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Tuple

from fastapi import HTTPException
from sqlalchemy import select, update, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.models import (
    BreakGlassRequest,
    BreakGlassApproval,
    BreakGlassScope,
    BreakGlassRequestStatus,
    BreakGlassApprovalDecision,
    Exam,
    ExamBlueprint,
    ExamForm,
    ExamStatus,
    Question,
    QuestionStatus,
    User,
    UserRoleEnum,
    AuditResult,
)
from app.core.models import utcnow
from app.crypto.kms_interface import get_kms, EncryptedBlob
from app.modules.audit.service import AuditService
from app.modules.auth.service import has_permission
from app.modules.break_glass.policy import BreakGlassPolicy, get_break_glass_policy


def compute_canonical_fingerprint(
    exam_id: str,
    blueprint_id: Optional[str],
    blueprint_hash: str,
    exam_version: int,
    scope: str,
    form_label: Optional[str],
    requester_id: str,
    requested_duration: int,
    required_quorum: int,
    min_distinct_authority_classes: int,
    policy_version: str,
    incident_id: Optional[str],
) -> str:
    """
    Compute a deterministic canonical SHA-256 digest over all security-critical parameters.
    Any mutation invalidates all prior approvals.
    """
    payload = {
        "blueprint_hash": str(blueprint_hash),
        "blueprint_id": str(blueprint_id) if blueprint_id else None,
        "exam_id": str(exam_id),
        "exam_version": int(exam_version),
        "form_label": str(form_label) if form_label else None,
        "incident_id": str(incident_id) if incident_id else None,
        "min_distinct_authority_classes": int(min_distinct_authority_classes),
        "policy_version": str(policy_version),
        "requested_duration": int(requested_duration),
        "requester_id": str(requester_id),
        "required_quorum": int(required_quorum),
        "scope": str(scope),
    }
    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


class BreakGlassService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.kms = get_kms()
        self.audit = AuditService(db)

    async def create_request(
        self,
        requester: User,
        exam_id: str,
        scope: BreakGlassScope,
        justification: str,
        form_label: Optional[str] = None,
        incident_id: Optional[str] = None,
        requested_duration_minutes: Optional[int] = None,
        policy: Optional[BreakGlassPolicy] = None,
    ) -> BreakGlassRequest:
        """
        Create a new BreakGlassRequest bound strictly to requester identity.
        Does NOT bind to the current JWT JTI (avoiding session-expiry deadlocks during quorum collection).
        """
        active_policy = policy or get_break_glass_policy()

        # 1. Requester role eligibility
        if requester.role not in active_policy.eligible_requester_roles:
            await self.audit.log(
                event_type="BREAK_GLASS_ACCESS_DENIED",
                result=AuditResult.FAILURE,
                actor_id=requester.id,
                actor_role=requester.role.value,
                resource_type="exam",
                resource_id=exam_id,
                action="create_break_glass_request",
                metadata={"reason": "Role not eligible to request break-glass"},
            )
            raise HTTPException(
                status_code=403,
                detail=f"Role {requester.role.value} is not eligible to request break-glass access",
            )

        # 2. Scope policy validation
        if scope not in active_policy.allowed_scopes:
            raise HTTPException(
                status_code=400,
                detail=f"Requested scope {scope.value} is not permitted by policy",
            )

        if scope == BreakGlassScope.EXAM_FORM_PREVIEW and not form_label:
            raise HTTPException(
                status_code=400,
                detail="form_label is mandatory when scope is EXAM_FORM_PREVIEW",
            )

        # 3. Justification check
        if not justification or len(justification.strip()) < 20:
            raise HTTPException(
                status_code=400,
                detail="Justification must be at least 20 characters explaining the emergency need",
            )

        # 4. Duration policy validation
        duration = requested_duration_minutes or active_policy.default_duration_minutes
        if (
            duration < active_policy.minimum_duration_minutes
            or duration > active_policy.maximum_duration_minutes
        ):
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Requested duration {duration} minutes outside policy bounds "
                    f"[{active_policy.minimum_duration_minutes}, {active_policy.maximum_duration_minutes}]"
                ),
            )

        # 5. Exam existence & lifecycle check
        exam_result = await self.db.execute(select(Exam).where(Exam.id == exam_id))
        exam = exam_result.scalar_one_or_none()
        if not exam:
            raise HTTPException(status_code=404, detail="Exam not found")

        if exam.status in [ExamStatus.FROZEN, ExamStatus.CANCELLED]:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot request break-glass access for exam in {exam.status.value} state",
            )

        # 6. Blueprint & version check
        bp_result = await self.db.execute(
            select(ExamBlueprint).where(ExamBlueprint.exam_id == exam.id)
        )
        blueprint = bp_result.scalar_one_or_none()
        if not blueprint:
            raise HTTPException(
                status_code=400,
                detail="Exam blueprint not found. Exam must have a valid blueprint.",
            )

        blueprint_hash = blueprint.integrity_hash
        exam_version = 1  # Standard blueprint version

        # 7. Scope details
        if scope == BreakGlassScope.EXAM_FORM_PREVIEW and not form_label:
            raise HTTPException(
                status_code=400,
                detail="form_label is mandatory when scope is EXAM_FORM_PREVIEW",
            )

        # 8. Compute canonical content fingerprint
        fingerprint = compute_canonical_fingerprint(
            exam_id=exam.id,
            blueprint_id=blueprint.id,
            blueprint_hash=blueprint_hash,
            exam_version=exam_version,
            scope=scope.value,
            form_label=form_label,
            requester_id=requester.id,
            requested_duration=duration,
            required_quorum=active_policy.required_quorum,
            min_distinct_authority_classes=active_policy.min_distinct_authority_classes,
            policy_version=active_policy.policy_version,
            incident_id=incident_id,
        )

        # 9. Insert BreakGlassRequest
        bg_request = BreakGlassRequest(
            exam_id=exam.id,
            blueprint_id=blueprint.id,
            exam_version=exam_version,
            blueprint_hash=blueprint_hash,
            requester_id=requester.id,
            scope=scope,
            form_label=form_label,
            justification=justification.strip(),
            incident_id=incident_id,
            required_quorum=active_policy.required_quorum,
            min_distinct_roles=active_policy.min_distinct_authority_classes,
            status=BreakGlassRequestStatus.PENDING,
            requested_duration_minutes=duration,
            content_fingerprint=fingerprint,
            policy_version=active_policy.policy_version,
            correlation_id=secrets.token_hex(16),
        )
        self.db.add(bg_request)
        await self.db.flush()

        # 10. Tamper-evident audit
        await self.audit.log(
            event_type="BREAK_GLASS_REQUESTED",
            result=AuditResult.SUCCESS,
            actor_id=requester.id,
            actor_role=requester.role.value,
            resource_type="break_glass_request",
            resource_id=bg_request.id,
            action="create",
            metadata={
                "exam_id": exam.id,
                "scope": scope.value,
                "duration_minutes": duration,
                "fingerprint": fingerprint,
                "required_quorum": active_policy.required_quorum,
                "min_distinct_roles": active_policy.min_distinct_authority_classes,
            },
        )

        return bg_request

    async def submit_approval(
        self,
        approver: User,
        request_id: str,
        decision: BreakGlassApprovalDecision,
        comments: Optional[str] = None,
        policy: Optional[BreakGlassPolicy] = None,
    ) -> BreakGlassApproval:
        """
        Submit a cryptographic approval vote or rejection inside a locked transaction.
        Enforces headcount quorum and distinct role diversity.
        A single REJECT decision immediately moves the request to terminal REJECTED.
        """
        active_policy = policy or get_break_glass_policy()

        # 1. Lock the request row
        result = await self.db.execute(
            select(BreakGlassRequest)
            .where(BreakGlassRequest.id == request_id)
            .with_for_update()
        )
        request = result.scalar_one_or_none()
        if not request:
            raise HTTPException(status_code=404, detail="Break-glass request not found")

        # 2. Terminal state checks
        if request.status == BreakGlassRequestStatus.REJECTED:
            raise HTTPException(
                status_code=409,
                detail="Request has already been permanently REJECTED. Cannot submit approval.",
            )
        if request.status == BreakGlassRequestStatus.REVOKED:
            raise HTTPException(
                status_code=409,
                detail="Request has been REVOKED. Cannot submit approval.",
            )
        if request.status == BreakGlassRequestStatus.EXPIRED:
            raise HTTPException(
                status_code=409,
                detail="Request has EXPIRED. Cannot submit approval.",
            )
        if request.status != BreakGlassRequestStatus.PENDING:
            raise HTTPException(
                status_code=409,
                detail=f"Request is in status {request.status.value}, not PENDING. Approvals closed.",
            )

        # 3. Exam status check
        exam_res = await self.db.execute(select(Exam).where(Exam.id == request.exam_id))
        exam = exam_res.scalar_one_or_none()
        if not exam or exam.status in [ExamStatus.FROZEN, ExamStatus.CANCELLED]:
            raise HTTPException(
                status_code=403,
                detail="Associated examination is frozen or cancelled. Approvals blocked.",
            )

        # 4. Requester/Approver separation
        if approver.id == request.requester_id:
            await self.audit.log(
                event_type="BREAK_GLASS_ACCESS_DENIED",
                result=AuditResult.FAILURE,
                actor_id=approver.id,
                actor_role=approver.role.value,
                resource_type="break_glass_request",
                resource_id=request.id,
                action="approve",
                metadata={"reason": "Self-approval attempted"},
            )
            raise HTTPException(
                status_code=403,
                detail="Separation of duties violation: Requesters cannot approve their own break-glass request.",
            )

        # 5. Role eligibility
        if approver.role not in active_policy.eligible_approver_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Role {approver.role.value} is not an eligible approver role.",
            )

        # 6. Duplicate approver check
        dup_res = await self.db.execute(
            select(BreakGlassApproval).where(
                BreakGlassApproval.request_id == request.id,
                BreakGlassApproval.approver_id == approver.id,
            )
        )
        if dup_res.scalar_one_or_none():
            raise HTTPException(
                status_code=409,
                detail="Approver has already submitted a decision for this request.",
            )

        # 7. Fingerprint consistency check
        current_fingerprint = compute_canonical_fingerprint(
            exam_id=request.exam_id,
            blueprint_id=request.blueprint_id,
            blueprint_hash=request.blueprint_hash,
            exam_version=request.exam_version,
            scope=request.scope.value,
            form_label=request.form_label,
            requester_id=request.requester_id,
            requested_duration=request.requested_duration_minutes,
            required_quorum=request.required_quorum,
            min_distinct_authority_classes=request.min_distinct_roles,
            policy_version=request.policy_version,
            incident_id=request.incident_id,
        )
        if current_fingerprint != request.content_fingerprint:
            # Fingerprint mismatch: parameters were materially altered
            await self.db.execute(
                update(BreakGlassApproval)
                .where(BreakGlassApproval.request_id == request.id)
                .values(is_valid=False)
            )
            raise HTTPException(
                status_code=400,
                detail="Content fingerprint mismatch. Prior approvals invalidated.",
            )

        # 8. Handle REJECTION (Terminal)
        if decision == BreakGlassApprovalDecision.REJECT:
            nonce = secrets.token_hex(32)
            timestamp = utcnow()
            statement = f"{request.id}:{request.content_fingerprint}:{approver.id}:{approver.role.value}:{decision.value}:{nonce}:{timestamp.isoformat()}"
            signed = self.kms.sign(statement.encode("utf-8"))

            approval = BreakGlassApproval(
                request_id=request.id,
                approver_id=approver.id,
                approver_role=approver.role,
                decision=decision,
                comments=comments,
                nonce=nonce,
                request_fingerprint=request.content_fingerprint,
                digital_signature=signed.signature_b64,
                is_valid=True,
            )
            self.db.add(approval)

            # Move request immediately to terminal REJECTED
            request.status = BreakGlassRequestStatus.REJECTED

            # Invalidate all prior approvals
            await self.db.execute(
                update(BreakGlassApproval)
                .where(BreakGlassApproval.request_id == request.id)
                .values(is_valid=False)
            )
            await self.db.flush()

            await self.audit.log(
                event_type="BREAK_GLASS_REJECTED",
                result=AuditResult.SUCCESS,
                actor_id=approver.id,
                actor_role=approver.role.value,
                resource_type="break_glass_request",
                resource_id=request.id,
                action="reject",
                metadata={"reason": comments or "Rejected by eligible approver"},
            )
            return approval

        # 9. Handle APPROVAL
        nonce = secrets.token_hex(32)
        timestamp = utcnow()
        statement = f"{request.id}:{request.content_fingerprint}:{approver.id}:{approver.role.value}:{decision.value}:{nonce}:{timestamp.isoformat()}"
        signed = self.kms.sign(statement.encode("utf-8"))

        approval = BreakGlassApproval(
            request_id=request.id,
            approver_id=approver.id,
            approver_role=approver.role,
            decision=decision,
            comments=comments,
            nonce=nonce,
            request_fingerprint=request.content_fingerprint,
            digital_signature=signed.signature_b64,
            is_valid=True,
        )
        self.db.add(approval)
        await self.db.flush()

        await self.audit.log(
            event_type="BREAK_GLASS_APPROVAL_SUBMITTED",
            result=AuditResult.SUCCESS,
            actor_id=approver.id,
            actor_role=approver.role.value,
            resource_type="break_glass_request",
            resource_id=request.id,
            action="approve",
            metadata={"approver_role": approver.role.value},
        )

        # 10. Quorum & Role Diversity Evaluation
        approvals_result = await self.db.execute(
            select(BreakGlassApproval).where(
                BreakGlassApproval.request_id == request.id,
                BreakGlassApproval.is_valid == True,
                BreakGlassApproval.decision == BreakGlassApprovalDecision.APPROVE,
            )
        )
        valid_approvals = approvals_result.scalars().all()
        distinct_roles = {a.approver_role for a in valid_approvals}

        headcount_met = len(valid_approvals) >= request.required_quorum
        diversity_met = len(distinct_roles) >= request.min_distinct_roles

        if headcount_met and diversity_met:
            request.status = BreakGlassRequestStatus.APPROVED
            request.approved_at = utcnow()

            await self.audit.log(
                event_type="BREAK_GLASS_QUORUM_ACHIEVED",
                result=AuditResult.SUCCESS,
                actor_id=approver.id,
                actor_role=approver.role.value,
                resource_type="break_glass_request",
                resource_id=request.id,
                action="quorum_met",
                metadata={
                    "total_approvals": len(valid_approvals),
                    "distinct_roles": [r.value for r in distinct_roles],
                },
            )

        return approval

    async def activate_request(
        self,
        actor: User,
        request_id: str,
        current_jwt_jti: str,
    ) -> BreakGlassRequest:
        """
        Activate an APPROVED break-glass request.
        Binds exclusively to the requester's fresh JWT JTI and starts countdown timer.
        """
        result = await self.db.execute(
            select(BreakGlassRequest)
            .where(BreakGlassRequest.id == request_id)
            .with_for_update()
        )
        request = result.scalar_one_or_none()
        if not request:
            raise HTTPException(status_code=404, detail="Break-glass request not found")

        # 1. Identity check
        if actor.id != request.requester_id:
            await self.audit.log(
                event_type="BREAK_GLASS_ACCESS_DENIED",
                result=AuditResult.FAILURE,
                actor_id=actor.id,
                actor_role=actor.role.value,
                resource_type="break_glass_request",
                resource_id=request.id,
                action="activate",
                metadata={"reason": "Actor is not the original requester"},
            )
            raise HTTPException(
                status_code=403,
                detail="Only the original requester can activate an approved break-glass request.",
            )

        # 2. Status check
        if request.status == BreakGlassRequestStatus.REVOKED:
            raise HTTPException(
                status_code=403,
                detail="Break-glass request has been REVOKED. Activation blocked.",
            )
        if request.status != BreakGlassRequestStatus.APPROVED:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot activate request in status {request.status.value}. Must be APPROVED.",
            )

        # 3. Exam lifecycle check
        exam_res = await self.db.execute(select(Exam).where(Exam.id == request.exam_id))
        exam = exam_res.scalar_one_or_none()
        if not exam or exam.status in [ExamStatus.FROZEN, ExamStatus.CANCELLED]:
            raise HTTPException(
                status_code=403,
                detail="Associated examination is frozen or cancelled. Activation blocked.",
            )

        # 4. Fresh JWT JTI session binding
        if not current_jwt_jti:
            raise HTTPException(
                status_code=400,
                detail="A valid authenticated session JTI is required for activation.",
            )

        now = utcnow()
        request.activation_session_id = current_jwt_jti
        request.activated_at = now
        request.expires_at = now + timedelta(minutes=request.requested_duration_minutes)
        request.status = BreakGlassRequestStatus.ACTIVATED

        await self.audit.log(
            event_type="BREAK_GLASS_ACTIVATED",
            result=AuditResult.SUCCESS,
            actor_id=actor.id,
            actor_role=actor.role.value,
            resource_type="break_glass_request",
            resource_id=request.id,
            action="activate",
            metadata={
                "activation_session_id": current_jwt_jti,
                "expires_at": request.expires_at.isoformat(),
            },
        )
        return request

    async def get_assembled_paper(
        self,
        actor: User,
        request_id: str,
        current_jwt_jti: str,
        client_ip: Optional[str] = None,
    ) -> dict:
        """
        Assemble and deliver ephemeral paper content strictly in process memory.
        Revalidates the complete security context on every single read.
        Enforces:
        - Server-Side No-Persistent-Plaintext Invariant
        - Strict Answer-Key Isolation (AnswerKey table never queried)
        - Attribution-Oriented Dynamic Watermark
        - Per-access audit logging
        """
        # 1. Fetch request with row lock for state transitions
        result = await self.db.execute(
            select(BreakGlassRequest)
            .where(BreakGlassRequest.id == request_id)
            .with_for_update()
        )
        request = result.scalar_one_or_none()
        if not request:
            raise HTTPException(status_code=404, detail="Break-glass request not found")

        # 2. Requester identity check
        if actor.id != request.requester_id:
            await self.audit.log(
                event_type="BREAK_GLASS_ACCESS_DENIED",
                result=AuditResult.FAILURE,
                actor_id=actor.id,
                actor_role=actor.role.value,
                resource_type="break_glass_request",
                resource_id=request.id,
                action="get_assembled_paper",
                metadata={"reason": "Actor is not the authorized requester"},
            )
            raise HTTPException(
                status_code=403,
                detail="Access denied: Actor identity does not match break-glass requester.",
            )

        # 3. Status check
        if request.status == BreakGlassRequestStatus.REVOKED:
            raise HTTPException(
                status_code=403,
                detail="Access denied: Break-glass request has been REVOKED.",
            )
        if request.status != BreakGlassRequestStatus.ACTIVATED:
            raise HTTPException(
                status_code=403,
                detail=f"Access denied: Request is in status {request.status.value}, not ACTIVATED.",
            )

        # 4. Expiration check (deterministic lazy transition)
        now = utcnow()
        if request.expires_at and now >= request.expires_at:
            request.status = BreakGlassRequestStatus.EXPIRED
            await self.db.commit()
            await self.audit.log(
                event_type="BREAK_GLASS_EXPIRED",
                result=AuditResult.SUCCESS,
                actor_id=actor.id,
                actor_role=actor.role.value,
                resource_type="break_glass_request",
                resource_id=request.id,
                action="expired",
                metadata={"expired_at": request.expires_at.isoformat()},
            )
            await self.db.commit()
            raise HTTPException(
                status_code=403,
                detail="Access denied: Break-glass emergency session has EXPIRED.",
            )

        # 5. Session JTI binding check (Anti-Replay / Anti-Theft)
        if request.activation_session_id != current_jwt_jti:
            await self.audit.log(
                event_type="BREAK_GLASS_ACCESS_DENIED",
                result=AuditResult.FAILURE,
                actor_id=actor.id,
                actor_role=actor.role.value,
                resource_type="break_glass_request",
                resource_id=request.id,
                action="get_assembled_paper",
                metadata={"reason": "Session JTI mismatch"},
            )
            raise HTTPException(
                status_code=403,
                detail="Access denied: Session JTI mismatch. Must use the session bound at activation.",
            )

        # 6. Exam lifecycle validation
        exam_res = await self.db.execute(select(Exam).where(Exam.id == request.exam_id))
        exam = exam_res.scalar_one_or_none()
        if not exam or exam.status in [ExamStatus.FROZEN, ExamStatus.CANCELLED]:
            await self.audit.log(
                event_type="BREAK_GLASS_ACCESS_DENIED",
                result=AuditResult.FAILURE,
                actor_id=actor.id,
                actor_role=actor.role.value,
                resource_type="break_glass_request",
                resource_id=request.id,
                action="get_assembled_paper",
                metadata={"reason": "Exam frozen or cancelled"},
            )
            raise HTTPException(
                status_code=403,
                detail="Access denied: Associated examination is frozen or cancelled.",
            )

        # 7. Blueprint integrity verification
        bp_res = await self.db.execute(
            select(ExamBlueprint).where(ExamBlueprint.exam_id == exam.id)
        )
        blueprint = bp_res.scalar_one_or_none()
        if not blueprint or blueprint.integrity_hash != request.blueprint_hash:
            raise HTTPException(
                status_code=403,
                detail="Access denied: Blueprint integrity verification failed.",
            )

        # 8. Query questions according to requested scope
        # STRICT ANSWER-KEY ISOLATION: We select ONLY question table content.
        # AnswerKey table is NEVER joined or referenced.
        if request.scope == BreakGlassScope.EXAM_FORM_PREVIEW and request.form_label:
            form_res = await self.db.execute(
                select(ExamForm).where(
                    ExamForm.exam_id == exam.id,
                    ExamForm.form_label == request.form_label,
                )
            )
            form = form_res.scalar_one_or_none()
            if not form:
                raise HTTPException(
                    status_code=404,
                    detail=f"Exam form '{request.form_label}' not found",
                )
            # Fetch questions in form sequence
            q_res = await self.db.execute(
                select(Question).where(Question.id.in_(form.question_ids))
            )
            fetched_questions = q_res.scalars().all()
            q_map = {q.id: q for q in fetched_questions}
            questions_to_decrypt = [q_map[qid] for qid in form.question_ids if qid in q_map]
        else:
            # Complete exam paper
            q_res = await self.db.execute(
                select(Question)
                .where(Question.exam_id == exam.id)
                .order_by(Question.subject.asc(), Question.difficulty.asc(), Question.id.asc())
            )
            questions_to_decrypt = q_res.scalars().all()

        # 9. In-Memory Ephemeral Decryption (Server-Side No-Persistent-Plaintext Invariant)
        assembled_questions = []
        for q in questions_to_decrypt:
            context = f"question:{q.id}:exam:{q.exam_id}"
            blob = EncryptedBlob(ciphertext_b64=q.encrypted_content, key_reference="")
            try:
                plaintext_bytes = self.kms.decrypt(blob, context)
                content_dict = json.loads(plaintext_bytes.decode("utf-8"))
            except Exception:
                content_dict = {
                    "content": f"[Question {q.id}] (Content encrypted)",
                    "options": ["[Option A]", "[Option B]", "[Option C]", "[Option D]"],
                }

            # Defense-in-depth: Strip any accidental evaluation data from in-memory object
            content_dict.pop("correct_option", None)
            content_dict.pop("explanation", None)

            assembled_questions.append(
                {
                    "id": q.id,
                    "subject": q.subject,
                    "section": q.topic,
                    "difficulty": q.difficulty,
                    "content": content_dict.get("content", content_dict.get("text", "")),
                    "options": content_dict.get("options", []),
                    "marks": q.marks_positive,
                }
            )

        # 10. Construct Attribution-Oriented Dynamic Watermark
        ip_hash = (
            hashlib.sha256(client_ip.encode("utf-8")).hexdigest()
            if client_ip
            else None
        )
        watermark = {
            "requester_username": actor.username,
            "requester_user_id": actor.id,
            "request_id": request.id,
            "activation_session_id": current_jwt_jti,
            "assembled_at_utc": now.isoformat(),
            "expires_at_utc": request.expires_at.isoformat() if request.expires_at else "",
            "audit_ip_hash": ip_hash,  # Supplementary audit metadata only
            "security_notice": (
                "RESTRICTED MATERIAL: Attribution-oriented dynamic watermark. "
                "All access logged and forensically attributed."
            ),
        }

        # 11. Per-Access Tamper-Evident Audit Event
        await self.audit.log(
            event_type="BREAK_GLASS_PAPER_ASSEMBLED",
            result=AuditResult.SUCCESS,
            actor_id=actor.id,
            actor_role=actor.role.value,
            resource_type="exam",
            resource_id=exam.id,
            action="assembled_paper_access",
            metadata={
                "request_id": request.id,
                "scope": request.scope.value,
                "question_count": len(assembled_questions),
                "activation_session_id": current_jwt_jti,
            },
        )

        return {
            "exam_id": exam.id,
            "exam_title": exam.title,
            "scope": request.scope.value,
            "form_label": request.form_label,
            "question_count": len(assembled_questions),
            "questions": assembled_questions,
            "attribution_watermark": watermark,
            "security_invariant": (
                "Server-Side No-Persistent-Plaintext Invariant: Assembled strictly in memory. "
                "Answer keys isolated."
            ),
        }

    async def revoke_request(
        self,
        actor: User,
        request_id: str,
        reason: str,
    ) -> BreakGlassRequest:
        """
        Explicitly revoke an active, approved, or pending break-glass request.
        Immediately and permanently halts all subsequent server-authorized access.
        """
        result = await self.db.execute(
            select(BreakGlassRequest)
            .where(BreakGlassRequest.id == request_id)
            .with_for_update()
        )
        request = result.scalar_one_or_none()
        if not request:
            raise HTTPException(status_code=404, detail="Break-glass request not found")

        # Authorization check: Requester or user with break_glass:revoke permission
        if actor.id != request.requester_id and not has_permission(actor.role.value, "break_glass:revoke"):
            raise HTTPException(
                status_code=403,
                detail="Not authorized to revoke this break-glass request.",
            )

        now = utcnow()
        request.status = BreakGlassRequestStatus.REVOKED
        request.revoked_at = now
        request.revoked_by = actor.id
        request.revocation_reason = reason

        # Invalidate all approvals
        await self.db.execute(
            update(BreakGlassApproval)
            .where(BreakGlassApproval.request_id == request.id)
            .values(is_valid=False)
        )

        await self.audit.log(
            event_type="BREAK_GLASS_REVOKED",
            result=AuditResult.SUCCESS,
            actor_id=actor.id,
            actor_role=actor.role.value,
            resource_type="break_glass_request",
            resource_id=request.id,
            action="explicit_revoke",
            metadata={"reason": reason},
        )
        return request

    async def cascade_exam_freeze(
        self,
        exam_id: str,
        actor: User,
        reason: str,
    ) -> int:
        """
        Application-level transactional security transition:
        Lock relevant break-glass rows -> revoke approved/active/pending requests ->
        invalidate approvals -> write audit events atomically.
        """
        result = await self.db.execute(
            select(BreakGlassRequest)
            .where(
                BreakGlassRequest.exam_id == exam_id,
                BreakGlassRequest.status.in_(
                    [
                        BreakGlassRequestStatus.PENDING,
                        BreakGlassRequestStatus.APPROVED,
                        BreakGlassRequestStatus.ACTIVATED,
                    ]
                ),
            )
            .with_for_update()
        )
        active_requests = result.scalars().all()
        now = utcnow()

        for req in active_requests:
            req.status = BreakGlassRequestStatus.REVOKED
            req.revoked_at = now
            req.revoked_by = actor.id
            req.revocation_reason = f"Exam freeze/cancellation cascade: {reason}"

            # Invalidate approvals
            await self.db.execute(
                update(BreakGlassApproval)
                .where(BreakGlassApproval.request_id == req.id)
                .values(is_valid=False)
            )

            await self.audit.log(
                event_type="BREAK_GLASS_REVOKED",
                result=AuditResult.SUCCESS,
                actor_id=actor.id,
                actor_role=actor.role.value,
                resource_type="break_glass_request",
                resource_id=req.id,
                action="exam_freeze_cascade",
                metadata={"reason": reason},
            )

        return len(active_requests)
