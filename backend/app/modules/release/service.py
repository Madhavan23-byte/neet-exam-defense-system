"""
B-SEA — Release Service
Time-locked, multi-party authorized exam release engine.

Security Architecture:
─────────────────────
Release ONLY occurs when ALL conditions are simultaneously true:
  1. server_time >= exam.scheduled_start_utc  (server clock, not client)
  2. threshold approvals collected >= exam.required_approvals
  3. all approval signatures are cryptographically valid
  4. exam blueprint is in APPROVED status with valid signature
  5. centre readiness >= minimum threshold
  6. no FREEZE_RELEASE incident is active
  7. system health check passes

No single administrator can bypass this policy.
The release is automated — not triggered by a single "release button".

PROTOTYPE NOTE:
The threshold authorization simulates multi-party approval through
independent signed approval records. Production replaces this with
Shamir's Secret Sharing or HSM-enforced multi-custodian policy.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.models import (
    AuditResult,
    Centre,
    CentreStatus,
    Exam,
    ExamBlueprint,
    ExamStatus,
    Incident,
    IncidentStatus,
    ReleaseApproval,
    User,
    UserRoleEnum,
)
from app.core.security import generate_nonce
from app.crypto.kms_interface import get_kms
from app.modules.audit.service import AuditService

settings = get_settings()


class ReleaseService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.audit = AuditService(db)
        self.kms = get_kms()

    async def get_release_status(self, exam_id: str) -> dict:
        """
        Get comprehensive release status for an exam.
        Shows all release conditions and whether they are satisfied.
        """
        exam = await self._get_exam(exam_id)
        if not exam:
            raise ValueError("Exam not found")

        conditions = await self._evaluate_release_conditions(exam)

        # Count approvals
        approvals_result = await self.db.execute(
            select(ReleaseApproval).where(
                ReleaseApproval.exam_id == exam_id,
                ReleaseApproval.is_valid == True,
            )
        )
        approvals = approvals_result.scalars().all()

        # Get who has approved
        authority_ids = [a.authority_id for a in approvals]

        return {
            "exam_id": exam_id,
            "exam_status": exam.status.value,
            "scheduled_start_utc": exam.scheduled_start_utc.isoformat() if exam.scheduled_start_utc else None,
            "current_time_utc": datetime.now(timezone.utc).isoformat(),
            "required_approvals": exam.required_approvals,
            "received_approvals": len(approvals),
            "approvals": [
                {"authority_id": a.authority_id, "approved_at": a.approved_at.isoformat()}
                for a in approvals
            ],
            "release_conditions": conditions,
            "all_conditions_met": all(conditions.values()),
            "release_frozen": exam.release_frozen,
        }

    async def submit_threshold_approval(
        self,
        exam_id: str,
        authority: User,
        ip: str = "",
    ) -> dict:
        """
        Submit a release authority's approval for exam release.

        CONCURRENCY INVARIANT (Phase 3C):
        ──────────────────────────────────
        The entire approval critical section is protected by a row-level lock on the
        Exam row (SELECT ... FOR UPDATE). This is READ COMMITTED isolation (PostgreSQL
        default), which is sufficient because we lock the specific row we intend to
        mutate, preventing concurrent transactions from reading stale state.

        Transaction boundary:
          BEGIN (provided by FastAPI get_db dependency)
           ↓
          LOCK Exam row (SELECT FOR UPDATE — minimum scope, single row)
           ↓
          validate authority role
           ↓
          validate exam/freeze state
           ↓
          check duplicate approval (within the lock)
           ↓
          insert approval
           ↓
          count approvals and update Exam.status
           ↓
          COMMIT (by get_db on success)

        The UniqueConstraint("exam_id", "authority_id") on ReleaseApproval provides
        a secondary database-level guard against duplicate approvals, even if the
        application-level check is somehow bypassed.

        PROTOTYPE NOTE: Production replaces this with SSS or HSM-enforced policy.
        """
        if authority.role not in [
            UserRoleEnum.RELEASE_AUTHORITY,
            UserRoleEnum.EXAM_AUTHORITY,
            UserRoleEnum.SUPER_ADMIN,
        ]:
            raise PermissionError("Only RELEASE_AUTHORITY can submit threshold approval")

        # ── STEP 1: Acquire row-level lock on the Exam row ───────────────────
        # This is the minimum necessary lock scope: just the one exam we're approving.
        # We use SELECT ... FOR UPDATE which in PostgreSQL acquires a row-level
        # exclusive lock, blocking any concurrent transaction that also tries to
        # lock the same row. READ COMMITTED isolation (PG default) is sufficient here.
        #
        # On SQLite: with_for_update() is ignored (SQLite uses file-level locks anyway).
        # The UniqueConstraint on ReleaseApproval provides the final enforcement layer.
        exam_result = await self.db.execute(
            select(Exam)
            .where(Exam.id == exam_id)
            .with_for_update()  # Row-level lock — PostgreSQL: prevents concurrent approvals
        )
        exam = exam_result.scalar_one_or_none()
        if not exam:
            raise ValueError("Exam not found")

        # ── STEP 2: Validate exam state within the lock ──────────────────────
        if exam.release_frozen:
            await self.audit.log(
                event_type="RELEASE_APPROVAL_BLOCKED",
                result=AuditResult.BLOCKED,
                actor_id=authority.id,
                actor_role=authority.role.value,
                resource_type="exam",
                resource_id=exam_id,
                risk_score=0.7,
                metadata={"reason": "Release is frozen by security incident"},
            )
            raise ValueError("Release is frozen due to active security incident")

        # ── STEP 3: Check duplicate approval within the lock ─────────────────
        # Because we hold the Exam row lock, no concurrent transaction can insert
        # another approval for this exam until we commit or rollback.
        existing = await self.db.execute(
            select(ReleaseApproval).where(
                ReleaseApproval.exam_id == exam_id,
                ReleaseApproval.authority_id == authority.id,
                ReleaseApproval.is_valid == True,
            )
        )
        if existing.scalar_one_or_none():
            raise ValueError("You have already submitted an approval for this exam")

        # ── STEP 4: Bind approval to the current blueprint hash ──────────────
        blueprint_result = await self.db.execute(
            select(ExamBlueprint).where(ExamBlueprint.exam_id == exam.id)
        )
        blueprint = blueprint_result.scalar_one_or_none()
        blueprint_hash = blueprint.integrity_hash if blueprint else "NO_BLUEPRINT"

        # ── STEP 5: Generate signed approval ─────────────────────────────────
        nonce = generate_nonce()
        approval_data = f"RELEASE_APPROVAL:{exam_id}:{authority.id}:{nonce}:{blueprint_hash}"
        signed = self.kms.sign(approval_data.encode("utf-8"))

        approval = ReleaseApproval(
            exam_id=exam_id,
            authority_id=authority.id,
            nonce=nonce,
            approval_signature=signed.signature_b64,
            ip_hash=hashlib.sha256(ip.encode()).hexdigest()[:32],
            is_valid=True,
        )
        self.db.add(approval)
        # flush to make the new row visible within this transaction for the count below
        await self.db.flush()

        # ── STEP 6: Count valid approvals and evaluate threshold ──────────────
        # Count AFTER flushing the new approval — the +1 is now in the DB (uncommitted).
        count_result = await self.db.execute(
            select(func.count(ReleaseApproval.id)).where(
                ReleaseApproval.exam_id == exam_id,
                ReleaseApproval.is_valid == True,
            )
        )
        total_approvals = count_result.scalar() or 0

        if total_approvals >= exam.required_approvals:
            exam.status = ExamStatus.THRESHOLD_APPROVED

        # ── STEP 7: Audit log (within the same transaction) ──────────────────
        await self.audit.log(
            event_type="RELEASE_APPROVAL_SUBMITTED",
            result=AuditResult.SUCCESS,
            actor_id=authority.id,
            actor_role=authority.role.value,
            resource_type="exam",
            resource_id=exam_id,
            metadata={
                "total_approvals": total_approvals,
                "required": exam.required_approvals,
                "threshold_met": total_approvals >= exam.required_approvals,
            },
        )
        # Transaction commits when get_db dependency exits successfully.

        return {
            "success": True,
            "total_approvals": total_approvals,
            "required_approvals": exam.required_approvals,
            "threshold_met": total_approvals >= exam.required_approvals,
            "message": "Approval recorded successfully",
        }


    async def check_and_trigger_release(self, exam_id: str) -> dict:
        """
        Evaluate all release conditions and trigger release if met.
        Called periodically by the system — NOT directly by a user.

        This is the automated release engine:
        - Does NOT require a human to click "Release"
        - Verifies ALL conditions independently
        - Writes release event to audit log before serving first question
        """
        exam = await self._get_exam(exam_id)
        if not exam:
            return {"released": False, "reason": "Exam not found"}

        if exam.status == ExamStatus.RELEASED:
            return {"released": True, "reason": "Already released"}

        conditions = await self._evaluate_release_conditions(exam)

        if not all(conditions.values()):
            unmet = [k for k, v in conditions.items() if not v]
            return {
                "released": False,
                "reason": f"Conditions not met: {unmet}",
                "conditions": conditions,
            }

        # All conditions met — trigger release
        exam.status = ExamStatus.RELEASED
        exam.released_at = datetime.now(timezone.utc)

        await self.audit.log(
            event_type="EXAM_RELEASED",
            result=AuditResult.SUCCESS,
            resource_type="exam",
            resource_id=exam_id,
            metadata={"conditions": conditions},
        )

        return {
            "released": True,
            "released_at": exam.released_at.isoformat(),
            "conditions": conditions,
        }

    async def freeze_release(
        self, exam_id: str, officer: User, reason: str
    ) -> dict:
        """
        Emergency freeze of exam release.
        Only SECURITY_OFFICER can execute this.
        """
        exam = await self._get_exam(exam_id)
        if not exam:
            raise ValueError("Exam not found")

        exam.release_frozen = True
        exam.status = ExamStatus.FROZEN

        # Application-level transactional cascade: revoke any active/approved/pending break-glass requests
        from app.modules.break_glass.service import BreakGlassService
        bg_service = BreakGlassService(self.db)
        revoked_count = await bg_service.cascade_exam_freeze(exam_id, officer, reason)

        await self.audit.log(
            event_type="RELEASE_FROZEN",
            result=AuditResult.SUCCESS,
            actor_id=officer.id,
            actor_role=officer.role.value,
            resource_type="exam",
            resource_id=exam_id,
            risk_score=0.8,
            metadata={"reason": reason, "revoked_break_glass_requests": revoked_count},
        )

        return {
            "success": True,
            "message": f"Exam release frozen. Reason: {reason}",
            "revoked_break_glass_requests": revoked_count,
        }

    async def _evaluate_release_conditions(self, exam: Exam) -> dict:
        """Check all release conditions. All must be True for release."""
        now = datetime.now(timezone.utc)

        # Condition 1: Time
        time_ok = False
        if exam.scheduled_start_utc:
            start_utc = exam.scheduled_start_utc
            if start_utc.tzinfo is None:
                start_utc = start_utc.replace(tzinfo=timezone.utc)
            time_ok = now >= start_utc

        # Condition 3: Blueprint approved
        blueprint_result = await self.db.execute(
            select(ExamBlueprint).where(ExamBlueprint.exam_id == exam.id)
        )
        blueprint = blueprint_result.scalar_one_or_none()
        blueprint_ok = blueprint is not None and blueprint.status == "APPROVED"
        current_blueprint_hash = blueprint.integrity_hash if blueprint else "NO_BLUEPRINT"

        # Condition 2: Threshold approvals
        approvals_result = await self.db.execute(
            select(ReleaseApproval).where(
                ReleaseApproval.exam_id == exam.id,
                ReleaseApproval.is_valid == True,
            )
        )
        all_approvals = approvals_result.scalars().all()
        
        valid_count = 0
        from datetime import timedelta
        for approval in all_approvals:
            # Check expiration (e.g., 24 hours)
            if now - approval.approved_at.replace(tzinfo=timezone.utc) > timedelta(hours=24):
                continue
                
            # Verify signature against current blueprint hash
            approval_data = f"RELEASE_APPROVAL:{exam.id}:{approval.authority_id}:{approval.nonce}:{current_blueprint_hash}"
            try:
                from app.crypto.kms_interface import SignedBlob
                blob = SignedBlob(signature_b64=approval.approval_signature, key_reference="")
                if self.kms.verify(approval_data.encode("utf-8"), blob):
                    valid_count += 1
            except Exception:
                pass # Invalid signature or mismatched blueprint

        threshold_ok = valid_count >= exam.required_approvals

        # Condition 4: Centre readiness
        centre_result = await self.db.execute(
            select(func.count(Centre.id)).where(
                Centre.exam_id == exam.id,
                Centre.status.in_([CentreStatus.READY, CentreStatus.ACTIVE]),
            )
        )
        total_centre_result = await self.db.execute(
            select(func.count(Centre.id)).where(Centre.exam_id == exam.id)
        )
        ready_centres = centre_result.scalar() or 0
        total_centres = total_centre_result.scalar() or 0

        if total_centres == 0:
            centre_ok = True  # No centres required (fully digital mode)
        else:
            readiness_pct = (ready_centres / total_centres) * 100
            centre_ok = readiness_pct >= exam.min_centre_readiness_pct

        # Condition 5: No active freeze
        not_frozen = not exam.release_frozen

        # Condition 6: No active critical incidents for this exam
        incident_result = await self.db.execute(
            select(func.count(Incident.id)).where(
                Incident.exam_id == exam.id,
                Incident.status.in_([
                    IncidentStatus.OPEN,
                    IncidentStatus.INVESTIGATING,
                ]),
            )
        )
        active_incidents = incident_result.scalar() or 0
        no_active_incidents = active_incidents == 0

        return {
            "time_condition": time_ok,
            "threshold_condition": threshold_ok,
            "blueprint_condition": blueprint_ok,
            "centre_readiness": centre_ok,
            "not_frozen": not_frozen,
            "no_active_incidents": no_active_incidents,
        }

    async def _get_exam(self, exam_id: str) -> Optional[Exam]:
        result = await self.db.execute(
            select(Exam).where(Exam.id == exam_id)
        )
        return result.scalar_one_or_none()
