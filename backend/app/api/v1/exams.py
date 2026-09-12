"""B-SEA — Exams, Blueprints, Forms API"""
import hashlib
import json
import secrets
from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from app.core.database import get_db
from app.core.dependencies import get_current_user, require_permission
from app.core.models import (
    Exam, ExamBlueprint, ExamForm, ExamStatus, FormStatus, Question, QuestionStatus, User
)
from app.crypto.kms_interface import compute_integrity_hash, get_kms
from app.modules.audit.service import AuditService

router = APIRouter()


class CreateExamRequest(BaseModel):
    title: str
    description: Optional[str] = None
    exam_type: str = "CBT"
    security_mode: str = "HIGH"
    scheduled_start_utc: Optional[str] = None
    scheduled_end_utc: Optional[str] = None
    duration_minutes: int = 180
    required_approvals: int = 3


class CreateBlueprintRequest(BaseModel):
    subjects: dict  # {"Physics": 45, "Chemistry": 45, "Biology": 90}
    difficulty_distribution: dict  # {"easy": 30, "medium": 75, "hard": 30}
    total_questions: int
    marks_per_correct: float = 4.0
    marks_per_incorrect: float = 1.0
    negative_marking: bool = True
    navigation_allowed: bool = True
    form_count: int = 4


@router.post("/", dependencies=[Depends(require_permission("exams:create"))])
async def create_exam(
    body: CreateExamRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new exam."""
    start_utc = None
    end_utc = None
    if body.scheduled_start_utc:
        start_utc = datetime.fromisoformat(body.scheduled_start_utc)
    if body.scheduled_end_utc:
        end_utc = datetime.fromisoformat(body.scheduled_end_utc)

    exam = Exam(
        org_id=current_user.org_id,
        title=body.title,
        description=body.description,
        exam_type=body.exam_type,
        security_mode=body.security_mode,
        scheduled_start_utc=start_utc,
        scheduled_end_utc=end_utc,
        duration_minutes=body.duration_minutes,
        required_approvals=body.required_approvals,
        created_by=current_user.id,
    )
    db.add(exam)
    await db.flush()

    audit = AuditService(db)
    await audit.log(
        event_type="EXAM_CREATED",
        actor_id=current_user.id,
        actor_role=current_user.role.value,
        resource_type="exam",
        resource_id=exam.id,
    )

    return {
        "id": exam.id,
        "title": exam.title,
        "status": exam.status.value,
        "scheduled_start_utc": exam.scheduled_start_utc.isoformat() if exam.scheduled_start_utc else None,
        "required_approvals": exam.required_approvals,
    }


@router.get("/")
async def list_exams(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all exams for the organization."""
    result = await db.execute(
        select(Exam).where(Exam.org_id == current_user.org_id).order_by(Exam.created_at.desc())
    )
    exams = result.scalars().all()
    return [
        {
            "id": e.id,
            "title": e.title,
            "status": e.status.value,
            "security_mode": e.security_mode.value,
            "scheduled_start_utc": e.scheduled_start_utc.isoformat() if e.scheduled_start_utc else None,
            "duration_minutes": e.duration_minutes,
            "required_approvals": e.required_approvals,
            "release_frozen": e.release_frozen,
        }
        for e in exams
    ]


@router.get("/{exam_id}")
async def get_exam(
    exam_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Exam).where(Exam.id == exam_id))
    exam = result.scalar_one_or_none()
    if not exam:
        raise HTTPException(status_code=404, detail="Exam not found")
    return {
        "id": exam.id,
        "title": exam.title,
        "description": exam.description,
        "status": exam.status.value,
        "security_mode": exam.security_mode.value,
        "scheduled_start_utc": exam.scheduled_start_utc.isoformat() if exam.scheduled_start_utc else None,
        "scheduled_end_utc": exam.scheduled_end_utc.isoformat() if exam.scheduled_end_utc else None,
        "duration_minutes": exam.duration_minutes,
        "required_approvals": exam.required_approvals,
        "release_frozen": exam.release_frozen,
        "released_at": exam.released_at.isoformat() if exam.released_at else None,
    }


@router.post("/{exam_id}/blueprint", dependencies=[Depends(require_permission("blueprint:create"))])
async def create_blueprint(
    exam_id: str,
    body: CreateBlueprintRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create exam blueprint. Blueprint defines what questions the exam contains."""
    config = {
        "subjects": body.subjects,
        "difficulty_distribution": body.difficulty_distribution,
        "total_questions": body.total_questions,
        "marks_per_correct": body.marks_per_correct,
        "marks_per_incorrect": body.marks_per_incorrect,
        "negative_marking": body.negative_marking,
        "navigation_allowed": body.navigation_allowed,
        "form_count": body.form_count,
    }
    config_json = json.dumps(config, sort_keys=True)
    integrity_hash = compute_integrity_hash(config_json.encode())

    kms = get_kms()
    signed = kms.sign(integrity_hash.encode())

    blueprint = ExamBlueprint(
        exam_id=exam_id,
        config=config,
        integrity_hash=integrity_hash,
        digital_signature=signed.signature_b64,
        status="DRAFT",
        created_by=current_user.id,
    )
    db.add(blueprint)

    exam_result = await db.execute(select(Exam).where(Exam.id == exam_id))
    exam = exam_result.scalar_one_or_none()
    if exam:
        exam.status = ExamStatus.BLUEPRINT_CREATED

    await db.flush()

    audit = AuditService(db)
    await audit.log(
        event_type="BLUEPRINT_CREATED",
        actor_id=current_user.id,
        actor_role=current_user.role.value,
        resource_type="blueprint",
        resource_id=blueprint.id,
    )

    return {
        "id": blueprint.id,
        "integrity_hash": integrity_hash,
        "status": blueprint.status,
        "config": config,
    }


@router.post("/{exam_id}/blueprint/approve", dependencies=[Depends(require_permission("blueprint:update"))])
async def approve_blueprint(
    exam_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Approve exam blueprint."""
    result = await db.execute(select(ExamBlueprint).where(ExamBlueprint.exam_id == exam_id))
    blueprint = result.scalar_one_or_none()
    if not blueprint:
        raise HTTPException(status_code=404, detail="Blueprint not found")

    blueprint.status = "APPROVED"
    blueprint.approved_by = current_user.id
    blueprint.approved_at = datetime.utcnow()

    return {"status": "APPROVED", "id": blueprint.id}


@router.post("/{exam_id}/forms/generate", dependencies=[Depends(require_permission("forms:generate"))])
async def generate_forms(
    exam_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Generate multiple equivalent exam forms from the approved blueprint.

    Forms contain question ID lists in randomized order.
    Content is NOT decrypted here — only IDs are shuffled.
    No plaintext exam paper is created at this stage.
    """
    # Get blueprint
    bp_result = await db.execute(select(ExamBlueprint).where(ExamBlueprint.exam_id == exam_id))
    blueprint = bp_result.scalar_one_or_none()
    if not blueprint or blueprint.status != "APPROVED":
        raise HTTPException(status_code=400, detail="Blueprint must be APPROVED before generating forms")

    # Get approved/encrypted questions
    q_result = await db.execute(
        select(Question).where(
            Question.exam_id == exam_id,
            Question.status.in_([QuestionStatus.ENCRYPTED, QuestionStatus.READY, QuestionStatus.APPROVED])
        )
    )
    questions = q_result.scalars().all()

    if not questions:
        raise HTTPException(status_code=400, detail="No encrypted questions available for form generation")

    form_count = blueprint.config.get("form_count", 4)
    form_labels = ["A", "B", "C", "D", "E", "F"][:form_count]
    question_ids = [q.id for q in questions]

    created_forms = []
    for label in form_labels:
        # Cryptographically secure shuffle for each form
        shuffled = question_ids.copy()
        # Fisher-Yates shuffle using secrets module
        for i in range(len(shuffled) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            shuffled[i], shuffled[j] = shuffled[j], shuffled[i]

        # Per-question option randomization
        option_orders = {}
        for qid in shuffled:
            order = list(range(4))  # 0-3 (A-D)
            for i in range(len(order) - 1, 0, -1):
                j = secrets.randbelow(i + 1)
                order[i], order[j] = order[j], order[i]
            option_orders[qid] = order

        form_data = json.dumps({"question_ids": shuffled}, sort_keys=True)
        integrity_hash = compute_integrity_hash(form_data.encode())

        form = ExamForm(
            exam_id=exam_id,
            form_label=label,
            question_ids=shuffled,
            option_orders=option_orders,
            integrity_hash=integrity_hash,
            status=FormStatus.ACTIVE if label == "A" else FormStatus.BACKUP,
        )
        db.add(form)
        created_forms.append({"label": label, "question_count": len(shuffled), "integrity_hash": integrity_hash})

    exam_result = await db.execute(select(Exam).where(Exam.id == exam_id))
    exam = exam_result.scalar_one_or_none()
    if exam:
        exam.status = ExamStatus.FORMS_GENERATED

    await db.flush()

    audit = AuditService(db)
    await audit.log(
        event_type="FORMS_GENERATED",
        actor_id=current_user.id,
        actor_role=current_user.role.value,
        resource_type="exam",
        resource_id=exam_id,
        metadata={"form_count": form_count, "question_count": len(question_ids)},
    )

    return {
        "forms_created": len(created_forms),
        "forms": created_forms,
        "security_note": (
            "Forms contain question ID lists only. "
            "Question content remains encrypted. "
            "No plaintext exam paper exists at this stage."
        ),
    }
