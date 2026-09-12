"""B-SEA — Questions API"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from app.core.database import get_db
from app.core.dependencies import get_client_ip, get_current_user, require_permission, require_role, limiter
from app.core.models import User, UserRoleEnum
from app.core.config import get_settings
from app.modules.questions.service import QuestionService

router = APIRouter()
settings = get_settings()


class CreateQuestionRequest(BaseModel):
    exam_id: str
    subject: str
    topic: Optional[str] = None
    difficulty: str = "medium"
    bloom_level: Optional[str] = None
    content: str  # JSON string with question text + options
    correct_option: int
    marks_positive: float = 4.0
    marks_negative: float = 1.0


class ReviewRequest(BaseModel):
    verdict: str  # APPROVED, REJECTED
    comments: Optional[str] = None


@router.post("/", dependencies=[Depends(require_permission("questions:create"))])
async def create_question(
    body: CreateQuestionRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new question in DRAFT status."""
    service = QuestionService(db)
    question = await service.create_question(
        exam_id=body.exam_id,
        author=current_user,
        subject=body.subject,
        topic=body.topic,
        difficulty=body.difficulty,
        bloom_level=body.bloom_level,
        content=body.content,
        correct_option=body.correct_option,
        marks_positive=body.marks_positive,
        marks_negative=body.marks_negative,
        ip=get_client_ip(request),
    )
    return {
        "id": question.id,
        "status": question.status.value,
        "subject": question.subject,
        "difficulty": question.difficulty,
        "created_at": question.created_at.isoformat(),
    }


@router.get("/exam/{exam_id}")
@limiter.limit(settings.rate_limit_api)
async def list_questions(
    request: Request,
    exam_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List questions — scoped by role (setters see own, reviewers see submitted)."""
    service = QuestionService(db)
    questions = await service.list_questions(current_user, exam_id)
    return [
        {
            "id": q.id,
            "subject": q.subject,
            "topic": q.topic,
            "difficulty": q.difficulty,
            "status": q.status.value,
            "version": q.version,
            "has_encrypted_content": q.encrypted_content is not None,
            "integrity_hash": q.content_hash,
            "created_at": q.created_at.isoformat(),
            "approved_at": q.approved_at.isoformat() if q.approved_at else None,
        }
        for q in questions
    ]


@router.post("/{question_id}/submit")
async def submit_question(
    question_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Submit a DRAFT question for review."""
    if current_user.role != UserRoleEnum.QUESTION_SETTER:
        raise HTTPException(status_code=403, detail="Only QUESTION_SETTER can submit")
    service = QuestionService(db)
    question = await service.submit_question(question_id, current_user)
    return {"id": question.id, "status": question.status.value}


@router.post("/{question_id}/approve", dependencies=[Depends(require_permission("questions:approve"))])
async def approve_question(
    question_id: str,
    body: ReviewRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Approve a question (MODERATOR/EXAM_AUTHORITY). Triggers immediate encryption."""
    service = QuestionService(db)
    question = await service.approve_question(question_id, current_user, body.comments or "")
    return {
        "id": question.id,
        "status": question.status.value,
        "encrypted": question.encrypted_content is not None,
        "integrity_hash": question.content_hash,
        "message": "Question approved and encrypted. Plaintext cleared from database.",
    }


@router.post("/{question_id}/reject", dependencies=[Depends(require_permission("questions:reject"))])
async def reject_question(
    question_id: str,
    body: ReviewRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Reject a question (MODERATOR)."""
    if not body.comments:
        raise HTTPException(status_code=400, detail="Rejection reason is required")
    service = QuestionService(db)
    question = await service.reject_question(question_id, current_user, body.comments)
    return {"id": question.id, "status": question.status.value}
