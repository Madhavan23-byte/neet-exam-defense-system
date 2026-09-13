import json
from typing import Any, Dict, List, Optional, Union
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field

from app.core.database import get_db
from app.core.dependencies import get_client_ip, get_current_user, require_permission, require_role, limiter
from app.core.models import User, UserRoleEnum, ReviewPurpose, QuestionAssignmentStatus
from app.core.config import get_settings
from app.modules.questions.service import QuestionService

router = APIRouter()
settings = get_settings()


class QuestionContentPayload(BaseModel):
    text: str
    options: List[str] = Field(default_factory=list)
    type: Optional[str] = "MCQ"
    diagram_urls: Optional[List[str]] = Field(default_factory=list)
    latex_equations: Optional[List[str]] = Field(default_factory=list)


def normalize_question_content(content: Union[str, QuestionContentPayload, dict]) -> str:
    """
    Normalize question content to canonical deterministic JSON string.
    Ensures exact canonical representation is used for hashing, encryption,
    decryption, and integrity verification.
    """
    if isinstance(content, QuestionContentPayload):
        raw_dict = content.model_dump()
    elif isinstance(content, dict):
        raw_dict = content
    elif isinstance(content, str):
        try:
            parsed = json.loads(content)
            if isinstance(parsed, dict):
                raw_dict = parsed
            else:
                raw_dict = {"text": str(parsed), "options": [], "type": "MCQ"}
        except (json.JSONDecodeError, TypeError):
            raw_dict = {"text": content, "options": [], "type": "MCQ"}
    else:
        raise ValueError("Invalid question content format")

    # Canonical dictionary structure
    data = {
        "text": str(raw_dict.get("text", "")),
        "options": list(raw_dict.get("options", [])),
        "type": str(raw_dict.get("type", "MCQ")),
    }
    if raw_dict.get("diagram_urls"):
        data["diagram_urls"] = list(raw_dict["diagram_urls"])
    if raw_dict.get("latex_equations"):
        data["latex_equations"] = list(raw_dict["latex_equations"])

    return json.dumps(data, sort_keys=True, separators=(",", ":"))


class CreateQuestionRequest(BaseModel):
    exam_id: str
    subject: str
    topic: Optional[str] = None
    difficulty: str = "medium"
    bloom_level: Optional[str] = None
    content: Union[str, QuestionContentPayload, dict]
    correct_option: int
    marks_positive: float = 4.0
    marks_negative: float = 1.0


class ReviewRequest(BaseModel):
    verdict: str  # APPROVED, REJECTED
    comments: Optional[str] = None


class AssignQuestionRequest(BaseModel):
    reviewer_id: str
    purpose: Optional[ReviewPurpose] = ReviewPurpose.TECHNICAL_REVIEW


class ShardQuestionsRequest(BaseModel):
    reviewer_ids: List[str]
    shard_size: Optional[int] = None
    redundancy: int = 1
    purpose: Optional[ReviewPurpose] = ReviewPurpose.TECHNICAL_REVIEW


class ReassignQuestionRequest(BaseModel):
    new_reviewer_id: str
    reason: str


class SubmitReviewRequest(BaseModel):
    assignment_id: str
    verdict: str  # APPROVED, REJECTED, NEEDS_REVISION
    comments: Optional[str] = None


# ── ROUTES ───────────────────────────────────────────────────────────────────

@router.post("/", dependencies=[Depends(require_permission("questions:create"))])
async def create_question(
    body: CreateQuestionRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new question in DRAFT status."""
    service = QuestionService(db)
    canonical_content = normalize_question_content(body.content)
    question = await service.create_question(
        exam_id=body.exam_id,
        author=current_user,
        subject=body.subject,
        topic=body.topic,
        difficulty=body.difficulty,
        bloom_level=body.bloom_level,
        content=canonical_content,
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


@router.get("/assignments/me")
async def get_my_assignments(
    exam_id: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get all question assignments for the authenticated reviewer."""
    service = QuestionService(db)
    return await service.get_reviewer_assignments(current_user, exam_id)


@router.get("/exam/{exam_id}")
@limiter.limit(settings.rate_limit_api)
async def list_questions(
    request: Request,
    exam_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List questions — strictly scoped by role and active assignment."""
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


@router.get("/{question_id}")
async def get_question_detail(
    question_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Direct question retrieval with strict IDOR defense.
    Reviewers can only fetch questions they are actively assigned to review.
    """
    service = QuestionService(db)
    try:
        return await service.get_question_detail(current_user, question_id)
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


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


@router.post("/{question_id}/assign")
async def assign_question(
    question_id: str,
    body: AssignQuestionRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Manually assign a question to an active reviewer."""
    service = QuestionService(db)
    try:
        assignment = await service.assign_question(
            question_id=question_id,
            reviewer_id=body.reviewer_id,
            assigned_by=current_user,
            purpose=body.purpose or ReviewPurpose.TECHNICAL_REVIEW,
        )
        return {
            "success": True,
            "assignment_id": assignment.id,
            "question_id": assignment.question_id,
            "reviewer_id": assignment.reviewer_id,
            "purpose": assignment.purpose.value,
            "status": assignment.status.value,
        }
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        err_str = str(e)
        status_code = status.HTTP_409_CONFLICT if "already exists" in err_str.lower() else status.HTTP_400_BAD_REQUEST
        raise HTTPException(status_code=status_code, detail=err_str)


@router.post("/exam/{exam_id}/shard")
async def shard_exam_questions(
    exam_id: str,
    body: ShardQuestionsRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Batch-shard submitted exam questions using OS-backed CSPRNG."""
    service = QuestionService(db)
    try:
        return await service.shard_exam_questions(
            exam_id=exam_id,
            reviewer_ids=body.reviewer_ids,
            assigned_by=current_user,
            shard_size=body.shard_size,
            redundancy=body.redundancy,
            purpose=body.purpose or ReviewPurpose.TECHNICAL_REVIEW,
        )
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/assignments/{assignment_id}/reassign")
async def reassign_question(
    assignment_id: str,
    body: ReassignQuestionRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Atomically revoke current assignment and create replacement assignment."""
    service = QuestionService(db)
    try:
        assignment = await service.reassign_question(
            assignment_id=assignment_id,
            new_reviewer_id=body.new_reviewer_id,
            reassigned_by=current_user,
            reason=body.reason,
        )
        return {
            "success": True,
            "new_assignment_id": assignment.id,
            "question_id": assignment.question_id,
            "new_reviewer_id": assignment.reviewer_id,
            "status": assignment.status.value,
        }
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/assignments/{assignment_id}/start")
async def start_review(
    assignment_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Reviewer starts review session (ACTIVE -> IN_REVIEW)."""
    service = QuestionService(db)
    try:
        assignment = await service.start_review(assignment_id, current_user)
        return {
            "success": True,
            "assignment_id": assignment.id,
            "status": assignment.status.value,
            "started_at": assignment.started_at.isoformat() if assignment.started_at else None,
        }
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/{question_id}/review")
async def submit_question_review(
    question_id: str,
    body: SubmitReviewRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Reviewer submits review on an assigned question (IN_REVIEW -> COMPLETED)."""
    service = QuestionService(db)
    try:
        review = await service.submit_review(
            assignment_id=body.assignment_id,
            actor=current_user,
            verdict=body.verdict,
            comments=body.comments,
        )
        return {
            "success": True,
            "review_id": review.id,
            "question_id": review.question_id,
            "verdict": review.verdict,
        }
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/{question_id}/approve", dependencies=[Depends(require_permission("questions:approve"))])
async def approve_question(
    question_id: str,
    body: ReviewRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Approve a question. Triggers immediate encryption.
    Moderator must be assigned to question during normal review workflow.
    """
    service = QuestionService(db)
    try:
        question = await service.approve_question(question_id, current_user, body.comments or "")
        return {
            "id": question.id,
            "status": question.status.value,
            "encrypted": question.encrypted_content is not None,
            "integrity_hash": question.content_hash,
            "message": "Question approved and encrypted. Plaintext cleared from database.",
        }
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/{question_id}/reject", dependencies=[Depends(require_permission("questions:reject"))])
async def reject_question(
    question_id: str,
    body: ReviewRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Reject a question. Moderator must be assigned to question during normal review workflow."""
    if not body.comments:
        raise HTTPException(status_code=400, detail="Rejection reason is required")
    service = QuestionService(db)
    try:
        question = await service.reject_question(question_id, current_user, body.comments)
        return {"id": question.id, "status": question.status.value}
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
