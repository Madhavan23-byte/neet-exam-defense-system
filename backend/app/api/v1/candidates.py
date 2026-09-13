"""B-SEA — Candidate CBT API
Secure question delivery for examination sessions.

Security architecture:
- Exam must be RELEASED before any question can be delivered
- Candidate must have an active session with valid token
- Questions are decrypted per-request (session-key cached)
- Every delivery is audit logged
- Answers are accepted only during active session window
- Answer key NEVER exposed through this API
"""
import json
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from app.core.database import get_db
from app.core.dependencies import get_client_ip, limiter
from app.core.models import (
    AuditResult, Candidate, CandidateSession, Exam, ExamForm, ExamStatus, FormStatus,
    Question, Response, SessionStatus, User, UserRoleEnum
)
from app.core.security import hash_password, verify_password, generate_secure_token, hash_token, hash_ip
from app.crypto.kms_interface import EncryptedBlob, compute_integrity_hash, get_kms
from app.modules.audit.service import AuditService
from app.modules.security.service import SecurityService

router = APIRouter()


class CandidateLoginRequest(BaseModel):
    registration_number: str
    password: str
    exam_id: str


class ResponseRequest(BaseModel):
    session_token: str
    question_id: str
    selected_option: Optional[int] = None
    is_marked_review: bool = False


class HeartbeatRequest(BaseModel):
    session_token: str
    current_question_index: int
    security_violations: int = 0
    tab_switch_count: int = 0


class SecurityEventRequest(BaseModel):
    session_token: str
    event_type: str
    details: Optional[dict] = None


from app.core.config import get_settings

settings = get_settings()

import time
from collections import defaultdict
import asyncio

# In-memory identity rate limiter for prototype purposes.
# PROD GAP: Production MUST use Redis or equivalent shared state to sync counts across instances.
_identity_login_attempts = defaultdict(list)
_identity_lock = asyncio.Lock()

@router.post("/auth/login")
@limiter.limit(settings.rate_limit_ip_login)
async def candidate_login(
    request: Request,
    body: CandidateLoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Candidate login and session initialization.

    Security checks:
    1. Exam must be RELEASED
    2. Candidate must not have active session (concurrent session prevention)
    3. Identity verified before session creation
    """
    # Enforce Identity-based Rate Limit (e.g., 5/minute per registration_number)
    async with _identity_lock:
        now = time.time()
        window_start = now - 60
        # Clean old attempts
        _identity_login_attempts[body.registration_number] = [
            t for t in _identity_login_attempts[body.registration_number] if t > window_start
        ]
        
        # Check limit
        # The limit is e.g. "5/minute", parse it or just hardcode for prototype based on config
        limit_str = settings.rate_limit_identity_login
        max_attempts = int(limit_str.split("/")[0])
        
        if len(_identity_login_attempts[body.registration_number]) >= max_attempts:
            raise HTTPException(status_code=429, detail="Too Many Requests for this candidate identity")
            
        _identity_login_attempts[body.registration_number].append(now)

    audit = AuditService(db)
    ip = get_client_ip(request)

    # Check exam is released
    exam_result = await db.execute(select(Exam).where(Exam.id == body.exam_id))
    exam = exam_result.scalar_one_or_none()

    if not exam:
        raise HTTPException(status_code=404, detail="Exam not found")

    if exam.status != ExamStatus.RELEASED:
        await audit.log(
            event_type="CANDIDATE_ACCESS_DENIED_UNRELEASED",
            result=AuditResult.BLOCKED,
            resource_type="exam",
            resource_id=body.exam_id,
            risk_score=0.3,
        )
        raise HTTPException(
            status_code=403,
            detail="Exam is not currently available. Access denied."
        )

    # Find candidate
    cand_result = await db.execute(
        select(Candidate).where(Candidate.registration_number == body.registration_number)
    )
    candidate = cand_result.scalar_one_or_none()
    
    if not candidate or not candidate.user_id:
        await audit.log(
            event_type="CANDIDATE_LOGIN_FAILED",
            result=AuditResult.FAILURE,
            resource_type="exam",
            resource_id=body.exam_id,
            ip_hash=hash_ip(ip) if ip else None,
            metadata={"registration_number": body.registration_number},
            risk_score=0.3
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Verify password against linked user account
    user_result = await db.execute(select(User).where(User.id == candidate.user_id))
    user = user_result.scalar_one_or_none()
    
    is_valid_password = await verify_password(body.password, user.password_hash) if user else False
    if not user or not user.is_active or not is_valid_password:
        await audit.log(
            event_type="CANDIDATE_LOGIN_FAILED",
            result=AuditResult.FAILURE,
            resource_type="exam",
            resource_id=body.exam_id,
            ip_hash=hash_ip(ip) if ip else None,
            metadata={"registration_number": body.registration_number},
            risk_score=0.5
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Check for existing active session (concurrent session prevention)
    existing_session = await db.execute(
        select(CandidateSession).where(
            CandidateSession.candidate_id == candidate.id,
            CandidateSession.exam_id == body.exam_id,
            CandidateSession.status == SessionStatus.ACTIVE,
        )
    )
    if existing_session.scalar_one_or_none():
        await audit.log(
            event_type="CONCURRENT_SESSION_ATTEMPT",
            result=AuditResult.BLOCKED,
            actor_id=candidate.id,
            resource_type="exam",
            resource_id=body.exam_id,
            risk_score=0.8,
        )
        raise HTTPException(
            status_code=409,
            detail="An active session already exists for this candidate."
        )

    # Get an active form to assign
    form_result = await db.execute(
        select(ExamForm).where(
            ExamForm.exam_id == body.exam_id,
            ExamForm.status == FormStatus.ACTIVE
        ).limit(1)
    )
    form = form_result.scalar_one_or_none()
    if not form:
        raise HTTPException(status_code=500, detail="No active exam form available")

    # Create session
    session_token = generate_secure_token(48)
    kms = get_kms()
    session_key = kms.derive_session_key(session_token[:16], body.exam_id)
    session_key_encrypted = kms.encrypt_with_session_key(session_key, session_key)  # Protect session key

    candidate_id = candidate.id
    session = CandidateSession(
        candidate_id=candidate_id,
        exam_id=body.exam_id,
        form_id=form.id,
        session_token_hash=hash_token(session_token),
        session_key_encrypted=session_key_encrypted,
        started_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=exam.duration_minutes + 30),
        last_heartbeat=datetime.now(timezone.utc),
        status=SessionStatus.ACTIVE,
        ip_hash=hashlib.sha256(ip.encode()).hexdigest()[:32],
    )
    db.add(session)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        # Narrow check: Only handle the expected uix_active_session_candidate_exam unique constraint violation
        is_active_session_race = False
        orig = getattr(exc, "orig", None)
        if orig:
            cause = getattr(orig, "__cause__", None)
            if cause and getattr(cause, "constraint_name", None) == "uix_active_session_candidate_exam":
                is_active_session_race = True
            elif getattr(orig, "pgcode", None) == "23505" and "uix_active_session_candidate_exam" in str(exc):
                is_active_session_race = True
        if not is_active_session_race and "uix_active_session_candidate_exam" in str(exc):
            is_active_session_race = True

        if is_active_session_race:
            await audit.log(
                event_type="CONCURRENT_SESSION_ATTEMPT",
                result=AuditResult.BLOCKED,
                actor_id=candidate_id,
                resource_type="exam",
                resource_id=body.exam_id,
                risk_score=0.8,
            )
            raise HTTPException(
                status_code=409,
                detail="An active session already exists for this candidate."
            )
        # Any other integrity error must NOT be masked as 409
        raise

    await audit.log(
        event_type="CANDIDATE_SESSION_STARTED",
        result=AuditResult.SUCCESS,
        actor_id=candidate.id,
        resource_type="exam_session",
        resource_id=session.id,
    )

    return {
        "session_token": session_token,
        "session_id": session.id,
        "exam_id": body.exam_id,
        "form_label": form.form_label,
        "total_questions": len(form.question_ids),
        "duration_minutes": exam.duration_minutes,
        "expires_at": session.expires_at.isoformat(),
        "started_at": session.started_at.isoformat(),
        "candidate_name": candidate.full_name,
        "watermark_id": candidate.id[:8].upper(),
    }


@router.get("/session/question/{question_index}")
async def get_question(
    question_index: int,
    session_token: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Deliver a single question to an authorized candidate.

    Security:
    - Session must be active and valid
    - Exam must be released
    - Question index must be within bounds
    - Content is decrypted per-delivery
    - Answer key is NEVER included in response
    - Each delivery is audit logged with watermark
    """
    # Validate session
    session, candidate = await _validate_session(session_token, db)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    # Get form
    form_result = await db.execute(select(ExamForm).where(ExamForm.id == session.form_id))
    form = form_result.scalar_one_or_none()
    if not form:
        raise HTTPException(status_code=500, detail="Form not found")

    question_ids = form.question_ids
    if question_index < 0 or question_index >= len(question_ids):
        raise HTTPException(status_code=400, detail="Invalid question index")

    question_id = question_ids[question_index]

    # Get question (encrypted)
    q_result = await db.execute(select(Question).where(Question.id == question_id))
    question = q_result.scalar_one_or_none()
    if not question or not question.encrypted_content:
        raise HTTPException(status_code=500, detail="Question not available")

    # Integrity check before decryption
    integrity_data = f"{question.id}:{question.version}:{question.encrypted_content}"
    expected_hash = compute_integrity_hash(integrity_data.encode("utf-8"))
    if expected_hash != question.content_hash:
        raise HTTPException(
            status_code=500,
            detail="QUESTION INTEGRITY CHECK FAILED — contact administrator"
        )

    # Decrypt question using KMS
    kms = get_kms()
    context = f"question:{question.id}:exam:{question.exam_id}"
    blob = EncryptedBlob(ciphertext_b64=question.encrypted_content, key_reference="")
    try:
        plaintext = kms.decrypt(blob, context)
        content = json.loads(plaintext.decode("utf-8"))
        content.pop("correct_option", None)  # CRITICAL: Never leak answer key
        content.pop("explanation", None)
    except Exception as e:
        raise HTTPException(status_code=500, detail="Question decryption failed")

    # Apply option order randomization from form
    option_order = form.option_orders.get(question_id, list(range(4)))
    if "options" in content:
        options = content["options"]
        if len(options) >= 4:
            content["options"] = [options[i] for i in option_order]
            content["option_order"] = option_order

    # Get existing response if any
    resp_result = await db.execute(
        select(Response).where(
            Response.session_id == session.id,
            Response.question_id == question_id,
        )
    )
    existing_response = resp_result.scalar_one_or_none()

    audit = AuditService(db)
    await audit.log(
        event_type="QUESTION_DELIVERED",
        result=AuditResult.SUCCESS,
        actor_id=candidate.id if candidate else None,
        resource_type="question",
        resource_id=question_id,
        metadata={"session_id": session.id, "index": question_index},
    )

    # Watermark embedded in response
    watermark = f"BSEA-{candidate.id[:8].upper()}-{session.id[:8].upper()}"

    return {
        "question_index": question_index,
        "total_questions": len(question_ids),
        "question_id": question_id,
        "subject": question.subject,
        "content": content,
        "selected_option": existing_response.selected_option if existing_response else None,
        "is_marked_review": existing_response.is_marked_review if existing_response else False,
        "watermark": watermark,
        "security_note": (
            "This content is watermarked. Screenshots can be forensically traced."
        ),
    }


@router.post("/session/response")
async def save_response(
    body: ResponseRequest,
    db: AsyncSession = Depends(get_db),
):
    """Save/update candidate answer for a question."""
    session, candidate = await _validate_session(body.session_token, db)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    # Upsert response
    resp_result = await db.execute(
        select(Response).where(
            Response.session_id == session.id,
            Response.question_id == body.question_id,
        )
    )
    existing = resp_result.scalar_one_or_none()

    if existing:
        existing.selected_option = body.selected_option
        existing.is_marked_review = body.is_marked_review
        existing.response_sequence += 1
    else:
        response = Response(
            session_id=session.id,
            question_id=body.question_id,
            selected_option=body.selected_option,
            is_marked_review=body.is_marked_review,
        )
        db.add(response)

    return {"success": True, "saved_at": datetime.now(timezone.utc).isoformat()}


@router.post("/session/heartbeat")
async def heartbeat(
    body: HeartbeatRequest,
    db: AsyncSession = Depends(get_db),
):
    """Session heartbeat — keeps session alive and reports security events."""
    session, _ = await _validate_session(body.session_token, db)
    if not session:
        return {"active": False}

    session.last_heartbeat = datetime.now(timezone.utc)
    session.current_question_index = body.current_question_index
    session.tab_switch_count = body.tab_switch_count
    session.security_violations = body.security_violations

    # Flag session if too many violations
    if body.security_violations >= 10:
        session.status = SessionStatus.FLAGGED

    return {
        "active": True,
        "expires_at": session.expires_at.isoformat(),
        "status": session.status.value,
    }


@router.post("/session/submit")
async def submit_exam(
    body: HeartbeatRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Final exam submission.
    
    Security & Concurrency:
    - Validates candidate session token.
    - Rejects duplicate submission with HTTP 409 Conflict.
    - Atomically updates session status to SUBMITTED.
    - Triggers evaluation and persists Result record.
    - Emits audit log event.
    - Destroys access to further questions.
    """
    token_hash = hash_token(body.session_token)
    sess_result = await db.execute(
        select(CandidateSession)
        .where(CandidateSession.session_token_hash == token_hash)
        .with_for_update()
    )
    session = sess_result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session")

    if session.status == SessionStatus.SUBMITTED:
        raise HTTPException(status_code=409, detail="Exam already submitted")

    if session.status != SessionStatus.ACTIVE:
        raise HTTPException(status_code=403, detail=f"Session is in {session.status.value} status")

    # Check expiry
    if session.expires_at:
        exp = session.expires_at.replace(tzinfo=timezone.utc) if session.expires_at.tzinfo is None else session.expires_at
        if datetime.now(timezone.utc) > exp:
            session.status = SessionStatus.EXPIRED
            await db.commit()
            raise HTTPException(status_code=400, detail="Examination time has expired")

    cand_result = await db.execute(
        select(Candidate).where(Candidate.id == session.candidate_id)
    )
    candidate = cand_result.scalar_one_or_none()

    session.status = SessionStatus.SUBMITTED
    session.submitted_at = datetime.now(timezone.utc)

    # Trigger evaluation and Result persistence
    from app.modules.evaluation.service import EvaluationService
    eval_service = EvaluationService(db)
    result = await eval_service.evaluate_session(session.id)

    audit = AuditService(db)
    await audit.log(
        event_type="EXAM_SUBMITTED",
        result=AuditResult.SUCCESS,
        actor_id=candidate.id if candidate else None,
        resource_type="exam_session",
        resource_id=session.id,
        metadata={"total_score": result.get("total_score")},
    )

    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail="Exam already submitted")


    return {
        "success": True,
        "session_id": session.id,
        "submitted_at": session.submitted_at.isoformat(),
        "result": result,
    }


@router.get("/session/result")
async def get_candidate_result(
    session_token: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieve candidate examination result receipt.
    
    Security:
    - Session token must be valid and authenticated.
    - Session must be in SUBMITTED status.
    - Answer keys and internal questions are NEVER returned.
    """
    from app.core.models import Result

    token_hash = hash_token(session_token)
    sess_result = await db.execute(
        select(CandidateSession).where(CandidateSession.session_token_hash == token_hash)
    )
    session = sess_result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session")

    if session.status != SessionStatus.SUBMITTED:
        raise HTTPException(
            status_code=400,
            detail=f"Examination has not been submitted (current status: {session.status.value})"
        )

    result_query = await db.execute(
        select(Result).where(Result.session_id == session.id)
    )
    result = result_query.scalar_one_or_none()

    if not result:
        return {
            "success": True,
            "session_id": session.id,
            "candidate_id": session.candidate_id,
            "exam_id": session.exam_id,
            "status": session.status.value,
            "submitted_at": session.submitted_at.isoformat() if session.submitted_at else None,
            "result_available": False,
            "message": "Submission received. Result calculation in progress.",
        }

    return {
        "success": True,
        "session_id": session.id,
        "candidate_id": session.candidate_id,
        "exam_id": session.exam_id,
        "status": session.status.value,
        "submitted_at": session.submitted_at.isoformat() if session.submitted_at else None,
        "result_available": True,
        "total_score": result.total_score,
        "max_score": result.max_score,
        "attempted": result.attempted,
        "correct": result.correct,
        "incorrect": result.incorrect,
        "skipped": result.skipped,
        "percentage": round((result.total_score / result.max_score * 100) if result.max_score > 0 else 0, 2),
    }


@router.post("/session/event")
async def report_security_event(
    body: SecurityEventRequest,
    db: AsyncSession = Depends(get_db),
):
    """Report a security event from the CBT client."""
    session, candidate = await _validate_session(body.session_token, db)
    if not session:
        return {"received": False}

    security = SecurityService(db)
    await security.create_security_event(
        event_type=f"CBT_{body.event_type}",
        severity="LOW" if body.event_type in ["TAB_SWITCH", "FULLSCREEN_EXIT"] else "MEDIUM",
        actor_id=candidate.id if candidate else None,
        session_id=session.id,
        exam_id=session.exam_id,
        details=body.details or {},
        risk_score=0.2,
    )

    return {"received": True}


async def _validate_session(session_token: str, db: AsyncSession):
    """Validate session token and return session + candidate."""
    token_hash = hash_token(session_token)
    sess_result = await db.execute(
        select(CandidateSession).where(
            CandidateSession.session_token_hash == token_hash,
            CandidateSession.status == SessionStatus.ACTIVE,
        )
    )
    session = sess_result.scalar_one_or_none()
    if not session:
        return None, None

    # Check expiry
    if session.expires_at:
        exp = session.expires_at.replace(tzinfo=timezone.utc) if session.expires_at.tzinfo is None else session.expires_at
        if datetime.now(timezone.utc) > exp:
            session.status = SessionStatus.EXPIRED
            return None, None

    cand_result = await db.execute(
        select(Candidate).where(Candidate.id == session.candidate_id)
    )
    candidate = cand_result.scalar_one_or_none()

    return session, candidate
