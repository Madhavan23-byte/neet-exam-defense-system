"""B-SEA — Dashboard API"""
from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta, timezone

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.core.models import (
    User, Exam, Question, CandidateSession, SecurityEvent,
    Incident, AuditLog, SessionStatus, ExamStatus, QuestionStatus, IncidentStatus
)

router = APIRouter()


@router.get("/overview")
async def get_dashboard_overview(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Master dashboard overview."""
    # Exams
    total_exams = await db.execute(select(func.count(Exam.id)).where(Exam.org_id == current_user.org_id))
    active_exams = await db.execute(
        select(func.count(Exam.id)).where(Exam.org_id == current_user.org_id, Exam.status == ExamStatus.RELEASED)
    )

    # Questions
    total_q = await db.execute(select(func.count(Question.id)))
    encrypted_q = await db.execute(
        select(func.count(Question.id)).where(Question.status == QuestionStatus.ENCRYPTED)
    )

    # Sessions
    active_sessions = await db.execute(
        select(func.count(CandidateSession.id)).where(CandidateSession.status == SessionStatus.ACTIVE)
    )

    # Security
    last_24h = datetime.now(timezone.utc) - timedelta(hours=24)
    recent_security = await db.execute(
        select(func.count(SecurityEvent.id)).where(SecurityEvent.created_at >= last_24h)
    )
    open_incidents = await db.execute(
        select(func.count(Incident.id)).where(Incident.status.in_(["OPEN", "INVESTIGATING"]))
    )
    critical_events = await db.execute(
        select(func.count(SecurityEvent.id)).where(
            SecurityEvent.severity.in_(["HIGH", "CRITICAL"]),
            SecurityEvent.resolved == False
        )
    )

    # Recent exams
    exams_result = await db.execute(
        select(Exam).where(Exam.org_id == current_user.org_id).order_by(Exam.created_at.desc()).limit(5)
    )
    recent_exams = exams_result.scalars().all()

    return {
        "stats": {
            "total_exams": total_exams.scalar() or 0,
            "active_exams": active_exams.scalar() or 0,
            "total_questions": total_q.scalar() or 0,
            "encrypted_questions": encrypted_q.scalar() or 0,
            "active_sessions": active_sessions.scalar() or 0,
            "security_events_24h": recent_security.scalar() or 0,
            "open_incidents": open_incidents.scalar() or 0,
            "critical_unresolved": critical_events.scalar() or 0,
        },
        "recent_exams": [
            {
                "id": e.id,
                "title": e.title,
                "status": e.status.value,
                "security_mode": e.security_mode.value,
                "scheduled_start_utc": e.scheduled_start_utc.isoformat() if e.scheduled_start_utc else None,
            }
            for e in recent_exams
        ],
        "system_health": {
            "api": "healthy",
            "database": "healthy",
            "kms": "mock_kms_prototype",
            "cache": "healthy",
        },
    }
