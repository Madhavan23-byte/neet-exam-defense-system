"""B-SEA — Security, Audit, Incidents, Dashboard APIs"""
# security.py
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from typing import Optional

from app.core.database import get_db
from app.core.dependencies import get_current_user, require_role
from app.core.models import AuditLog, SecurityEvent, Incident, IncidentSeverity, IncidentStatus, User, Exam, Question, CandidateSession, SessionStatus, UserRoleEnum
from app.modules.security.service import SecurityService
from app.modules.audit.service import AuditService

router = APIRouter()


@router.get("/events", dependencies=[Depends(require_role(UserRoleEnum.SUPER_ADMIN, UserRoleEnum.SECURITY_OFFICER, UserRoleEnum.AUDITOR))])
async def get_security_events(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    service = SecurityService(db)
    return await service.get_dashboard_stats()


@router.get("/events/list", dependencies=[Depends(require_role(UserRoleEnum.SUPER_ADMIN, UserRoleEnum.SECURITY_OFFICER, UserRoleEnum.AUDITOR))])
async def list_security_events(
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(SecurityEvent).order_by(SecurityEvent.created_at.desc()).limit(limit)
    )
    events = result.scalars().all()
    return [
        {
            "id": e.id,
            "event_type": e.event_type,
            "severity": e.severity,
            "actor_id": e.actor_id,
            "risk_score": e.risk_score,
            "details": e.details,
            "resolved": e.resolved,
            "created_at": e.created_at.isoformat(),
        }
        for e in events
    ]
