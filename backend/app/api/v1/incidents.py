"""B-SEA — Incidents API"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone

from app.core.database import get_db
from app.core.dependencies import get_current_user, require_role
from app.core.models import Incident, IncidentSeverity, IncidentStatus, User, CandidateSession, SessionStatus

router = APIRouter()


class CreateIncidentRequest(BaseModel):
    title: str
    severity: str
    exam_id: Optional[str] = None
    description: Optional[str] = None
    affected_resource: Optional[str] = None


class IncidentActionRequest(BaseModel):
    action: str
    target_id: str
    reason: str


@router.post("/", dependencies=[Depends(require_role("SECURITY_OFFICER", "SUPER_ADMIN"))])
async def create_incident(
    body: CreateIncidentRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    incident = Incident(
        title=body.title,
        severity=IncidentSeverity(body.severity),
        exam_id=body.exam_id,
        description=body.description,
        affected_resource=body.affected_resource,
        created_by=current_user.id,
        actions_taken=[],
    )
    db.add(incident)
    await db.flush()
    return {"id": incident.id, "status": incident.status.value}


@router.get("/")
async def list_incidents(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Incident).order_by(Incident.created_at.desc()))
    incidents = result.scalars().all()
    return [
        {
            "id": i.id,
            "title": i.title,
            "severity": i.severity.value,
            "status": i.status.value,
            "exam_id": i.exam_id,
            "affected_resource": i.affected_resource,
            "created_at": i.created_at.isoformat(),
            "resolved_at": i.resolved_at.isoformat() if i.resolved_at else None,
        }
        for i in incidents
    ]


@router.post("/{incident_id}/action", dependencies=[Depends(require_role("SECURITY_OFFICER", "SUPER_ADMIN"))])
async def execute_incident_action(
    incident_id: str,
    body: IncidentActionRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Execute incident response actions.
    Available actions: LOCK_USER, REVOKE_SESSION, REVOKE_FORM, RESOLVE
    """
    incident_result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = incident_result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    result_msg = ""

    if body.action == "LOCK_USER":
        from app.core.models import User as UserModel
        user_result = await db.execute(select(UserModel).where(UserModel.id == body.target_id))
        target_user = user_result.scalar_one_or_none()
        if target_user:
            target_user.is_locked = True
            result_msg = f"User {target_user.username} locked"

    elif body.action == "REVOKE_SESSION":
        sess_result = await db.execute(
            select(CandidateSession).where(CandidateSession.id == body.target_id)
        )
        session = sess_result.scalar_one_or_none()
        if session:
            session.status = SessionStatus.REVOKED
            result_msg = f"Session {body.target_id[:8]} revoked"

    elif body.action == "RESOLVE":
        incident.status = IncidentStatus.RESOLVED
        incident.resolved_at = datetime.now(timezone.utc)
        incident.resolution = body.reason
        result_msg = "Incident resolved"

    # Record action taken
    if incident.actions_taken is None:
        incident.actions_taken = []
    incident.actions_taken = incident.actions_taken + [{
        "action": body.action,
        "target_id": body.target_id,
        "reason": body.reason,
        "executed_by": current_user.id,
        "executed_at": datetime.now(timezone.utc).isoformat(),
        "result": result_msg,
    }]

    return {"success": True, "message": result_msg, "action": body.action}
