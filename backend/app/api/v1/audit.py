"""B-SEA — Audit API"""
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import get_current_user, require_role
from app.core.models import AuditLog, User, UserRoleEnum
from app.modules.audit.service import AuditService

router = APIRouter()


@router.get("/logs", dependencies=[Depends(require_role(UserRoleEnum.SUPER_ADMIN, UserRoleEnum.SECURITY_OFFICER, UserRoleEnum.AUDITOR))])
async def get_audit_logs(
    limit: int = 100,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get audit logs (AUDITOR/SECURITY_OFFICER only)."""
    result = await db.execute(
        select(AuditLog).order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).limit(limit)
    )
    logs = result.scalars().all()
    return [
        {
            "id": l.id,
            "seq": l.seq,
            "event_type": l.event_type,
            "actor_id": l.actor_id,
            "actor_role": l.actor_role,
            "resource_type": l.resource_type,
            "resource_id": l.resource_id,
            "action": l.action,
            "result": l.result.value,
            "risk_score": l.risk_score,
            "metadata": l.event_metadata or {},
            "timestamp": l.timestamp.isoformat(),
            "event_hash": l.event_hash[:16] + "...",  # Partial hash for display
        }
        for l in logs
    ]


@router.get("/verify", dependencies=[Depends(require_role(UserRoleEnum.SUPER_ADMIN, UserRoleEnum.SECURITY_OFFICER, UserRoleEnum.AUDITOR))])
async def verify_audit_chain(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Verify the integrity of the entire audit log hash chain.
    Detects any tampering with historical audit records.
    """
    service = AuditService(db)
    result = await service.verify_chain()
    return result
