"""B-SEA — Release API"""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from app.core.database import get_db
from app.core.dependencies import get_client_ip, get_current_user, require_role
from app.core.models import User
from app.modules.release.service import ReleaseService

router = APIRouter()


class FreezeRequest(BaseModel):
    reason: str


@router.get("/{exam_id}/status")
async def get_release_status(
    exam_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get comprehensive release status for an exam."""
    service = ReleaseService(db)
    return await service.get_release_status(exam_id)


@router.post("/{exam_id}/approve")
async def submit_approval(
    exam_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Submit threshold authorization approval for exam release."""
    service = ReleaseService(db)
    ip = get_client_ip(request)
    try:
        return await service.submit_threshold_approval(exam_id, current_user, ip)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except IntegrityError:
        # DB-level UniqueConstraint on (exam_id, authority_id) fired.
        # This is the database's final enforcement of the duplicate-approval invariant.
        # Return 409 Conflict — not 500 — so the API layer handles DB enforcement cleanly.
        await db.rollback()
        raise HTTPException(status_code=409, detail="Duplicate approval: you have already approved this exam")


@router.post("/{exam_id}/check")
async def check_release(
    exam_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Evaluate all release conditions and trigger release if met."""
    service = ReleaseService(db)
    return await service.check_and_trigger_release(exam_id)


@router.post("/{exam_id}/freeze", dependencies=[Depends(require_role("SECURITY_OFFICER", "SUPER_ADMIN"))])
async def freeze_release(
    exam_id: str,
    body: FreezeRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Emergency freeze of exam release (SECURITY_OFFICER only)."""
    service = ReleaseService(db)
    return await service.freeze_release(exam_id, current_user, body.reason)
