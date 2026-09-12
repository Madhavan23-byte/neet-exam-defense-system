"""B-SEA — Users API"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, EmailStr
from typing import Optional

from app.core.database import get_db
from app.core.dependencies import get_current_user, require_role
from app.core.models import Organization, User, UserRoleEnum
from app.core.security import hash_password

router = APIRouter()


class CreateUserRequest(BaseModel):
    username: str
    email: str
    full_name: str
    role: str
    password: str
    org_id: Optional[str] = None


@router.get("/")
async def list_users(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(User).where(User.org_id == current_user.org_id)
    )
    users = result.scalars().all()
    return [
        {
            "id": u.id,
            "username": u.username,
            "full_name": u.full_name,
            "email": u.email,
            "role": u.role.value,
            "is_active": u.is_active,
            "is_locked": u.is_locked,
            "mfa_enabled": u.mfa_enabled,
            "last_login": u.last_login.isoformat() if u.last_login else None,
        }
        for u in users
    ]


@router.post("/", dependencies=[Depends(require_role("SUPER_ADMIN", "EXAM_AUTHORITY"))])
async def create_user(
    body: CreateUserRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # Check username uniqueness
    existing = await db.execute(select(User).where(User.username == body.username))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username already exists")

    user = User(
        org_id=body.org_id or current_user.org_id,
        email=body.email,
        username=body.username,
        full_name=body.full_name,
        role=UserRoleEnum(body.role),
        password_hash=await hash_password(body.password),
    )
    db.add(user)
    await db.flush()

    return {
        "id": user.id,
        "username": user.username,
        "role": user.role.value,
        "message": "User created successfully",
    }


@router.post("/{user_id}/lock", dependencies=[Depends(require_role("SUPER_ADMIN", "SECURITY_OFFICER"))])
async def lock_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_locked = True
    return {"success": True, "message": f"User {user.username} locked"}


@router.post("/{user_id}/unlock", dependencies=[Depends(require_role("SUPER_ADMIN"))])
async def unlock_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_locked = False
    user.failed_login_attempts = 0
    return {"success": True, "message": f"User {user.username} unlocked"}
