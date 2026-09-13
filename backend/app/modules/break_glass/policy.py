"""
B-SEA — Phase 3B Break-Glass Policy Engine
Defines configurable policy constraints for emergency complete-paper access.
"""
from __future__ import annotations

from pydantic import BaseModel, Field
from app.core.models import UserRoleEnum, BreakGlassScope


class BreakGlassPolicy(BaseModel):
    """
    Configurable parameters governing break-glass requests and multi-party quorum.
    Durations, quorums, and authority classes are NOT hardcoded constants.
    """
    default_duration_minutes: int = Field(default=30, ge=1)
    minimum_duration_minutes: int = Field(default=10, ge=1)
    maximum_duration_minutes: int = Field(default=60, ge=1)
    required_quorum: int = Field(default=2, ge=2)
    min_distinct_authority_classes: int = Field(default=2, ge=1)
    eligible_requester_roles: list[UserRoleEnum] = Field(
        default=[
            UserRoleEnum.SUPER_ADMIN,
            UserRoleEnum.EXAM_AUTHORITY,
            UserRoleEnum.SECURITY_OFFICER,
        ]
    )
    eligible_approver_roles: list[UserRoleEnum] = Field(
        default=[
            UserRoleEnum.EXAM_AUTHORITY,
            UserRoleEnum.SECURITY_OFFICER,
            UserRoleEnum.SUPER_ADMIN,
            UserRoleEnum.RELEASE_AUTHORITY,
        ]
    )
    allowed_scopes: list[BreakGlassScope] = Field(
        default=[
            BreakGlassScope.COMPLETE_EXAM_PAPER,
            BreakGlassScope.EXAM_FORM_PREVIEW,
            BreakGlassScope.AUDIT_VERIFICATION,
        ]
    )
    policy_version: str = "1.0"


_default_policy = BreakGlassPolicy()


def get_break_glass_policy() -> BreakGlassPolicy:
    """Return the active BreakGlassPolicy configuration."""
    return _default_policy
