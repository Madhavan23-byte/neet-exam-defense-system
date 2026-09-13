"""
B-SEA — Centralized Purpose-to-Operation Authorization Policy
Phase 3A: Dynamic & Ephemeral Question Access Control

Defines the exact intersectional policy mapping:
- Purpose allows Operation
- Role permits Operation
- User has necessary explicit permission
"""
from __future__ import annotations

from typing import Set, Tuple, Optional
from app.core.models import ReviewPurpose, QuestionOperation, UserRoleEnum, User
from app.modules.auth.service import has_permission


# Central Purpose -> Permitted Operations Matrix
PURPOSE_OPERATION_MATRIX: dict[ReviewPurpose, Set[QuestionOperation]] = {
    ReviewPurpose.TECHNICAL_REVIEW: {QuestionOperation.VIEW, QuestionOperation.REVIEW},
    ReviewPurpose.SYLLABUS_REVIEW: {QuestionOperation.VIEW, QuestionOperation.REVIEW},
    ReviewPurpose.LANGUAGE_REVIEW: {QuestionOperation.VIEW, QuestionOperation.REVIEW},
    ReviewPurpose.DISTRACTOR_REVIEW: {QuestionOperation.VIEW, QuestionOperation.REVIEW},
    ReviewPurpose.KEY_VERIFICATION: {
        QuestionOperation.VIEW,
        QuestionOperation.REVIEW,
        QuestionOperation.APPROVE,
        QuestionOperation.REJECT,
    },
}


def validate_operation_entitlement(
    purpose: ReviewPurpose,
    operation: QuestionOperation,
    actor: User,
) -> Tuple[bool, str]:
    """
    Validate that an operation is permitted under the strict intersection:
    Purpose Policy AND Role Policy AND Explicit Permission.

    The purpose matrix NEVER overrides role or permission constraints.
    Returns: (is_permitted, error_message)
    """
    # 1. Purpose Policy Check
    allowed_ops = PURPOSE_OPERATION_MATRIX.get(purpose, set())
    if operation not in allowed_ops:
        return (
            False,
            f"Operation {operation.value} is not permitted for review purpose {purpose.value}",
        )

    # 2. Intersectional Role & Permission Checks for Sensitive Operations
    if operation == QuestionOperation.APPROVE:
        if actor.role != UserRoleEnum.MODERATOR:
            return (
                False,
                f"Role {actor.role.value} is not authorized to approve questions; requires MODERATOR",
            )
        if not has_permission(actor.role.value, "questions:approve"):
            return False, "User lacks explicit 'questions:approve' permission"

    elif operation == QuestionOperation.REJECT:
        if actor.role != UserRoleEnum.MODERATOR:
            return (
                False,
                f"Role {actor.role.value} is not authorized to reject questions; requires MODERATOR",
            )
        if not has_permission(actor.role.value, "questions:reject"):
            return False, "User lacks explicit 'questions:reject' permission"

    elif operation in [QuestionOperation.VIEW, QuestionOperation.REVIEW]:
        if actor.role not in [UserRoleEnum.REVIEWER, UserRoleEnum.MODERATOR]:
            return (
                False,
                f"Role {actor.role.value} is not authorized for {operation.value} in reviewer workflow",
            )

    return True, ""
