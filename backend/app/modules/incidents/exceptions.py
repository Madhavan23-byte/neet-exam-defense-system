"""
B-SEA Phase 3C-5D: Security Incident Management Exceptions
Conforming to BSEA_PHASE3C_5D_SECURITY_INCIDENT_MANAGEMENT_ARCHITECTURE_REVIEW_REV06.md.
"""
from __future__ import annotations


class IncidentManagementError(Exception):
    """Base exception for all security incident management operations."""
    pass


class IncidentNotFoundError(IncidentManagementError):
    """Raised when an incident case cannot be found."""
    pass


class InvalidStateTransitionError(IncidentManagementError):
    """Raised when an incident lifecycle state transition violates the state machine matrix."""
    pass


class OptimisticLockError(IncidentManagementError):
    """Raised when an OCC version check fails during atomic update."""
    pass


class AdvisoryLockContentionError(IncidentManagementError):
    """Raised when an advisory lock cannot be acquired or experiences deadlocks."""
    pass


class CorrelationWindowExpiredError(IncidentManagementError):
    """Raised when attempting to attach to an expired correlation window without rollover."""
    pass


class InvalidDimensionError(IncidentManagementError):
    """Raised when dimension dictionary is empty, malformed, or invalid."""
    pass


class TemporalIdentityError(IncidentManagementError):
    """Raised when a temporal field is supplied to threat vector identity generation."""
    pass


class InvalidEvidenceError(IncidentManagementError):
    """Raised when evidence verification fails or evidence reference is invalid."""
    pass


class InvalidCommentError(IncidentManagementError):
    """Raised when comment validation fails (length, XSS, or secret screening)."""
    pass


class UnauthorizedActionError(IncidentManagementError):
    """Raised when user role lacks required authority for an incident action."""
    pass
