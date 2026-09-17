"""
B-SEA Phase 3C-5D: Security Incident Management Foundation Module
Re-exports all authoritative incident models, enums, exceptions, and services.
"""
from app.modules.incidents.models import (
    SecurityIncidentStatus,
    SecurityIncidentSeverity,
    CorrelationStatus,
    SealVerificationStatus,
    EvidenceType,
    SecurityIncident,
    IncidentEvidenceLink,
    IncidentComment,
)
from app.modules.incidents.exceptions import (
    IncidentManagementError,
    IncidentNotFoundError,
    InvalidStateTransitionError,
    OptimisticLockError,
    AdvisoryLockContentionError,
    CorrelationWindowExpiredError,
    InvalidDimensionError,
    TemporalIdentityError,
    InvalidEvidenceError,
    InvalidCommentError,
    UnauthorizedActionError,
)
from app.modules.incidents.identity import (
    generate_threat_vector_key,
    normalize_canonical_rule_id,
    normalize_dimensions,
    normalize_exam_id,
    normalize_policy_version,
    derive_advisory_lock_key,
)
from app.modules.incidents.service import SecurityIncidentService

__all__ = [
    "SecurityIncidentStatus",
    "SecurityIncidentSeverity",
    "CorrelationStatus",
    "SealVerificationStatus",
    "EvidenceType",
    "SecurityIncident",
    "IncidentEvidenceLink",
    "IncidentComment",
    "IncidentManagementError",
    "IncidentNotFoundError",
    "InvalidStateTransitionError",
    "OptimisticLockError",
    "AdvisoryLockContentionError",
    "CorrelationWindowExpiredError",
    "InvalidDimensionError",
    "TemporalIdentityError",
    "InvalidEvidenceError",
    "InvalidCommentError",
    "UnauthorizedActionError",
    "generate_threat_vector_key",
    "normalize_canonical_rule_id",
    "normalize_dimensions",
    "normalize_exam_id",
    "normalize_policy_version",
    "derive_advisory_lock_key",
    "SecurityIncidentService",
]
