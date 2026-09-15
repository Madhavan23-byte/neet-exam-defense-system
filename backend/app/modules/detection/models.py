"""
B-SEA Phase 3C-5C Detection & Correlation Foundation — Core Data Models
Conforming to BSEA_PHASE3C_5C_DETECTION_CORRELATION_ARCHITECTURE_REVIEW_REV03.md
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


class IdentityCorrelationStrength(str, Enum):
    """Rule-A identity linkage confidence levels."""
    ACTOR_MATCH = "ACTOR_MATCH"                     # Strong: matching non-null actor_id
    IP_MATCH_ONLY = "IP_MATCH_ONLY"                 # Weaker: actor_id missing, matching ip_hash only
    INSUFFICIENT_IDENTITY = "INSUFFICIENT_IDENTITY" # Neither provides sufficient linkage


class AuditEvidenceState(str, Enum):
    """Rule-F 5-state audit evidence lifecycle."""
    EXPECTED = "EXPECTED"                   # Session active; post-activation audit events expected
    RECEIVED = "RECEIVED"                   # Verified audit log referencing session arrived cleanly
    DELAYED = "DELAYED"                     # Elapsed time <= 60s (within normal transport window)
    UNRESOLVED = "UNRESOLVED"               # Elapsed time > 60s and <= 300s (awaiting worker retry)
    CONFIRMED_MISSING = "CONFIRMED_MISSING" # Elapsed time > 300s or explicit insertion failure logged


class ScopeEvaluationState(str, Enum):
    """Rule-E Break-Glass scope authorization comparison states."""
    MATCH = "MATCH"               # Access occurred within approved window, exam, and action
    OUT_OF_SCOPE = "OUT_OF_SCOPE" # Access outside authorized temporal window, exam, or action
    UNRESOLVED = "UNRESOLVED"     # Resource hierarchy or scope metadata cannot be determined


class CloudTrailReconciliationState(str, Enum):
    """Four explicit states for AWS CloudTrail KMS API management events reconciliation."""
    CORRELATED = "CORRELATED"                     # Perfectly matches RequestId, key, timestamp, op
    UNRESOLVED = "UNRESOLVED"                     # Event age < 15 mins; within normal CloudTrail delay
    MISSING_EVIDENCE = "MISSING_EVIDENCE"         # Event age >= 15 mins without CloudTrail record
    CONFLICTING_EVIDENCE = "CONFLICTING_EVIDENCE" # RequestId matches but IAM caller/status conflicts


class RuleEvaluationResult(str, Enum):
    """Result of an individual detection rule evaluation."""
    MATCH = "match"
    NO_MATCH = "no_match"
    ERROR = "error"


class DetectionSeverity(str, Enum):
    """Permitted detection severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DetectionMode(str, Enum):
    """Detection operational mode."""
    SHADOW = "shadow"
    ACTIVE = "active"


@dataclass(frozen=True)
class SecurityEventNormalized:
    """
    Authoritative normalized internal security event representation.
    Strictly immutable, memory-efficient, and sanitized of exam content.
    """
    event_id: str
    event_type: str
    timestamp: datetime
    source_subsystem: str
    result: str  # SUCCESS, FAILURE, DENIED, BLOCKED, ERROR
    actor_id: Optional[str] = None
    actor_role: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    action: Optional[str] = None
    session_id: Optional[str] = None
    device_id: Optional[str] = None
    ip_hash: Optional[str] = None
    trace_id: Optional[str] = None
    request_id: Optional[str] = None
    audit_log_id: Optional[str] = None
    kms_request_id: Optional[str] = None
    policy_version: str = "BSEA-DETECTION-v1"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "source_subsystem": self.source_subsystem,
            "result": self.result,
            "actor_id": self.actor_id,
            "actor_role": self.actor_role,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "action": self.action,
            "session_id": self.session_id,
            "device_id": self.device_id,
            "ip_hash": self.ip_hash,
            "trace_id": self.trace_id,
            "request_id": self.request_id,
            "audit_log_id": self.audit_log_id,
            "kms_request_id": self.kms_request_id,
            "policy_version": self.policy_version,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class DetectionRuleDefinition:
    """
    Deterministic specification for an individual detection rule.
    """
    rule_id: str                          # e.g., "RULE-A"
    rule_version: str                      # e.g., "1.0.0"
    title: str                            # Human-readable title
    description: str                      # Detailed detection rationale
    severity: str                         # LOW, MEDIUM, HIGH, CRITICAL
    enabled: bool = True                  # Active toggle
    mode: str = "shadow"                  # "shadow" (mandatory in Phase 3C-5C)
    time_window_seconds: int = 300        # Window duration
    primary_dimension: str = "actor_id"   # actor_id, session_id, device_id, etc.
    threshold: int = 5                    # Event count threshold
    event_conditions: Dict[str, Any] = field(default_factory=dict)
    evidence_requirements: List[str] = field(default_factory=list)
    policy_version: str = "BSEA-RULES-v1"


@dataclass(frozen=True)
class SecuritySignal:
    """
    Authoritative representation of an advisory security detection signal.
    Strictly advisory in Phase 3C-5C; does not trigger autonomous containment.
    """
    signal_id: str
    rule_id: str
    rule_version: str
    detected_at: datetime
    severity: str
    confidence: float
    mode: str = "shadow"
    correlation_keys: Dict[str, str] = field(default_factory=dict)
    evidence_references: List[str] = field(default_factory=list)
    event_count: int = 0
    window_seconds: int = 300
    policy_version: str = "BSEA-RULES-v1"
    explanation: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "detected_at": self.detected_at.isoformat(),
            "severity": self.severity,
            "confidence": self.confidence,
            "mode": self.mode,
            "correlation_keys": self.correlation_keys,
            "evidence_references": self.evidence_references,
            "event_count": self.event_count,
            "window_seconds": self.window_seconds,
            "policy_version": self.policy_version,
            "explanation": self.explanation,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    def compute_idempotency_hash(self) -> str:
        """Deterministic signal deduplication hash per window bucket."""
        ts_bucket = int(self.detected_at.timestamp() // max(self.window_seconds, 1))
        primary_val = sorted(self.correlation_keys.items())[0][1] if self.correlation_keys else "none"
        raw = f"{self.rule_id}:{primary_val}:{ts_bucket}:{self.rule_version}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CloudTrailKMSEvent:
    """
    Normalized representation of an AWS CloudTrail KMS API management event.
    """
    event_id: str
    event_time: datetime
    event_name: str                      # e.g., "Sign", "GenerateDataKey", "Decrypt"
    kms_key_arn: str
    request_id: str
    caller_arn: str
    event_source: str = "kms.amazonaws.com"
    error_code: Optional[str] = None
    status: str = "SUCCESS"
    raw_payload: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BreakGlassScopeReference:
    """
    Reference metadata for an active Break-Glass request used in Rule-E evaluation.
    """
    request_id: str
    scope: str
    exam_id: str
    valid_from: datetime
    valid_until: datetime
    blueprint_id: Optional[str] = None
    exam_version: Optional[int] = None
    target_centre_id: Optional[str] = None
    authorized_actions: List[str] = field(default_factory=list)
