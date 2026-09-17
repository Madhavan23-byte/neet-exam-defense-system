"""
B-SEA Phase 3C-5E: Policy-Governed Security Containment Models
Conforming strictly to docs/BSEA_PHASE3C5E_ARCHITECTURE_REV04_1.md.

Implements the decoupled 7-tier containment domain architecture:
1. ContainmentIntent: Abstract containment goal (IntentKey independent of RequesterID).
2. ContainmentRequest: Specific submission instance by an operator.
3. ContainmentAuthorization: Cryptographic multi-party authorization signature.
4. BreakGlassToken: Ephemeral single-use emergency override token.
5. ContainmentExecutionRecord: Dispatched execution attempt with ExternalOperationID.
6. ContainmentVerificationProof: Out-of-band independent verification proof object.
7. ContainmentConsumedNonce: Strict replay protection for all cryptographic nonces.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from sqlalchemy import (
    String,
    Integer,
    Float,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    UniqueConstraint,
    CheckConstraint,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    return str(uuid.uuid4())


# ─── ENUMS ───────────────────────────────────────────────────────────────────

class ContainmentIntentStatus(str, enum.Enum):
    """Lifecycle states of the abstract Containment Intent (Rev-04.1 Section 12)."""
    REGISTERED = "REGISTERED"
    IN_PROGRESS = "IN_PROGRESS"
    CONTAINED = "CONTAINED"
    EXPIRED = "EXPIRED"
    FAILED = "FAILED"


class ContainmentRequestStatus(str, enum.Enum):
    """Lifecycle states of an operational Containment Request (Rev-04.1 Section 12)."""
    REQUESTED = "REQUESTED"
    POLICY_EVALUATED = "POLICY_EVALUATED"
    AWAITING_AUTHORIZATION = "AWAITING_AUTHORIZATION"
    AUTHORIZED = "AUTHORIZED"
    EXECUTING = "EXECUTING"
    EXECUTED = "EXECUTED"
    VERIFYING_PENDING = "VERIFYING_PENDING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"
    QUARANTINED = "QUARANTINED"


class ContainmentActionRisk(str, enum.Enum):
    """Containment Action Risk Tiers (Rev-04.1 Section 2 & 3)."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ContainmentActionType(str, enum.Enum):
    """Normative Containment Action Taxonomy (Rev-04.1 Section 4)."""
    ACT_CAND_SESSION_TERM = "ACT_CAND_SESSION_TERM"
    ACT_ACCT_DISABLE = "ACT_ACCT_DISABLE"
    ACT_Q_PREVENT_ASSIGN = "ACT_Q_PREVENT_ASSIGN"
    ACT_CENTRE_RESTRICT = "ACT_CENTRE_RESTRICT"
    ACT_FORM_SUSPEND = "ACT_FORM_SUSPEND"
    ACT_CENTRE_SUSPEND = "ACT_CENTRE_SUSPEND"
    ACT_CRYPTO_REVOKE_MASTER = "ACT_CRYPTO_REVOKE_MASTER"


class ExecutionOutcome(str, enum.Enum):
    """Tri-state raw execution outcomes (Rev-04.1 Section 7)."""
    EXECUTION_SUCCEEDED = "EXECUTION_SUCCEEDED"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    EXECUTION_UNKNOWN = "EXECUTION_UNKNOWN"


class VerificationOutcome(str, enum.Enum):
    """Tri-state independent verification outcomes (Rev-04.1 Section 7)."""
    VERIFICATION_VERIFIED = "VERIFICATION_VERIFIED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    VERIFICATION_INCONCLUSIVE = "VERIFICATION_INCONCLUSIVE"


class BreakGlassTokenStatus(str, enum.Enum):
    """Break-Glass Token Lifecycle (Rev-04.1 Section 8 & 12)."""
    ISSUED = "ISSUED"
    CONSUMED = "CONSUMED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    UNDER_REVIEW = "UNDER_REVIEW"
    RATIFIED = "RATIFIED"
    BREACH_DECLARED = "BREACH_DECLARED"


# ─── MODELS ──────────────────────────────────────────────────────────────────

class ContainmentIntent(Base):
    """
    Tier 1: Logical Containment Intent.
    Identified strictly by IntentKey = SHA-256(incident_id || generation || action_type || target_urn).
    Independent of RequesterID to ensure idempotent convergence.
    """
    __tablename__ = "containment_intents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    intent_key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("security_incidents.id", ondelete="RESTRICT", name="fk_containment_intents_incident_id"),
        nullable=False,
        index=True,
    )
    incident_generation: Mapped[int] = mapped_column(Integer, nullable=False)
    action_type: Mapped[ContainmentActionType] = mapped_column(Enum(ContainmentActionType), nullable=False)
    canonical_target_urn: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    risk_tier: Mapped[ContainmentActionRisk] = mapped_column(Enum(ContainmentActionRisk), nullable=False)
    status: Mapped[ContainmentIntentStatus] = mapped_column(
        Enum(ContainmentIntentStatus), nullable=False, default=ContainmentIntentStatus.REGISTERED
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, server_default=func.now(), onupdate=utcnow, nullable=False)

    requests: Mapped[List["ContainmentRequest"]] = relationship("ContainmentRequest", back_populates="intent", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_intents_incident_gen", "incident_id", "incident_generation"),
        Index("ix_intents_status", "status"),
    )


class ContainmentRequest(Base):
    """
    Tier 2: Operational Containment Request submitted by a specific principal.
    Bound to an IntentKey, target snapshot hash, and policy version.
    """
    __tablename__ = "containment_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    request_key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    intent_key: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("containment_intents.intent_key", ondelete="RESTRICT", name="fk_containment_requests_intent_key"),
        nullable=False,
        index=True,
    )
    requester_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="RESTRICT", name="fk_containment_requests_requester_id"),
        nullable=False,
    )
    target_snapshot_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    scope_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    max_allowed_entities: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_decision: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    status: Mapped[ContainmentRequestStatus] = mapped_column(
        Enum(ContainmentRequestStatus), nullable=False, default=ContainmentRequestStatus.REQUESTED
    )
    execution_lease_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, server_default=func.now(), onupdate=utcnow, nullable=False)

    intent: Mapped["ContainmentIntent"] = relationship("ContainmentIntent", back_populates="requests")
    authorizations: Mapped[List["ContainmentAuthorization"]] = relationship("ContainmentAuthorization", back_populates="request", cascade="all, delete-orphan")
    execution_records: Mapped[List["ContainmentExecutionRecord"]] = relationship("ContainmentExecutionRecord", back_populates="request", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_requests_status", "status"),
        Index("ix_requests_requester", "requester_id"),
    )


class ContainmentAuthorization(Base):
    """
    Tier 3: Multi-Party Authorization Signature.
    Enforces Two-Person Control and records single-use authorization nonces.
    """
    __tablename__ = "containment_authorizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    request_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("containment_requests.id", ondelete="RESTRICT", name="fk_containment_auth_request_id"),
        nullable=False,
        index=True,
    )
    approver_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="RESTRICT", name="fk_containment_auth_approver_id"),
        nullable=False,
    )
    auth_nonce: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    signature: Mapped[str] = mapped_column(String(512), nullable=False)
    is_break_glass: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    break_glass_token_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, server_default=func.now(), nullable=False)

    request: Mapped["ContainmentRequest"] = relationship("ContainmentRequest", back_populates="authorizations")

    __table_args__ = (
        Index("ix_authorizations_request_id", "request_id"),
    )


class BreakGlassToken(Base):
    """
    Ephemeral Single-Use Break-Glass Emergency Override Token.
    Strictly bounded by 15-minute TTL, single-entity scope, and permanent consumption.
    """
    __tablename__ = "break_glass_tokens"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # bgt_<uuidv4>
    token_nonce: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    intent_key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    incident_id: Mapped[str] = mapped_column(String(36), nullable=False)
    incident_generation: Mapped[int] = mapped_column(Integer, nullable=False)
    canonical_target_urn: Mapped[str] = mapped_column(String(256), nullable=False)
    target_scope_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    action_type: Mapped[ContainmentActionType] = mapped_column(Enum(ContainmentActionType), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    issuer_id: Mapped[str] = mapped_column(String(36), nullable=False)
    fido2_assertion_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[BreakGlassTokenStatus] = mapped_column(
        Enum(BreakGlassTokenStatus), nullable=False, default=BreakGlassTokenStatus.ISSUED
    )
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, server_default=func.now(), nullable=False)

    __table_args__ = (
        Index("ix_bg_tokens_intent", "intent_key"),
        Index("ix_bg_tokens_status", "status"),
    )


class ContainmentExecutionRecord(Base):
    """
    Tier 4: Physical Execution Run Instance.
    Tracks ExternalOperationID, adapter latency, raw outcome, and verification reference.
    """
    __tablename__ = "containment_execution_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)  # ExecutionRunId
    request_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("containment_requests.id", ondelete="RESTRICT", name="fk_containment_exec_request_id"),
        nullable=False,
        index=True,
    )
    external_operation_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    adapter_name: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_outcome: Mapped[ExecutionOutcome] = mapped_column(Enum(ExecutionOutcome), nullable=False)
    latency_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    error_code: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, server_default=func.now(), nullable=False)

    request: Mapped["ContainmentRequest"] = relationship("ContainmentRequest", back_populates="execution_records")
    verification_proof: Mapped[Optional["ContainmentVerificationProof"]] = relationship("ContainmentVerificationProof", back_populates="execution_record", uselist=False)


class ContainmentVerificationProof(Base):
    """
    Independent Verification Proof Object.
    Generated strictly out-of-band by an independent verifier inspecting physical target ground truth.
    """
    __tablename__ = "containment_verification_proofs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    execution_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("containment_execution_records.id", ondelete="RESTRICT", name="fk_containment_verif_exec_id"),
        nullable=False,
        unique=True,
        index=True,
    )
    verifier_name: Mapped[str] = mapped_column(String(64), nullable=False)
    verification_outcome: Mapped[VerificationOutcome] = mapped_column(Enum(VerificationOutcome), nullable=False)
    observed_target_state: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    proof_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    proof_payload: Mapped[Dict[str, Any]] = mapped_column(JSONB().with_variant(Text, "sqlite"), nullable=False)
    manual_attestation_officer_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    manual_attestation_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, server_default=func.now(), nullable=False)

    execution_record: Mapped["ContainmentExecutionRecord"] = relationship("ContainmentExecutionRecord", back_populates="verification_proof")


class ContainmentConsumedNonce(Base):
    """
    Append-only repository of consumed cryptographic nonces to strictly enforce replay protection.
    """
    __tablename__ = "containment_consumed_nonces"

    nonce: Mapped[str] = mapped_column(String(64), primary_key=True)
    nonce_type: Mapped[str] = mapped_column(String(32), nullable=False)  # 'AUTH' or 'BREAK_GLASS'
    consumed_by: Mapped[str] = mapped_column(String(36), nullable=False)
    consumed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, server_default=func.now(), nullable=False)
