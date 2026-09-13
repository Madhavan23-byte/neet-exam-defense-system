"""
B-SEA Database Models
Complete SQLAlchemy ORM models for all B-SEA entities.
All UUIDs, all timestamped, all indexed on security-critical fields.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum
from typing import List, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Enum,
    text,
)
from sqlalchemy import JSON as JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.core.database import Base


def utcnow():
    return datetime.now(timezone.utc)


def new_uuid():
    return str(uuid.uuid4())


# ── Enums ─────────────────────────────────────────────────────────────────────

class UserRoleEnum(str, PyEnum):
    SUPER_ADMIN = "SUPER_ADMIN"
    EXAM_AUTHORITY = "EXAM_AUTHORITY"
    QUESTION_SETTER = "QUESTION_SETTER"
    REVIEWER = "REVIEWER"
    MODERATOR = "MODERATOR"
    SECURITY_OFFICER = "SECURITY_OFFICER"
    RELEASE_AUTHORITY = "RELEASE_AUTHORITY"
    CENTRE_ADMIN = "CENTRE_ADMIN"
    INVIGILATOR = "INVIGILATOR"
    CANDIDATE = "CANDIDATE"
    AUDITOR = "AUDITOR"


class QuestionStatus(str, PyEnum):
    DRAFT = "DRAFT"
    SUBMITTED = "SUBMITTED"
    UNDER_REVIEW = "UNDER_REVIEW"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    ENCRYPTED = "ENCRYPTED"
    READY = "READY"
    ASSIGNED = "ASSIGNED"
    RELEASED = "RELEASED"
    ARCHIVED = "ARCHIVED"
    QUARANTINED = "QUARANTINED"


class QuestionAssignmentStatus(str, PyEnum):
    ACTIVE = "ACTIVE"
    IN_REVIEW = "IN_REVIEW"
    COMPLETED = "COMPLETED"
    REVOKED = "REVOKED"


class ReviewPurpose(str, PyEnum):
    TECHNICAL_REVIEW = "TECHNICAL_REVIEW"
    SYLLABUS_REVIEW = "SYLLABUS_REVIEW"
    LANGUAGE_REVIEW = "LANGUAGE_REVIEW"
    DISTRACTOR_REVIEW = "DISTRACTOR_REVIEW"
    KEY_VERIFICATION = "KEY_VERIFICATION"


class QuestionOperation(str, PyEnum):
    VIEW = "VIEW"
    REVIEW = "REVIEW"
    APPROVE = "APPROVE"
    REJECT = "REJECT"


class AccessGrantStatus(str, PyEnum):
    GRANTED = "GRANTED"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class ExamStatus(str, PyEnum):
    DRAFT = "DRAFT"
    BLUEPRINT_CREATED = "BLUEPRINT_CREATED"
    FORMS_GENERATED = "FORMS_GENERATED"
    THRESHOLD_PENDING = "THRESHOLD_PENDING"
    THRESHOLD_APPROVED = "THRESHOLD_APPROVED"
    RELEASED = "RELEASED"
    ONGOING = "ONGOING"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"
    FROZEN = "FROZEN"


class SecurityMode(str, PyEnum):
    STANDARD = "STANDARD"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FormStatus(str, PyEnum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    BACKUP = "BACKUP"


class SessionStatus(str, PyEnum):
    ACTIVE = "ACTIVE"
    SUBMITTED = "SUBMITTED"
    EXPIRED = "EXPIRED"
    FLAGGED = "FLAGGED"
    REVOKED = "REVOKED"


class CentreStatus(str, PyEnum):
    PENDING = "PENDING"
    READY = "READY"
    ACTIVE = "ACTIVE"
    ISOLATED = "ISOLATED"
    OFFLINE = "OFFLINE"


class IncidentSeverity(str, PyEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentStatus(str, PyEnum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"


class AuditResult(str, PyEnum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    BLOCKED = "BLOCKED"
    WARNING = "WARNING"


# ── Organization ──────────────────────────────────────────────────────────────

class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    short_name: Mapped[str] = mapped_column(String(50), nullable=False, unique=True)
    org_type: Mapped[str] = mapped_column(String(100), nullable=False)
    country: Mapped[str] = mapped_column(String(100), nullable=False, default="Global")
    timezone: Mapped[str] = mapped_column(String(100), nullable=False, default="UTC")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    config: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    users: Mapped[List["User"]] = relationship("User", back_populates="organization")
    exams: Mapped[List["Exam"]] = relationship("Exam", back_populates="organization")


# ── User ──────────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    username: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRoleEnum] = mapped_column(Enum(UserRoleEnum), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_locked: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret_encrypted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_ip_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    organization: Mapped["Organization"] = relationship("Organization", back_populates="users")
    questions: Mapped[List["Question"]] = relationship("Question", back_populates="author", foreign_keys="Question.author_id")
    release_approvals: Mapped[List["ReleaseApproval"]] = relationship("ReleaseApproval", back_populates="authority")

    __table_args__ = (
        Index("ix_users_org_role", "org_id", "role"),
    )


# ── Exam ──────────────────────────────────────────────────────────────────────

class Exam(Base):
    __tablename__ = "exams"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    exam_type: Mapped[str] = mapped_column(String(100), nullable=False, default="CBT")
    security_mode: Mapped[SecurityMode] = mapped_column(Enum(SecurityMode), default=SecurityMode.HIGH)
    scheduled_start_utc: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    scheduled_end_utc: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_minutes: Mapped[int] = mapped_column(Integer, default=180)
    status: Mapped[ExamStatus] = mapped_column(Enum(ExamStatus), default=ExamStatus.DRAFT)
    required_approvals: Mapped[int] = mapped_column(Integer, default=3)
    min_centre_readiness_pct: Mapped[float] = mapped_column(Float, default=90.0)
    release_frozen: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    released_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    organization: Mapped["Organization"] = relationship("Organization", back_populates="exams")
    blueprint: Mapped[Optional["ExamBlueprint"]] = relationship("ExamBlueprint", back_populates="exam", uselist=False)
    questions: Mapped[List["Question"]] = relationship("Question", back_populates="exam")
    forms: Mapped[List["ExamForm"]] = relationship("ExamForm", back_populates="exam")
    release_approvals: Mapped[List["ReleaseApproval"]] = relationship("ReleaseApproval", back_populates="exam")
    centres: Mapped[List["Centre"]] = relationship("Centre", back_populates="exam")

    __table_args__ = (
        Index("ix_exams_org_status", "org_id", "status"),
        Index("ix_exams_scheduled", "scheduled_start_utc"),
    )


# ── Exam Blueprint ────────────────────────────────────────────────────────────

class ExamBlueprint(Base):
    __tablename__ = "exam_blueprints"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    exam_id: Mapped[str] = mapped_column(ForeignKey("exams.id"), nullable=False, unique=True)
    config: Mapped[dict] = mapped_column(JSONB, nullable=False)  # Blueprint config (stored unencrypted for prototype)
    integrity_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    digital_signature: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="DRAFT")
    approved_by: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id"), nullable=True)
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    exam: Mapped["Exam"] = relationship("Exam", back_populates="blueprint")


# ── Question ──────────────────────────────────────────────────────────────────

class Question(Base):
    __tablename__ = "questions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    exam_id: Mapped[str] = mapped_column(ForeignKey("exams.id"), nullable=False)
    author_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    subject: Mapped[str] = mapped_column(String(200), nullable=False)
    topic: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    difficulty: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    bloom_level: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    question_format: Mapped[str] = mapped_column(String(50), default="MCQ")
    marks_positive: Mapped[float] = mapped_column(Float, default=4.0)
    marks_negative: Mapped[float] = mapped_column(Float, default=1.0)
    status: Mapped[QuestionStatus] = mapped_column(Enum(QuestionStatus), default=QuestionStatus.DRAFT)
    version: Mapped[int] = mapped_column(Integer, default=1)

    # Encrypted content (stored in object store; metadata here)
    object_store_key: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    key_reference: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    content_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    digital_signature: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # For prototype: also store encrypted content in DB
    encrypted_content: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    encrypted_answer: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Plaintext only in DRAFT status — cleared on ENCRYPTED transition
    plaintext_content: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    rejection_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    approved_by: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id"), nullable=True)
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    exam: Mapped["Exam"] = relationship("Exam", back_populates="questions")
    author: Mapped["User"] = relationship("User", back_populates="questions", foreign_keys=[author_id])
    reviews: Mapped[List["QuestionReview"]] = relationship("QuestionReview", back_populates="question")
    assignments: Mapped[List["QuestionAssignment"]] = relationship("QuestionAssignment", back_populates="question", cascade="all, delete-orphan")
    access_grants: Mapped[List["QuestionAccessGrant"]] = relationship("QuestionAccessGrant", back_populates="question", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_questions_exam_status", "exam_id", "status"),
        Index("ix_questions_author", "author_id"),
        Index("ix_questions_subject_difficulty", "subject", "difficulty"),
    )


# ── Question Review ───────────────────────────────────────────────────────────

class QuestionReview(Base):
    __tablename__ = "question_reviews"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    question_id: Mapped[str] = mapped_column(ForeignKey("questions.id"), nullable=False)
    reviewer_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    verdict: Mapped[str] = mapped_column(String(50), nullable=False)  # APPROVED, REJECTED, NEEDS_REVISION
    comments: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    question: Mapped["Question"] = relationship("Question", back_populates="reviews")
    reviewer: Mapped["User"] = relationship("User")


# ── Question Assignment (Sharding) ───────────────────────────────────────────

class QuestionAssignment(Base):
    __tablename__ = "question_assignments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    question_id: Mapped[str] = mapped_column(ForeignKey("questions.id", ondelete="CASCADE"), nullable=False)
    reviewer_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    exam_id: Mapped[str] = mapped_column(ForeignKey("exams.id"), nullable=False)
    assigned_by: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    purpose: Mapped[ReviewPurpose] = mapped_column(Enum(ReviewPurpose), default=ReviewPurpose.TECHNICAL_REVIEW, nullable=False)
    status: Mapped[QuestionAssignmentStatus] = mapped_column(Enum(QuestionAssignmentStatus), default=QuestionAssignmentStatus.ACTIVE, nullable=False)
    assigned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    question: Mapped["Question"] = relationship("Question", back_populates="assignments")
    reviewer: Mapped["User"] = relationship("User", foreign_keys=[reviewer_id])
    assigner: Mapped["User"] = relationship("User", foreign_keys=[assigned_by])
    exam: Mapped["Exam"] = relationship("Exam")
    access_grants: Mapped[List["QuestionAccessGrant"]] = relationship("QuestionAccessGrant", back_populates="assignment", cascade="all, delete-orphan")

    __table_args__ = (
        Index(
            "uix_active_question_reviewer_assignment",
            "question_id",
            "reviewer_id",
            unique=True,
            postgresql_where=text("status IN ('ACTIVE', 'IN_REVIEW')"),
        ),
        Index("ix_qassign_reviewer_status", "reviewer_id", "status"),
        Index("ix_qassign_exam_status", "exam_id", "status"),
        Index("ix_qassign_question_status", "question_id", "status"),
    )


# ── Ephemeral Question Access Grant (Phase 3A) ────────────────────────────────

class QuestionAccessGrant(Base):
    __tablename__ = "question_access_grants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    question_id: Mapped[str] = mapped_column(ForeignKey("questions.id", ondelete="CASCADE"), nullable=False)
    exam_id: Mapped[str] = mapped_column(ForeignKey("exams.id"), nullable=False)
    reviewer_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    assignment_id: Mapped[str] = mapped_column(ForeignKey("question_assignments.id", ondelete="CASCADE"), nullable=False)
    purpose: Mapped[ReviewPurpose] = mapped_column(Enum(ReviewPurpose), nullable=False)
    operation: Mapped[QuestionOperation] = mapped_column(Enum(QuestionOperation), nullable=False)
    status: Mapped[AccessGrantStatus] = mapped_column(Enum(AccessGrantStatus), default=AccessGrantStatus.GRANTED, nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    activated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    session_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    correlation_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    question: Mapped["Question"] = relationship("Question", back_populates="access_grants")
    assignment: Mapped["QuestionAssignment"] = relationship("QuestionAssignment", back_populates="access_grants")
    reviewer: Mapped["User"] = relationship("User", foreign_keys=[reviewer_id])
    exam: Mapped["Exam"] = relationship("Exam")
    creator: Mapped["User"] = relationship("User", foreign_keys=[created_by])

    __table_args__ = (
        Index(
            "uix_active_grant_assignment_operation",
            "assignment_id",
            "operation",
            unique=True,
            postgresql_where=text("status IN ('GRANTED', 'ACTIVE')"),
        ),
        Index("ix_qgrant_reviewer_status", "reviewer_id", "status"),
        Index("ix_qgrant_assignment_status", "assignment_id", "status"),
        Index("ix_qgrant_question_op", "question_id", "operation"),
    )



# ── Exam Form ─────────────────────────────────────────────────────────────────

class ExamForm(Base):
    __tablename__ = "exam_forms"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    exam_id: Mapped[str] = mapped_column(ForeignKey("exams.id"), nullable=False)
    form_label: Mapped[str] = mapped_column(String(10), nullable=False)  # A, B, C, D
    question_ids: Mapped[list] = mapped_column(JSONB, nullable=False)  # Ordered list of question IDs
    option_orders: Mapped[dict] = mapped_column(JSONB, nullable=False)  # Per-question option randomization
    integrity_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[FormStatus] = mapped_column(Enum(FormStatus), default=FormStatus.ACTIVE)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    exam: Mapped["Exam"] = relationship("Exam", back_populates="forms")
    sessions: Mapped[List["CandidateSession"]] = relationship("CandidateSession", back_populates="form")

    __table_args__ = (
        UniqueConstraint("exam_id", "form_label", name="uq_exam_form_label"),
        Index("ix_form_exam_status", "exam_id", "status"),
    )


# ── Candidate ─────────────────────────────────────────────────────────────────

class Candidate(Base):
    __tablename__ = "candidates"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    user_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id"), nullable=True)
    registration_number: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    email_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    phone_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    identity_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    sessions: Mapped[List["CandidateSession"]] = relationship("CandidateSession", back_populates="candidate")

    __table_args__ = (
        Index("ix_candidate_org", "org_id"),
    )


# ── Candidate Session ─────────────────────────────────────────────────────────

class CandidateSession(Base):
    __tablename__ = "candidate_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    candidate_id: Mapped[str] = mapped_column(ForeignKey("candidates.id"), nullable=False)
    exam_id: Mapped[str] = mapped_column(ForeignKey("exams.id"), nullable=False)
    form_id: Mapped[str] = mapped_column(ForeignKey("exam_forms.id"), nullable=False)
    centre_id: Mapped[Optional[str]] = mapped_column(ForeignKey("centres.id"), nullable=True)
    session_token_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    session_key_encrypted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    submitted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_heartbeat: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[SessionStatus] = mapped_column(Enum(SessionStatus), default=SessionStatus.ACTIVE)
    ip_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    device_fingerprint: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    tab_switch_count: Mapped[int] = mapped_column(Integer, default=0)
    security_violations: Mapped[int] = mapped_column(Integer, default=0)
    current_question_index: Mapped[int] = mapped_column(Integer, default=0)

    candidate: Mapped["Candidate"] = relationship("Candidate", back_populates="sessions")
    form: Mapped["ExamForm"] = relationship("ExamForm", back_populates="sessions")
    responses: Mapped[List["Response"]] = relationship("Response", back_populates="session")

    __table_args__ = (
        Index("ix_session_candidate_exam", "candidate_id", "exam_id"),
        Index("ix_session_status", "status"),
        # Database-level enforcement: one ACTIVE session per candidate per exam.
        # PostgreSQL partial unique index — prevents race-condition duplicate sessions
        # even when concurrent requests bypass the application-level check.
        # PROD NOTE: On PostgreSQL this is a WHERE-clause partial index.
        # On SQLite this is a full unique index (SQLite also supports partial indexes
        # but SQLAlchemy's DDL rendering path varies — validate at migration time).
        Index(
            "uix_active_session_candidate_exam",
            "candidate_id",
            "exam_id",
            unique=True,
            postgresql_where=text("status = 'ACTIVE'"),
            sqlite_where=text("status = 'ACTIVE'"),
        ),
    )


# ── Response ──────────────────────────────────────────────────────────────────

class Response(Base):
    __tablename__ = "responses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    session_id: Mapped[str] = mapped_column(ForeignKey("candidate_sessions.id"), nullable=False)
    question_id: Mapped[str] = mapped_column(ForeignKey("questions.id"), nullable=False)
    selected_option: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # 0-3 for A-D
    is_marked_review: Mapped[bool] = mapped_column(Boolean, default=False)
    is_skipped: Mapped[bool] = mapped_column(Boolean, default=False)
    saved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    response_sequence: Mapped[int] = mapped_column(Integer, default=1)  # Replay detection

    session: Mapped["CandidateSession"] = relationship("CandidateSession", back_populates="responses")
    question: Mapped["Question"] = relationship("Question")

    __table_args__ = (
        UniqueConstraint("session_id", "question_id", name="uq_session_question_response"),
        Index("ix_response_session", "session_id"),
    )


# ── Release Approval ──────────────────────────────────────────────────────────

class ReleaseApproval(Base):
    __tablename__ = "release_approvals"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    exam_id: Mapped[str] = mapped_column(ForeignKey("exams.id"), nullable=False)
    authority_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    nonce: Mapped[str] = mapped_column(String(128), nullable=False)
    approval_signature: Mapped[str] = mapped_column(Text, nullable=False)
    ip_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    is_valid: Mapped[bool] = mapped_column(Boolean, default=True)

    exam: Mapped["Exam"] = relationship("Exam", back_populates="release_approvals")
    authority: Mapped["User"] = relationship("User", back_populates="release_approvals")

    __table_args__ = (
        UniqueConstraint("exam_id", "authority_id", name="uq_exam_authority_approval"),
        Index("ix_release_approval_exam", "exam_id"),
    )


# ── Centre ────────────────────────────────────────────────────────────────────

class Centre(Base):
    __tablename__ = "centres"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), nullable=False)
    exam_id: Mapped[Optional[str]] = mapped_column(ForeignKey("exams.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    centre_code: Mapped[str] = mapped_column(String(50), nullable=False, unique=True)
    location: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    country: Mapped[str] = mapped_column(String(100), default="Global")
    status: Mapped[CentreStatus] = mapped_column(Enum(CentreStatus), default=CentreStatus.PENDING)
    device_count: Mapped[int] = mapped_column(Integer, default=0)
    checked_in_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    admin_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    exam: Mapped[Optional["Exam"]] = relationship("Exam", back_populates="centres")

    __table_args__ = (
        Index("ix_centre_exam_status", "exam_id", "status"),
    )


# ── Audit Log ─────────────────────────────────────────────────────────────────

class AuditLog(Base):
    """
    Hash-chained audit log.
    Each entry includes prev_hash and event_hash forming an immutable chain.
    Any modification to historical entries breaks the chain and is detectable.
    """
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)  # Monotonically increasing
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    actor_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    actor_role: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    resource_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    resource_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    action: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    result: Mapped[AuditResult] = mapped_column(Enum(AuditResult), default=AuditResult.SUCCESS)
    ip_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    device_id: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    event_metadata: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    prev_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        Index("ix_audit_actor", "actor_id"),
        Index("ix_audit_event_type", "event_type"),
        Index("ix_audit_timestamp", "timestamp"),
        Index("ix_audit_resource", "resource_type", "resource_id"),
    )


# ── Security Event ────────────────────────────────────────────────────────────

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    actor_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    session_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    exam_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    details: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    resolved: Mapped[bool] = mapped_column(Boolean, default=False)
    resolved_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        Index("ix_security_event_type_severity", "event_type", "severity"),
        Index("ix_security_event_actor", "actor_id"),
        Index("ix_security_event_created", "created_at"),
    )


# ── Incident ──────────────────────────────────────────────────────────────────

class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[IncidentSeverity] = mapped_column(Enum(IncidentSeverity), nullable=False)
    status: Mapped[IncidentStatus] = mapped_column(Enum(IncidentStatus), default=IncidentStatus.OPEN)
    exam_id: Mapped[Optional[str]] = mapped_column(ForeignKey("exams.id"), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    affected_resource: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    assigned_to: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id"), nullable=True)
    actions_taken: Mapped[Optional[list]] = mapped_column(JSONB, nullable=True)
    resolution: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_incident_severity_status", "severity", "status"),
    )


# ── Answer Key ────────────────────────────────────────────────────────────────

class AnswerKey(Base):
    """
    Answer keys are stored separately with strict access control.
    Only the evaluation service (with EVALUATOR permission) can access these.
    Candidate-facing APIs must NEVER access this table.
    """
    __tablename__ = "answer_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    question_id: Mapped[str] = mapped_column(ForeignKey("questions.id"), nullable=False, unique=True)
    correct_option: Mapped[int] = mapped_column(Integer, nullable=False)  # 0-3
    marks_positive: Mapped[float] = mapped_column(Float, default=4.0)
    marks_negative: Mapped[float] = mapped_column(Float, default=1.0)
    explanation_encrypted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    key_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    question: Mapped["Question"] = relationship("Question")

    __table_args__ = (
        Index("ix_answer_key_question", "question_id"),
    )


# ── Result ────────────────────────────────────────────────────────────────────

class Result(Base):
    __tablename__ = "results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    session_id: Mapped[str] = mapped_column(ForeignKey("candidate_sessions.id"), nullable=False, unique=True)
    candidate_id: Mapped[str] = mapped_column(ForeignKey("candidates.id"), nullable=False)
    exam_id: Mapped[str] = mapped_column(ForeignKey("exams.id"), nullable=False)
    total_score: Mapped[float] = mapped_column(Float, default=0.0)
    max_score: Mapped[float] = mapped_column(Float, default=0.0)
    attempted: Mapped[int] = mapped_column(Integer, default=0)
    correct: Mapped[int] = mapped_column(Integer, default=0)
    incorrect: Mapped[int] = mapped_column(Integer, default=0)
    skipped: Mapped[int] = mapped_column(Integer, default=0)
    result_signature: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (
        Index("ix_result_candidate_exam", "candidate_id", "exam_id"),
    )
