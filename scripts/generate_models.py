from pathlib import Path

models_path = Path("E:/Cloud-Mini-Project/backend/app/core/models.py")
content = models_path.read_text(encoding="utf-8")

# 1. Update imports
old_import = """from sqlalchemy import (
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
)"""

new_import = """from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
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
)"""

assert old_import in content, "old_import not found!"
content = content.replace(old_import, new_import, 1)

# 2. Update AuditLog and add AuditChainLink & AuditEpochSeal
old_audit_block = """class AuditLog(Base):
    \"\"\"
    Hash-chained audit log.
    Each entry includes prev_hash and event_hash forming an immutable chain.
    Any modification to historical entries breaks the chain and is detectable.
    \"\"\"
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
    )"""

new_audit_block = """class AuditLog(Base):
    \"\"\"
    Append-only authoritative audit log.
    Raw security & application audit events are strictly immutable after commit.
    PostgreSQL triggers strictly prevent UPDATE and DELETE operations.
    \"\"\"
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    seq: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # Legacy compatibility; sealer assigns chain_seq
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    actor_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    actor_role: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    resource_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    resource_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    action: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    result: Mapped[AuditResult] = mapped_column(Enum(AuditResult), default=AuditResult.SUCCESS, nullable=False)
    ip_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    device_id: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    event_metadata: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    prev_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)  # Legacy compatibility
    event_hash: Mapped[str] = mapped_column(String(128), nullable=False)  # Canonical event SHA-256
    trace_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    kms_request_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=func.now(), nullable=False
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=func.now(), nullable=False
    )

    chain_link: Mapped[Optional["AuditChainLink"]] = relationship(
        "AuditChainLink", back_populates="audit_log", uselist=False
    )

    __table_args__ = (
        Index("ix_audit_actor", "actor_id"),
        Index("ix_audit_event_type", "event_type"),
        Index("ix_audit_timestamp", "timestamp"),
        Index("ix_audit_created_at", "created_at"),
        Index("ix_audit_created_at_id", "created_at", "id"),
        Index("ix_audit_resource", "resource_type", "resource_id"),
        Index("ix_audit_trace_id", "trace_id"),
    )


# ── Audit Chain Link (Append-Only Hash Chain) ────────────────────────────────

class AuditChainLink(Base):
    \"\"\"
    Append-only cryptographic hash chain linking raw audit logs.
    Sealer assigns strictly contiguous monotonic chain_seq.
    Each link references exactly one audit_logs row.
    PostgreSQL triggers strictly prohibit UPDATE and DELETE operations.
    \"\"\"
    __tablename__ = "audit_chain_links"

    link_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    chain_seq: Mapped[int] = mapped_column(BigInteger, nullable=False, unique=True)
    audit_log_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("audit_logs.id", ondelete="RESTRICT", name="fk_audit_chain_links_audit_log_id"),
        nullable=False,
        unique=True,
    )
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    prev_chain_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    chain_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=func.now(), nullable=False
    )

    audit_log: Mapped["AuditLog"] = relationship("AuditLog", back_populates="chain_link")

    __table_args__ = (
        UniqueConstraint("chain_seq", name="uq_audit_chain_links_chain_seq"),
        UniqueConstraint("audit_log_id", name="uq_audit_chain_links_audit_log_id"),
        Index("ix_audit_chain_links_chain_seq", "chain_seq"),
        Index("ix_audit_chain_links_audit_log_id", "audit_log_id"),
        Index("ix_audit_chain_links_created_at", "created_at"),
    )


# ── Audit Epoch Seal (Append-Only KMS Ed25519 Checkpoints) ───────────────────

class AuditEpochSeal(Base):
    \"\"\"
    Append-only KMS Ed25519 signed epoch checkpoints.
    Seals a contiguous range of chain links [start_chain_seq, end_chain_seq].
    PostgreSQL triggers strictly prohibit UPDATE and DELETE operations.
    \"\"\"
    __tablename__ = "audit_epoch_seals"

    epoch_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)  # 1, 2, 3...
    policy_version: Mapped[str] = mapped_column(String(32), nullable=False, default="BSEA-AUDIT-v1")
    start_chain_seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    end_chain_seq: Mapped[int] = mapped_column(BigInteger, nullable=False, unique=True)
    record_count: Mapped[int] = mapped_column(Integer, nullable=False)
    prev_seal_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    final_chain_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    epoch_root_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    signature_b64: Mapped[str] = mapped_column(Text, nullable=False)
    kms_key_id: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("end_chain_seq", name="uq_audit_epoch_seals_end_chain_seq"),
        Index("ix_audit_epoch_seals_start_chain_seq", "start_chain_seq"),
        Index("ix_audit_epoch_seals_created_at", "created_at"),
        CheckConstraint("start_chain_seq >= 1", name="ck_audit_epoch_seals_positive_seq"),
        CheckConstraint("start_chain_seq <= end_chain_seq", name="ck_audit_epoch_seals_seq_range"),
        CheckConstraint("record_count > 0", name="ck_audit_epoch_seals_record_count"),
        CheckConstraint("record_count = (end_chain_seq - start_chain_seq + 1)", name="ck_audit_epoch_seals_count_match"),
    )"""

assert old_audit_block in content, "old_audit_block not found!"
content = content.replace(old_audit_block, new_audit_block, 1)

out_path = Path("C:/Users/madha/.gemini/antigravity-ide/brain/b08a7d54-faed-4bb0-aeb8-0567c09c12c6/scratch/updated_models.py")
out_path.write_text(content, encoding="utf-8")
print(f"Generated updated_models.py successfully ({len(content)} bytes)")
