"""
B-SEA Authoritative Audit Sealer Engine

Phase 3C-4B Reference Implementation.
Implements:
- Session-scoped PostgreSQL advisory lock leadership serialization (0x4253454100000001)
- Poison / invalid audit event rejection and closed-failure
- Transaction B: Canonical chain sequence assignment & 72-byte preimage hashing
- RFC 6962 Domain-separated Merkle root generation
- Deterministic canonical epoch manifest creation
- AWS KMS / MockKMS Ed25519 signing strictly OUTSIDE database transactions
- Transaction D: Transactional cross-epoch continuity verification and seal persistence
- Complete deterministic retry and crash recovery
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.database import engine as default_engine
from app.crypto.kms_interface import get_kms
from app.modules.audit.canonical import (
    DEFAULT_POLICY_VERSION,
    get_kms_signing_key_id,
    GENESIS_CHAIN_HASH,
    GENESIS_EPOCH_HASH,
    build_canonical_epoch_manifest,
    compute_canonical_chain_hash,
    compute_merkle_root,
    compute_prev_seal_hash,
    serialize_canonical_epoch_manifest,
)

logger = logging.getLogger(__name__)

# Primary Session-Scoped Advisory Lock ID for Sealer Leadership
# Hex: 0x4253454100000001 -> Signed 64-bit int: 4779267104085409793
SEALER_ADVISORY_LOCK_ID = 4779267104085409793

TARGET_EPOCH_SIZE = 1000
MAX_EPOCH_AGE_SECONDS = 900  # 15 minutes

_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class AuditSealerError(Exception):
    """Base exception for audit sealer errors."""
    pass


class AuditSealerLockError(AuditSealerError):
    """Raised when leadership lock cannot be acquired or fails."""
    pass


class AuditSealerContinuityError(AuditSealerError):
    """Raised when cross-epoch continuity verification fails."""
    pass


class PoisonAuditEventError(AuditSealerError):
    """Raised when an invalid/corrupted audit event is encountered (fail closed)."""
    pass


class KMSSealingError(AuditSealerError):
    """Raised when KMS signing fails during epoch sealing."""
    pass


@dataclass
class SealerCycleResult:
    status: str  # "SUCCESS", "NOOP", "LOCKED", "ERROR"
    links_incorporated: int = 0
    epochs_sealed: int = 0
    epoch_ids: List[int] = field(default_factory=list)
    message: str = ""


class AuditSealer:
    """
    Authoritative Sealer Daemon responsible for canonical chain incorporation
    and KMS-signed epoch checkpoint sealing.
    """

    def __init__(
        self,
        engine: Optional[AsyncEngine] = None,
        kms: Optional[Any] = None,
        policy_version: str = DEFAULT_POLICY_VERSION,
        target_epoch_size: int = TARGET_EPOCH_SIZE,
        max_epoch_age_seconds: int = MAX_EPOCH_AGE_SECONDS,
        kms_key_id: Optional[str] = None,
    ):
        self.engine = engine or default_engine
        self.kms = kms or get_kms()
        self.policy_version = policy_version
        self.target_epoch_size = target_epoch_size
        self.max_epoch_age_seconds = max_epoch_age_seconds
        self.kms_key_id = kms_key_id

    async def acquire_leadership(self, conn) -> bool:
        """
        Attempt to acquire session-scoped PostgreSQL advisory lock.
        Bound to physical PostgreSQL connection/session.
        """
        res = await conn.execute(
            text("SELECT pg_try_advisory_lock(:lock_id)"),
            {"lock_id": SEALER_ADVISORY_LOCK_ID},
        )
        locked = bool(res.scalar())
        await conn.commit()
        return locked

    async def release_leadership(self, conn) -> bool:
        """
        Release session-scoped PostgreSQL advisory lock.
        """
        try:
            res = await conn.execute(
                text("SELECT pg_advisory_unlock(:lock_id)"),
                {"lock_id": SEALER_ADVISORY_LOCK_ID},
            )
            unlocked = bool(res.scalar())
            await conn.commit()
            return unlocked
        except Exception as e:
            logger.warning(f"Error releasing advisory lock {SEALER_ADVISORY_LOCK_ID}: {e}")
            return False

    async def incorporate_unsealed_events(
        self, conn, batch_size: int = 1000
    ) -> int:
        """
        Transaction B: Canonical Chain Incorporation.
        Selects committed raw audit logs not yet in audit_chain_links,
        validates integrity (rejecting poison records), assigns contiguous
        monotonic chain_seq values, and persists to audit_chain_links.
        """
        # 1. Candidate Selection
        query_candidates = text("""
            SELECT al.id, al.event_hash, al.created_at
            FROM audit_logs al
            WHERE NOT EXISTS (
                SELECT 1 FROM audit_chain_links acl WHERE acl.audit_log_id = al.id
            )
            ORDER BY al.created_at ASC, al.id ASC
            LIMIT :batch_size;
        """)
        res = await conn.execute(query_candidates, {"batch_size": batch_size})
        candidates = res.fetchall()
        await conn.commit()

        if not candidates:
            return 0

        # 2. Poison / Invalid Audit Record Validation (Fail Closed)
        for cand in candidates:
            if not cand.event_hash or not _HEX64_RE.match(cand.event_hash):
                logger.error(
                    f"POISON AUDIT EVENT DETECTED: audit_log {cand.id} has invalid event_hash: {cand.event_hash!r}"
                )
                raise PoisonAuditEventError(
                    f"Unrecoverable poison audit event detected: id={cand.id}, event_hash={cand.event_hash!r}. Failing closed."
                )

        # 3. Transaction B: Lock chain head and append contiguous chain links
        async with conn.begin():
            head_res = await conn.execute(
                text("""
                    SELECT chain_seq, chain_hash
                    FROM audit_chain_links
                    ORDER BY chain_seq DESC
                    LIMIT 1
                    FOR UPDATE;
                """)
            )
            head = head_res.fetchone()

            if head is None:
                last_seq = 0
                last_chain_hash = GENESIS_CHAIN_HASH
            else:
                last_seq = head[0]
                last_chain_hash = head[1]

            links_to_insert = []
            now_utc = datetime.now(timezone.utc)

            for cand in candidates:
                last_seq += 1
                curr_seq = last_seq
                prev_chain_hash = last_chain_hash
                curr_chain_hash = compute_canonical_chain_hash(
                    prev_chain_hash, cand.event_hash, curr_seq
                )
                links_to_insert.append({
                    "chain_seq": curr_seq,
                    "audit_log_id": cand.id,
                    "event_hash": cand.event_hash.lower(),
                    "prev_chain_hash": prev_chain_hash.lower(),
                    "chain_hash": curr_chain_hash.lower(),
                    "created_at": now_utc,
                })
                last_chain_hash = curr_chain_hash

            await conn.execute(
                text("""
                    INSERT INTO audit_chain_links (
                        chain_seq, audit_log_id, event_hash, prev_chain_hash, chain_hash, created_at
                    ) VALUES (
                        :chain_seq, :audit_log_id, :event_hash, :prev_chain_hash, :chain_hash, :created_at
                    )
                """),
                links_to_insert,
            )

        logger.info(f"Incorporated {len(candidates)} audit events into canonical chain (new head seq: {last_seq})")
        return len(candidates)

    async def evaluate_and_seal_epoch(self, conn) -> Optional[int]:
        """
        Evaluates epoch sealing conditions (1,000 links or 15-minute age threshold).
        If eligible:
        - Freezes range [start_chain_seq, end_chain_seq]
        - Computes Merkle root RFC 6962
        - Builds canonical manifest
        - Calls KMS sign OUTSIDE database transaction
        - Validates continuity & persists seal in Transaction D
        """
        # Query latest epoch seal to determine start_chain_seq & prev_seal_hash
        seal_res = await conn.execute(
            text("""
                SELECT epoch_id, start_chain_seq, end_chain_seq, record_count,
                       prev_seal_hash, epoch_root_hash, policy_version, kms_key_id
                FROM audit_epoch_seals
                ORDER BY epoch_id DESC
                LIMIT 1;
            """)
        )
        latest_seal = seal_res.fetchone()
        await conn.commit()

        if latest_seal is None:
            start_chain_seq = 1
            next_epoch_id = 1
            prev_seal_hash = GENESIS_EPOCH_HASH
        else:
            start_chain_seq = latest_seal.end_chain_seq + 1
            next_epoch_id = latest_seal.epoch_id + 1
            prev_manifest = build_canonical_epoch_manifest(
                epoch_id=latest_seal.epoch_id,
                start_chain_seq=latest_seal.start_chain_seq,
                end_chain_seq=latest_seal.end_chain_seq,
                record_count=latest_seal.record_count,
                epoch_root_hash=latest_seal.epoch_root_hash,
                prev_seal_hash=latest_seal.prev_seal_hash,
                kms_key_id=latest_seal.kms_key_id,
                policy_version=latest_seal.policy_version,
            )
            prev_manifest_bytes = serialize_canonical_epoch_manifest(prev_manifest)
            prev_seal_hash = compute_prev_seal_hash(prev_manifest_bytes)

        # Inspect unsealed chain links starting from start_chain_seq
        unsealed_res = await conn.execute(
            text("""
                SELECT COUNT(acl.chain_seq), MIN(al.created_at), MAX(acl.chain_seq)
                FROM audit_chain_links acl
                JOIN audit_logs al ON acl.audit_log_id = al.id
                WHERE acl.chain_seq >= :start_chain_seq;
            """),
            {"start_chain_seq": start_chain_seq},
        )
        unsealed_row = unsealed_res.fetchone()
        unsealed_count = unsealed_row[0] if unsealed_row else 0
        min_created_at = unsealed_row[1] if unsealed_row else None
        max_chain_seq = unsealed_row[2] if unsealed_row else None
        await conn.commit()

        if unsealed_count == 0:
            return None

        # Determine if ready to seal
        now_utc = datetime.now(timezone.utc)
        if unsealed_count >= self.target_epoch_size:
            # Full epoch
            record_count = self.target_epoch_size
            end_chain_seq = start_chain_seq + record_count - 1
        else:
            # Partial epoch age evaluation
            if min_created_at is None:
                return None
            if min_created_at.tzinfo is None:
                min_created_at = min_created_at.replace(tzinfo=timezone.utc)
            age_seconds = (now_utc - min_created_at).total_seconds()

            if age_seconds >= self.max_epoch_age_seconds:
                # Age threshold reached: seal all currently available links
                record_count = unsealed_count
                end_chain_seq = max_chain_seq
            else:
                # Not ready to seal
                return None

        # Fetch chain hashes for frozen range [start_chain_seq, end_chain_seq]
        links_res = await conn.execute(
            text("""
                SELECT chain_seq, chain_hash
                FROM audit_chain_links
                WHERE chain_seq >= :start_chain_seq AND chain_seq <= :end_chain_seq
                ORDER BY chain_seq ASC;
            """),
            {"start_chain_seq": start_chain_seq, "end_chain_seq": end_chain_seq},
        )
        links = links_res.fetchall()
        await conn.commit()

        if len(links) != record_count:
            raise AuditSealerError(
                f"Frozen range gap detected: expected {record_count} links between {start_chain_seq} and {end_chain_seq}, found {len(links)}"
            )

        chain_hashes = [link.chain_hash for link in links]
        epoch_root_hash = compute_merkle_root(chain_hashes)
        final_chain_hash = chain_hashes[-1]

        # Build exact 9-field canonical epoch manifest
        target_kms_key = self.kms_key_id or get_kms_signing_key_id(self.kms)
        manifest_dict = build_canonical_epoch_manifest(
            epoch_id=next_epoch_id,
            start_chain_seq=start_chain_seq,
            end_chain_seq=end_chain_seq,
            record_count=record_count,
            epoch_root_hash=epoch_root_hash,
            prev_seal_hash=prev_seal_hash,
            kms_key_id=target_kms_key,
            policy_version=self.policy_version,
        )
        manifest_bytes = serialize_canonical_epoch_manifest(manifest_dict)

        # ── KMS SIGNING (STRICTLY OUTSIDE DATABASE TRANSACTION) ──
        try:
            signed_payload = self.kms.sign(manifest_bytes, key_id=self.kms_key_id)
        except Exception as e:
            logger.error(f"KMS Signing failed for epoch {next_epoch_id}: {e}")
            raise KMSSealingError(f"KMS signing failed for epoch {next_epoch_id}: {e}") from e

        # ── TRANSACTION D: CONTINUITY VALIDATION + PERSISTENCE ──
        async with conn.begin():
            # Verify latest seal under row lock
            latest_check_res = await conn.execute(
                text("""
                    SELECT epoch_id, start_chain_seq, end_chain_seq, record_count,
                           prev_seal_hash, epoch_root_hash, policy_version, kms_key_id
                    FROM audit_epoch_seals
                    ORDER BY epoch_id DESC
                    LIMIT 1
                    FOR UPDATE;
                """)
            )
            latest_db = latest_check_res.fetchone()

            if latest_db is None:
                expected_epoch_id = 1
                expected_start = 1
                expected_prev_seal = GENESIS_EPOCH_HASH
            else:
                expected_epoch_id = latest_db.epoch_id + 1
                expected_start = latest_db.end_chain_seq + 1
                check_manifest = build_canonical_epoch_manifest(
                    epoch_id=latest_db.epoch_id,
                    start_chain_seq=latest_db.start_chain_seq,
                    end_chain_seq=latest_db.end_chain_seq,
                    record_count=latest_db.record_count,
                    epoch_root_hash=latest_db.epoch_root_hash,
                    prev_seal_hash=latest_db.prev_seal_hash,
                    kms_key_id=latest_db.kms_key_id,
                    policy_version=latest_db.policy_version,
                )
                expected_prev_seal = compute_prev_seal_hash(check_manifest)

            if (
                next_epoch_id != expected_epoch_id
                or start_chain_seq != expected_start
                or prev_seal_hash != expected_prev_seal
            ):
                raise AuditSealerContinuityError(
                    f"Cross-epoch continuity verification failed in Transaction D: "
                    f"expected epoch_id={expected_epoch_id} (got {next_epoch_id}), "
                    f"expected start_chain_seq={expected_start} (got {start_chain_seq}), "
                    f"expected prev_seal_hash={expected_prev_seal} (got {prev_seal_hash})"
                )

            # Persist sealed epoch checkpoint
            await conn.execute(
                text("""
                    INSERT INTO audit_epoch_seals (
                        epoch_id, policy_version, start_chain_seq, end_chain_seq,
                        record_count, prev_seal_hash, final_chain_hash,
                        epoch_root_hash, signature_b64, kms_key_id, created_at
                    ) VALUES (
                        :epoch_id, :policy_version, :start_chain_seq, :end_chain_seq,
                        :record_count, :prev_seal_hash, :final_chain_hash,
                        :epoch_root_hash, :signature_b64, :kms_key_id, :created_at
                    )
                """),
                {
                    "epoch_id": next_epoch_id,
                    "policy_version": self.policy_version,
                    "start_chain_seq": start_chain_seq,
                    "end_chain_seq": end_chain_seq,
                    "record_count": record_count,
                    "prev_seal_hash": prev_seal_hash,
                    "final_chain_hash": final_chain_hash,
                    "epoch_root_hash": epoch_root_hash,
                    "signature_b64": signed_payload.signature_b64,
                    "kms_key_id": signed_payload.key_id,
                    "created_at": datetime.now(timezone.utc),
                },
            )

        logger.info(
            f"Successfully sealed Epoch {next_epoch_id} (range [{start_chain_seq}, {end_chain_seq}], count={record_count})"
        )
        return next_epoch_id

    async def run_once(self, batch_size: int = 1000) -> SealerCycleResult:
        """
        Execute a single sealer cycle:
        1. Connect to PostgreSQL
        2. Acquire session advisory lock
        3. Incorporate unsealed events
        4. Evaluate and seal ready epochs
        5. Release advisory lock
        """
        async with self.engine.connect() as conn:
            acquired = await self.acquire_leadership(conn)
            if not acquired:
                logger.info(
                    f"Sealer advisory lock 0x{SEALER_ADVISORY_LOCK_ID:x} is held by another worker. Skipping."
                )
                return SealerCycleResult(
                    status="LOCKED",
                    message="Sealer advisory lock held by another process.",
                )

            total_incorporated = 0
            sealed_epochs = []
            try:
                # Incorporate all ready unsealed batches
                while True:
                    count = await self.incorporate_unsealed_events(conn, batch_size=batch_size)
                    total_incorporated += count
                    if count < batch_size:
                        break

                # Seal ready epochs
                while True:
                    epoch_id = await self.evaluate_and_seal_epoch(conn)
                    if epoch_id is None:
                        break
                    sealed_epochs.append(epoch_id)

                if total_incorporated == 0 and not sealed_epochs:
                    status = "NOOP"
                    message = "No unsealed events or ready epochs."
                else:
                    status = "SUCCESS"
                    message = f"Incorporated {total_incorporated} links, sealed {len(sealed_epochs)} epochs."

                return SealerCycleResult(
                    status=status,
                    links_incorporated=total_incorporated,
                    epochs_sealed=len(sealed_epochs),
                    epoch_ids=sealed_epochs,
                    message=message,
                )
            finally:
                await self.release_leadership(conn)

    async def run_forever(self, interval_seconds: int = 60):
        """
        Run the sealer loop indefinitely with error handling and sleep.
        """
        logger.info("AuditSealer background service started.")
        while True:
            try:
                result = await self.run_once()
                if result.status == "SUCCESS":
                    logger.info(f"Sealer cycle completed: {result.message}")
            except Exception as e:
                logger.error(f"Error in sealer cycle: {e}", exc_info=True)

            await asyncio.sleep(interval_seconds)
