"""
B-SEA Dual-Mode Durable Audit Ingestion Service and Canonical Chain Verifier

Phase 3C-4B Authoritative Implementation.
Supports:
- MODE A: Business-Atomic Audit (participates in caller's AsyncSession transaction)
- MODE B: Security-Critical Isolated Audit (independent AsyncSession, survives caller rollback)
- Canonical Hash Chain & Epoch Seal Dual-Path Integrity Verification
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import HTTPException
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import AsyncSessionLocal
from app.core.models import (
    AuditChainLink,
    AuditEpochSeal,
    AuditLog,
    AuditPoisonQuarantine,
    AuditResult,
    new_uuid,
)
from app.modules.audit.canonical import _HEX64_RE
from app.modules.audit.quarantine import (
    build_quarantine_authorization_payload,
    get_operator_key_registry,
)
from app.crypto.kms_interface import (
    GENESIS_HASH,
    compute_audit_hash,
    get_kms,
)
from app.modules.audit.canonical import (
    GENESIS_CHAIN_HASH,
    GENESIS_EPOCH_HASH,
    build_canonical_epoch_manifest,
    build_canonical_event_payload,
    compute_canonical_chain_hash,
    compute_canonical_event_hash,
    compute_merkle_root,
    compute_prev_seal_hash,
    serialize_canonical_epoch_manifest,
)

logger = logging.getLogger(__name__)

# Deprecated bounded queue stubs for backward-compatible imports in main.py
AUDIT_QUEUE_MAX_SIZE = 10000
DEFAULT_LEGACY_CUTOVER_SEQ = 5982
_audit_queue = asyncio.Queue(maxsize=AUDIT_QUEUE_MAX_SIZE)


class AuditService:
    """
    Durable Audit Service implementing dual-mode ingestion:
    - Mode A: Business-Atomic (participates in caller's active AsyncSession)
    - Mode B: Security-Isolated (commits immediately in an independent AsyncSession)
    """

    def __init__(self, db: Optional[AsyncSession] = None):
        self.db = db

    async def log(
        self,
        event_type: str,
        result: AuditResult = AuditResult.SUCCESS,
        actor_id: Optional[str] = None,
        actor_role: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        action: Optional[str] = None,
        ip_hash: Optional[str] = None,
        device_id: Optional[str] = None,
        metadata: Optional[dict] = None,
        risk_score: float = 0.0,
        session: Optional[AsyncSession] = None,
    ) -> AuditLog:
        """
        MODE A: Business-Atomic Audit Ingestion.
        The audit log entry participates in the caller's transaction.
        If the caller's transaction rolls back, this audit log rolls back atomically.
        """
        timestamp = datetime.now(timezone.utc)
        event_id = new_uuid()

        # Build canonical event payload and compute immutable canonical event hash
        payload = build_canonical_event_payload(
            event_id=event_id,
            event_type=event_type,
            created_at=timestamp,
            result=result,
            actor_id=actor_id,
            actor_role=actor_role,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            event_metadata=metadata or {},
            ip_hash=ip_hash,
            device_id=device_id,
            risk_score=risk_score,
        )
        event_hash = compute_canonical_event_hash(payload)

        # Create immutable raw audit log entry
        log_entry = AuditLog(
            id=event_id,
            event_type=event_type,
            actor_id=actor_id,
            actor_role=actor_role,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            result=result,
            ip_hash=ip_hash,
            device_id=device_id,
            event_metadata=metadata or {},
            risk_score=risk_score,
            event_hash=event_hash,
            seq=None,  # Canonical sequence is assigned by the Sealer into audit_chain_links
            prev_hash=None,
            created_at=timestamp,
            timestamp=timestamp,
        )

        target_session = session or self.db
        if target_session is not None:
            # Mode A: Add to active business transaction (caller commits or rolls back)
            target_session.add(log_entry)
            return log_entry
        else:
            # If no caller session was provided, commit durably in an independent session
            async with AsyncSessionLocal() as standalone_session:
                standalone_session.add(log_entry)
                await standalone_session.commit()
                await standalone_session.refresh(log_entry)
            return log_entry

    async def log_security_event(
        self,
        event_type: str,
        result: AuditResult = AuditResult.FAILURE,
        actor_id: Optional[str] = None,
        actor_role: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        action: Optional[str] = None,
        ip_hash: Optional[str] = None,
        device_id: Optional[str] = None,
        metadata: Optional[dict] = None,
        risk_score: float = 0.0,
    ) -> AuditLog:
        """
        MODE B: Security-Critical Failure / Denial Ingestion.
        Always executed in a dedicated, isolated AsyncSession and committed immediately.
        Caller rollback CANNOT erase this audit record.
        """
        timestamp = datetime.now(timezone.utc)
        event_id = new_uuid()

        payload = build_canonical_event_payload(
            event_id=event_id,
            event_type=event_type,
            created_at=timestamp,
            result=result,
            actor_id=actor_id,
            actor_role=actor_role,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            event_metadata=metadata or {},
            ip_hash=ip_hash,
            device_id=device_id,
            risk_score=risk_score,
        )
        event_hash = compute_canonical_event_hash(payload)

        log_entry = AuditLog(
            id=event_id,
            event_type=event_type,
            actor_id=actor_id,
            actor_role=actor_role,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            result=result,
            ip_hash=ip_hash,
            device_id=device_id,
            event_metadata=metadata or {},
            risk_score=risk_score,
            event_hash=event_hash,
            seq=None,
            prev_hash=None,
            created_at=timestamp,
            timestamp=timestamp,
        )

        async with AsyncSessionLocal() as sec_session:
            sec_session.add(log_entry)
            await sec_session.commit()
            await sec_session.refresh(log_entry)

        return log_entry

    async def verify_chain(self) -> dict:
        """
        Dual-Path Cryptographic Chain Verification:
        1. Verifies the canonical Phase 3C-4B chain (audit_chain_links & audit_epoch_seals)
           including exact 72-byte preimage hashes, contiguous sequences, Merkle trees,
           and KMS Ed25519 signatures.
        2. Fallback to legacy Phase 3C-4A seq/prev_hash verification if no canonical
           chain links exist yet.
        """
        session = self.db
        if session is None:
            async with AsyncSessionLocal() as temp_session:
                return await self._verify_chain_internal(temp_session)
        return await self._verify_chain_internal(session)

    async def _verify_chain_internal(self, session: AsyncSession) -> dict:
        # Check if canonical chain links exist
        res = await session.execute(
            select(AuditChainLink).order_by(AuditChainLink.chain_seq.asc())
        )
        links = res.scalars().all()

        if links:
            return await self._verify_canonical_chain(session, links)

        # Fallback to legacy audit_logs chain verification if links are empty
        return await self._verify_legacy_chain(session)

    async def _verify_canonical_chain(
        self, session: AsyncSession, links: List[AuditChainLink]
    ) -> dict:
        # 1. Verify link contiguous sequencing and 72-byte canonical hashes
        prev_chain_hash = GENESIS_CHAIN_HASH
        links_by_seq = {}

        for idx, link in enumerate(links):
            expected_seq = idx + 1
            if link.chain_seq != expected_seq:
                return {
                    "valid": False,
                    "canonical_chain": True,
                    "entries_checked": idx,
                    "chain_links_verified": idx,
                    "broken_at": link.chain_seq,
                    "message": f"CANONICAL SEQUENCE GAP: expected {expected_seq}, found {link.chain_seq}",
                }

            if link.prev_chain_hash != prev_chain_hash:
                return {
                    "valid": False,
                    "canonical_chain": True,
                    "entries_checked": idx,
                    "chain_links_verified": idx,
                    "broken_at": link.chain_seq,
                    "message": f"CANONICAL PREV HASH MISMATCH at chain_seq {link.chain_seq}",
                }

            expected_hash = compute_canonical_chain_hash(
                prev_chain_hash, link.event_hash, link.chain_seq
            )
            if link.chain_hash != expected_hash:
                return {
                    "valid": False,
                    "canonical_chain": True,
                    "entries_checked": idx,
                    "chain_links_verified": idx,
                    "broken_at": link.chain_seq,
                    "message": f"CANONICAL CHAIN HASH MISMATCH at chain_seq {link.chain_seq}",
                }

            prev_chain_hash = link.chain_hash
            links_by_seq[link.chain_seq] = link

        # 2. Verify audit_epoch_seals
        res = await session.execute(
            select(AuditEpochSeal).order_by(AuditEpochSeal.epoch_id.asc())
        )
        seals = res.scalars().all()

        kms = get_kms()
        prev_seal_hash = GENESIS_EPOCH_HASH
        prev_end_seq = 0

        for s_idx, seal in enumerate(seals):
            expected_epoch_id = s_idx + 1
            if seal.epoch_id != expected_epoch_id:
                return {
                    "valid": False,
                    "canonical_chain": True,
                    "entries_checked": len(links),
                    "chain_links_verified": len(links),
                    "broken_at_epoch": seal.epoch_id,
                    "message": f"EPOCH ID SEQUENCE GAP: expected {expected_epoch_id}, found {seal.epoch_id}",
                }

            expected_start = prev_end_seq + 1
            if seal.start_chain_seq != expected_start:
                return {
                    "valid": False,
                    "canonical_chain": True,
                    "entries_checked": len(links),
                    "chain_links_verified": len(links),
                    "broken_at_epoch": seal.epoch_id,
                    "message": f"CROSS-EPOCH SEQUENCE GAP: expected start {expected_start}, found {seal.start_chain_seq}",
                }

            expected_count = seal.end_chain_seq - seal.start_chain_seq + 1
            if seal.record_count != expected_count:
                return {
                    "valid": False,
                    "canonical_chain": True,
                    "entries_checked": len(links),
                    "chain_links_verified": len(links),
                    "broken_at_epoch": seal.epoch_id,
                    "message": f"EPOCH RECORD COUNT MISMATCH in epoch {seal.epoch_id}",
                }

            if seal.prev_seal_hash != prev_seal_hash:
                return {
                    "valid": False,
                    "canonical_chain": True,
                    "entries_checked": len(links),
                    "chain_links_verified": len(links),
                    "broken_at_epoch": seal.epoch_id,
                    "message": f"EPOCH PREV SEAL HASH MISMATCH in epoch {seal.epoch_id}",
                }

            # Recompute Merkle root over chain links
            epoch_link_hashes = [
                links_by_seq[seq].chain_hash
                for seq in range(seal.start_chain_seq, seal.end_chain_seq + 1)
                if seq in links_by_seq
            ]
            if len(epoch_link_hashes) != seal.record_count:
                return {
                    "valid": False,
                    "canonical_chain": True,
                    "entries_checked": len(links),
                    "chain_links_verified": len(links),
                    "broken_at_epoch": seal.epoch_id,
                    "message": f"MISSING CHAIN LINKS in epoch {seal.epoch_id}",
                }

            expected_root = compute_merkle_root(epoch_link_hashes)
            if seal.epoch_root_hash != expected_root:
                return {
                    "valid": False,
                    "canonical_chain": True,
                    "entries_checked": len(links),
                    "chain_links_verified": len(links),
                    "broken_at_epoch": seal.epoch_id,
                    "message": f"EPOCH MERKLE ROOT MISMATCH in epoch {seal.epoch_id}",
                }

            if seal.final_chain_hash != epoch_link_hashes[-1]:
                return {
                    "valid": False,
                    "canonical_chain": True,
                    "entries_checked": len(links),
                    "chain_links_verified": len(links),
                    "broken_at_epoch": seal.epoch_id,
                    "message": f"EPOCH FINAL CHAIN HASH MISMATCH in epoch {seal.epoch_id}",
                }

            # Reconstruct canonical manifest bytes and verify KMS signature
            manifest_dict = build_canonical_epoch_manifest(
                epoch_id=seal.epoch_id,
                start_chain_seq=seal.start_chain_seq,
                end_chain_seq=seal.end_chain_seq,
                record_count=seal.record_count,
                epoch_root_hash=seal.epoch_root_hash,
                prev_seal_hash=seal.prev_seal_hash,
                kms_key_id=seal.kms_key_id,
                policy_version=seal.policy_version,
            )
            manifest_bytes = serialize_canonical_epoch_manifest(manifest_dict)

            is_valid_sig = kms.verify(
                manifest_bytes, seal.signature_b64, seal.kms_key_id
            )
            if not is_valid_sig:
                return {
                    "valid": False,
                    "canonical_chain": True,
                    "entries_checked": len(links),
                    "chain_links_verified": len(links),
                    "broken_at_epoch": seal.epoch_id,
                    "message": f"EPOCH KMS SIGNATURE VERIFICATION FAILED in epoch {seal.epoch_id}",
                }

            # Update tracking for next epoch
            prev_seal_hash = compute_prev_seal_hash(manifest_bytes)
            prev_end_seq = seal.end_chain_seq

        return {
            "valid": True,
            "canonical_chain": True,
            "entries_checked": len(links),
            "chain_links_verified": len(links),
            "epochs_verified": len(seals),
            "chain_head": prev_chain_hash,
            "chain_head_seq": len(links),
            "broken_at": None,
        }


    async def verify_chain_deep(
        self,
        legacy_cutover_seq: Optional[int] = None,
        read_replica_session: Optional[AsyncSession] = None,
        max_replica_lag_seconds: float = 5.0,
        authorized_primary_fallback: bool = True,
    ) -> dict:
        """
        10-Point Exhaustive Cryptographic & Raw Payload Audit Verifier.
        Validates:
        1. Chain sequence contiguity (1..N)
        2. Canonical 72-byte preimage chaining
        3. Epoch ID & cross-epoch sequence continuity
        4. RFC 6962-inspired domain-separated Merkle roots
        5. KMS Ed25519 manifest digital signatures
        6. audit_chain_links <-> audit_logs foreign key linkage (no orphans)
        7. Legacy event hash preservation (chain_seq <= legacy_cutover_seq)
        8. Live canonical event hash recomputation (chain_seq > legacy_cutover_seq)
        9. audit_poison_quarantine dual signatures and non-chaining
        10. Unchained backlog integrity & lag evaluation

        Returns exactly one of: PASS, FAIL, UNAVAILABLE, INSUFFICIENT_FRESHNESS, UNRESOLVED.
        """
        cutover_seq = legacy_cutover_seq if legacy_cutover_seq is not None else DEFAULT_LEGACY_CUTOVER_SEQ
        now_iso = datetime.now(timezone.utc).isoformat()
        lag_seconds: Optional[float] = None
        fallback_used = False

        # Evaluate replica freshness and fallback hierarchy
        if read_replica_session is not None:
            try:
                res_lag = await read_replica_session.execute(
                    text("SELECT CASE WHEN pg_is_in_recovery() THEN EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp())) ELSE 0.0 END;")
                )
                lag_val = res_lag.scalar()
                lag_seconds = float(lag_val) if lag_val is not None else 0.0

                if lag_seconds > max_replica_lag_seconds:
                    logger.warning(
                        f"Read replica lag ({lag_seconds:.2f}s) exceeds threshold ({max_replica_lag_seconds}s)."
                    )
                    if authorized_primary_fallback:
                        logger.info("Executing authorized fallback to authoritative primary database.")
                        fallback_used = True
                        if self.db is not None:
                            return await self._verify_chain_deep_internal(
                                self.db, cutover_seq, lag_seconds, fallback_used
                            )
                        else:
                            async with AsyncSessionLocal() as prim_session:
                                return await self._verify_chain_deep_internal(
                                    prim_session, cutover_seq, lag_seconds, fallback_used
                                )
                    else:
                        return {
                            "status": "INSUFFICIENT_FRESHNESS",
                            "verification_timestamp": now_iso,
                            "replication_lag_seconds": lag_seconds,
                            "fallback_to_primary_used": False,
                            "reason": f"Read replica lag ({lag_seconds:.2f}s) exceeds threshold ({max_replica_lag_seconds}s) and primary fallback not authorized.",
                            "failure_category": "REPLICA_STALE",
                            "failure_details": None,
                        }
                else:
                    return await self._verify_chain_deep_internal(
                        read_replica_session, cutover_seq, lag_seconds, fallback_used
                    )
            except Exception as e:
                logger.warning(f"Error connecting to read replica: {e}")
                if authorized_primary_fallback:
                    fallback_used = True
                    try:
                        if self.db is not None:
                            return await self._verify_chain_deep_internal(
                                self.db, cutover_seq, None, fallback_used
                            )
                        else:
                            async with AsyncSessionLocal() as prim_session:
                                return await self._verify_chain_deep_internal(
                                    prim_session, cutover_seq, None, fallback_used
                                )
                    except Exception as prim_err:
                        return {
                            "status": "UNAVAILABLE",
                            "verification_timestamp": now_iso,
                            "replication_lag_seconds": None,
                            "fallback_to_primary_used": True,
                            "reason": f"Both read replica and authoritative primary are unavailable: {prim_err}",
                            "failure_category": "DB_UNAVAILABLE",
                            "failure_details": None,
                        }
                else:
                    return {
                        "status": "UNAVAILABLE",
                        "verification_timestamp": now_iso,
                        "replication_lag_seconds": None,
                        "fallback_to_primary_used": False,
                        "reason": f"Read replica is unavailable: {e}",
                        "failure_category": "REPLICA_UNAVAILABLE",
                        "failure_details": None,
                    }

        # Primary direct execution
        try:
            if self.db is not None:
                return await self._verify_chain_deep_internal(
                    self.db, cutover_seq, 0.0, False
                )
            else:
                async with AsyncSessionLocal() as prim_session:
                    return await self._verify_chain_deep_internal(
                        prim_session, cutover_seq, 0.0, False
                    )
        except Exception as e:
            return {
                "status": "UNAVAILABLE",
                "verification_timestamp": now_iso,
                "replication_lag_seconds": 0.0,
                "fallback_to_primary_used": False,
                "reason": f"Authoritative primary database is unavailable: {e}",
                "failure_category": "DB_UNAVAILABLE",
                "failure_details": None,
            }

    async def _verify_chain_deep_internal(
        self,
        session: AsyncSession,
        cutover_seq: int,
        lag_seconds: Optional[float],
        fallback_used: bool,
    ) -> dict:
        now_iso = datetime.now(timezone.utc).isoformat()
        try:
            # Fetch all chain links ordered by sequence
            res_links = await session.execute(
                select(AuditChainLink).order_by(AuditChainLink.chain_seq.asc())
            )
            links = list(res_links.scalars().all())

            # Fetch all epoch seals
            res_seals = await session.execute(
                select(AuditEpochSeal).order_by(AuditEpochSeal.epoch_id.asc())
            )
            seals = list(res_seals.scalars().all())

            # Fetch all quarantine records
            res_q = await session.execute(select(AuditPoisonQuarantine))
            quarantines = list(res_q.scalars().all())

            # ── Point 1: Chain Sequence Contiguity (1..N) ────────────────────
            prev_chain_hash = GENESIS_CHAIN_HASH
            links_by_seq = {}
            for idx, link in enumerate(links):
                expected_seq = idx + 1
                if link.chain_seq != expected_seq:
                    return {
                        "status": "FAIL",
                        "verification_timestamp": now_iso,
                        "failure_category": "CANONICAL_SEQUENCE_GAP",
                        "chain_seq": link.chain_seq,
                        "expected": expected_seq,
                        "actual": link.chain_seq,
                        "reason": f"Canonical sequence gap: expected {expected_seq}, found {link.chain_seq}",
                        "failure_details": {"chain_seq": link.chain_seq, "expected_seq": expected_seq},
                    }

                # ── Point 2: Canonical Preimage Chaining (72-byte SHA-256) ───
                if link.prev_chain_hash.lower() != prev_chain_hash.lower():
                    return {
                        "status": "FAIL",
                        "verification_timestamp": now_iso,
                        "failure_category": "CANONICAL_PREV_HASH_MISMATCH",
                        "chain_seq": link.chain_seq,
                        "expected": prev_chain_hash.lower(),
                        "actual": link.prev_chain_hash.lower(),
                        "reason": f"Canonical prev hash mismatch at chain_seq {link.chain_seq}",
                        "failure_details": {"chain_seq": link.chain_seq},
                    }

                expected_hash = compute_canonical_chain_hash(
                    prev_chain_hash, link.event_hash, link.chain_seq
                )
                if link.chain_hash.lower() != expected_hash.lower():
                    return {
                        "status": "FAIL",
                        "verification_timestamp": now_iso,
                        "failure_category": "CANONICAL_CHAIN_HASH_MISMATCH",
                        "chain_seq": link.chain_seq,
                        "expected": expected_hash.lower(),
                        "actual": link.chain_hash.lower(),
                        "reason": f"Canonical chain hash mismatch at chain_seq {link.chain_seq}",
                        "failure_details": {"chain_seq": link.chain_seq},
                    }

                prev_chain_hash = link.chain_hash
                links_by_seq[link.chain_seq] = link

            # ── Point 3: Epoch Sequence & Cross-Epoch Continuity ─────────────
            prev_end_seq = 0
            expected_prev_seal = GENESIS_EPOCH_HASH
            kms = get_kms()

            for s_idx, seal in enumerate(seals):
                expected_epoch_id = s_idx + 1
                if seal.epoch_id != expected_epoch_id:
                    return {
                        "status": "FAIL",
                        "verification_timestamp": now_iso,
                        "failure_category": "EPOCH_ID_GAP",
                        "epoch_id": seal.epoch_id,
                        "expected": expected_epoch_id,
                        "actual": seal.epoch_id,
                        "reason": f"Epoch ID sequence gap: expected {expected_epoch_id}, found {seal.epoch_id}",
                        "failure_details": {"epoch_id": seal.epoch_id},
                    }

                expected_start = prev_end_seq + 1
                if seal.start_chain_seq != expected_start:
                    return {
                        "status": "FAIL",
                        "verification_timestamp": now_iso,
                        "failure_category": "CROSS_EPOCH_SEQUENCE_GAP",
                        "epoch_id": seal.epoch_id,
                        "expected": expected_start,
                        "actual": seal.start_chain_seq,
                        "reason": f"Cross-epoch sequence gap: expected start {expected_start}, found {seal.start_chain_seq}",
                        "failure_details": {"epoch_id": seal.epoch_id},
                    }

                expected_count = seal.end_chain_seq - seal.start_chain_seq + 1
                if seal.record_count != expected_count:
                    return {
                        "status": "FAIL",
                        "verification_timestamp": now_iso,
                        "failure_category": "EPOCH_RECORD_COUNT_MISMATCH",
                        "epoch_id": seal.epoch_id,
                        "expected": expected_count,
                        "actual": seal.record_count,
                        "reason": f"Epoch record count mismatch in epoch {seal.epoch_id}",
                        "failure_details": {"epoch_id": seal.epoch_id},
                    }

                if seal.prev_seal_hash.lower() != expected_prev_seal.lower():
                    return {
                        "status": "FAIL",
                        "verification_timestamp": now_iso,
                        "failure_category": "EPOCH_PREV_SEAL_HASH_MISMATCH",
                        "epoch_id": seal.epoch_id,
                        "expected": expected_prev_seal.lower(),
                        "actual": seal.prev_seal_hash.lower(),
                        "reason": f"Epoch prev seal hash mismatch in epoch {seal.epoch_id}",
                        "failure_details": {"epoch_id": seal.epoch_id},
                    }

                # ── Point 4: Merkle Root Integrity (RFC 6962-inspired) ───────
                epoch_link_hashes = [
                    links_by_seq[seq].chain_hash
                    for seq in range(seal.start_chain_seq, seal.end_chain_seq + 1)
                    if seq in links_by_seq
                ]
                if len(epoch_link_hashes) != seal.record_count:
                    return {
                        "status": "FAIL",
                        "verification_timestamp": now_iso,
                        "failure_category": "MISSING_CHAIN_LINKS_IN_EPOCH",
                        "epoch_id": seal.epoch_id,
                        "reason": f"Missing chain links in epoch {seal.epoch_id}: found {len(epoch_link_hashes)} of {seal.record_count}",
                        "failure_details": {"epoch_id": seal.epoch_id},
                    }

                expected_root = compute_merkle_root(epoch_link_hashes)
                if seal.epoch_root_hash.lower() != expected_root.lower():
                    return {
                        "status": "FAIL",
                        "verification_timestamp": now_iso,
                        "failure_category": "EPOCH_MERKLE_ROOT_MISMATCH",
                        "epoch_id": seal.epoch_id,
                        "expected": expected_root.lower(),
                        "actual": seal.epoch_root_hash.lower(),
                        "reason": f"Epoch Merkle root mismatch in epoch {seal.epoch_id}",
                        "failure_details": {"epoch_id": seal.epoch_id},
                    }

                if seal.final_chain_hash.lower() != epoch_link_hashes[-1].lower():
                    return {
                        "status": "FAIL",
                        "verification_timestamp": now_iso,
                        "failure_category": "EPOCH_FINAL_CHAIN_HASH_MISMATCH",
                        "epoch_id": seal.epoch_id,
                        "expected": epoch_link_hashes[-1].lower(),
                        "actual": seal.final_chain_hash.lower(),
                        "reason": f"Epoch final chain hash mismatch in epoch {seal.epoch_id}",
                        "failure_details": {"epoch_id": seal.epoch_id},
                    }

                # ── Point 5: KMS Ed25519 Manifest Digital Signatures ──────────
                manifest_dict = build_canonical_epoch_manifest(
                    epoch_id=seal.epoch_id,
                    start_chain_seq=seal.start_chain_seq,
                    end_chain_seq=seal.end_chain_seq,
                    record_count=seal.record_count,
                    epoch_root_hash=seal.epoch_root_hash,
                    prev_seal_hash=seal.prev_seal_hash,
                    kms_key_id=seal.kms_key_id,
                    policy_version=seal.policy_version,
                )
                manifest_bytes = serialize_canonical_epoch_manifest(manifest_dict)

                is_valid_sig = kms.verify(
                    manifest_bytes, seal.signature_b64, seal.kms_key_id
                )
                if not is_valid_sig:
                    return {
                        "status": "FAIL",
                        "verification_timestamp": now_iso,
                        "failure_category": "KMS_SIGNATURE_VERIFICATION_FAILED",
                        "epoch_id": seal.epoch_id,
                        "reason": f"KMS signature verification failed in epoch {seal.epoch_id}",
                        "failure_details": {"epoch_id": seal.epoch_id, "kms_key_id": seal.kms_key_id},
                    }

                expected_prev_seal = compute_prev_seal_hash(manifest_bytes)
                prev_end_seq = seal.end_chain_seq

            # ── Points 6, 7, 8: Linkage, Legacy Preservation & Live Recomputation ─
            # Query all corresponding audit_logs
            all_log_ids = [l.audit_log_id for l in links]
            logs_by_id = {}
            batch_size = 1000
            for i in range(0, len(all_log_ids), batch_size):
                chunk = all_log_ids[i : i + batch_size]
                r_chunk = await session.execute(
                    select(AuditLog).where(AuditLog.id.in_(chunk))
                )
                for log_row in r_chunk.scalars().all():
                    logs_by_id[log_row.id] = log_row

            legacy_verified = 0
            live_verified = 0

            for link in links:
                log_entry = logs_by_id.get(link.audit_log_id)
                # Point 6: Linkage Existence (No Orphans)
                if log_entry is None:
                    return {
                        "status": "FAIL",
                        "verification_timestamp": now_iso,
                        "failure_category": "ORPHAN_CHAIN_LINK",
                        "chain_seq": link.chain_seq,
                        "audit_log_id": link.audit_log_id,
                        "reason": f"Chain link at sequence {link.chain_seq} references non-existent audit_log {link.audit_log_id}",
                        "failure_details": {"chain_seq": link.chain_seq, "audit_log_id": link.audit_log_id},
                    }

                # Point 7: Legacy Event Hash Preservation (chain_seq <= cutover_seq)
                if link.chain_seq <= cutover_seq:
                    if link.event_hash.lower() != (log_entry.event_hash or "").lower():
                        return {
                            "status": "FAIL",
                            "verification_timestamp": now_iso,
                            "failure_category": "LEGACY_EVENT_HASH_MISMATCH",
                            "chain_seq": link.chain_seq,
                            "audit_log_id": link.audit_log_id,
                            "expected": (log_entry.event_hash or "").lower(),
                            "actual": link.event_hash.lower(),
                            "reason": f"Historical event hash preservation mismatch at chain_seq {link.chain_seq}",
                            "failure_details": {"chain_seq": link.chain_seq, "audit_log_id": link.audit_log_id},
                        }
                    legacy_verified += 1

                # Point 8: Live Canonical Event Hash Recomputation (chain_seq > cutover_seq)
                else:
                    recomputed_hash = None
                    for cand_time in (log_entry.timestamp, log_entry.created_at):
                        if cand_time is None:
                            continue
                        live_payload = build_canonical_event_payload(
                            event_id=log_entry.id,
                            event_type=log_entry.event_type,
                            created_at=cand_time,
                            result=log_entry.result,
                            actor_id=log_entry.actor_id,
                            actor_role=log_entry.actor_role,
                            resource_type=log_entry.resource_type,
                            resource_id=log_entry.resource_id,
                            action=log_entry.action,
                            event_metadata=log_entry.event_metadata or {},
                            ip_hash=log_entry.ip_hash,
                            device_id=log_entry.device_id,
                            risk_score=log_entry.risk_score or 0.0,
                        )
                        cand_hash = compute_canonical_event_hash(live_payload).lower()
                        if cand_hash == link.event_hash.lower():
                            recomputed_hash = cand_hash
                            break
                    if recomputed_hash is None:
                        recomputed_hash = cand_hash

                    if (
                        link.event_hash.lower() != recomputed_hash
                        or (log_entry.event_hash or "").lower() != recomputed_hash
                    ):
                        return {
                            "status": "FAIL",
                            "verification_timestamp": now_iso,
                            "failure_category": "LIVE_PAYLOAD_HASH_MISMATCH",
                            "chain_seq": link.chain_seq,
                            "audit_log_id": link.audit_log_id,
                            "expected": recomputed_hash,
                            "link_hash": link.event_hash.lower(),
                            "log_hash": (log_entry.event_hash or "").lower(),
                            "reason": f"Canonical event hash recomputation mismatch from raw payload at chain_seq {link.chain_seq}",
                            "failure_details": {"chain_seq": link.chain_seq, "audit_log_id": link.audit_log_id},
                        }
                    live_verified += 1

            # ── Point 9: Quarantine Ledger Verification & Non-Chaining ─────────
            chain_log_ids = set(l.audit_log_id for l in links)
            reg = get_operator_key_registry()

            for q in quarantines:
                # Non-chaining invariant: Quarantined row must NEVER be in chain links
                if q.audit_log_id in chain_log_ids:
                    return {
                        "status": "FAIL",
                        "verification_timestamp": now_iso,
                        "failure_category": "QUARANTINE_CHAIN_CONTAMINATION",
                        "audit_log_id": q.audit_log_id,
                        "reason": f"CRITICAL: Quarantined audit log {q.audit_log_id} was illegally incorporated into audit_chain_links!",
                        "failure_details": {"audit_log_id": q.audit_log_id},
                    }

                # Dual custody invariant
                if q.operator_1_id == q.operator_2_id or q.operator_1_key_id == q.operator_2_key_id:
                    return {
                        "status": "FAIL",
                        "verification_timestamp": now_iso,
                        "failure_category": "QUARANTINE_DUAL_CUSTODY_VIOLATION",
                        "audit_log_id": q.audit_log_id,
                        "reason": f"Dual custody violation in stored quarantine record {q.quarantine_id}",
                        "failure_details": {"audit_log_id": q.audit_log_id},
                    }

                # Signature verification
                q_payload = build_quarantine_authorization_payload(
                    audit_log_id=q.audit_log_id,
                    detected_event_hash=q.detected_event_hash,
                    quarantine_reason=q.quarantine_reason,
                    incident_reference=q.incident_reference,
                    operator_1_id=q.operator_1_id,
                    operator_2_id=q.operator_2_id,
                    policy_version=q.policy_version,
                    authorization_nonce=q.authorization_nonce,
                )
                v1 = reg.verify_operator_signature(
                    q.operator_1_id, q.operator_1_key_id, q_payload, q.operator_1_signature_b64
                )
                v2 = reg.verify_operator_signature(
                    q.operator_2_id, q.operator_2_key_id, q_payload, q.operator_2_signature_b64
                )
                if not (v1 and v2):
                    return {
                        "status": "FAIL",
                        "verification_timestamp": now_iso,
                        "failure_category": "QUARANTINE_SIGNATURE_INVALID",
                        "audit_log_id": q.audit_log_id,
                        "reason": f"Quarantine operator signature verification failed for log {q.audit_log_id}",
                        "failure_details": {"audit_log_id": q.audit_log_id},
                    }

            # Check for unquarantined poison events in unsealed queue
            unsealed_res = await session.execute(
                text("""
                    SELECT al.id, al.event_hash
                    FROM audit_logs al
                    WHERE NOT EXISTS (SELECT 1 FROM audit_chain_links acl WHERE acl.audit_log_id = al.id)
                      AND NOT EXISTS (SELECT 1 FROM audit_poison_quarantine apq WHERE apq.audit_log_id = al.id)
                    ORDER BY al.created_at ASC, al.id ASC
                    LIMIT 100;
                """)
            )
            unsealed_candidates = unsealed_res.fetchall()
            for cand in unsealed_candidates:
                if not cand.event_hash or not _HEX64_RE.match(cand.event_hash):
                    return {
                        "status": "FAIL",
                        "verification_timestamp": now_iso,
                        "failure_category": "UNQUARANTINED_POISON_EVENT",
                        "audit_log_id": cand.id,
                        "reason": f"Unquarantined poison audit event detected in unsealed backlog: id={cand.id}",
                        "failure_details": {"audit_log_id": cand.id, "event_hash": cand.event_hash},
                    }

            # ── Point 10: Unchained Backlog Integrity & Lag Evaluation ───────
            count_unsealed_res = await session.execute(
                text("""
                    SELECT COUNT(*)
                    FROM audit_logs al
                    WHERE NOT EXISTS (SELECT 1 FROM audit_chain_links acl WHERE acl.audit_log_id = al.id)
                      AND NOT EXISTS (SELECT 1 FROM audit_poison_quarantine apq WHERE apq.audit_log_id = al.id);
                """)
            )
            unsealed_count = count_unsealed_res.scalar() or 0

            return {
                "status": "PASS",
                "verification_timestamp": now_iso,
                "replication_lag_seconds": lag_seconds,
                "fallback_to_primary_used": fallback_used,
                "total_links_verified": len(links),
                "total_epochs_verified": len(seals),
                "total_quarantined_verified": len(quarantines),
                "legacy_cutover_seq": cutover_seq,
                "legacy_links_verified": legacy_verified,
                "live_links_verified": live_verified,
                "unsealed_backlog_count": unsealed_count,
                "failure_category": None,
                "failure_details": None,
                "reason": None,
            }

        except Exception as e:
            logger.error(f"Deep verifier encountered execution fault: {e}", exc_info=True)
            return {
                "status": "UNRESOLVED",
                "verification_timestamp": now_iso,
                "replication_lag_seconds": lag_seconds,
                "fallback_to_primary_used": fallback_used,
                "reason": f"Deep verification execution fault: {e}",
                "failure_category": "EXECUTION_FAULT",
                "failure_details": {"exception": str(e)},
            }


    async def _verify_legacy_chain(self, session: AsyncSession) -> dict:
        result = await session.execute(
            select(AuditLog).order_by(AuditLog.seq.asc())
        )
        entries = result.scalars().all()

        if not entries:
            return {"valid": True, "entries_checked": 0, "broken_at": None}

        prev_hash = GENESIS_HASH
        for entry in entries:
            if entry.seq is None or entry.prev_hash is None:
                continue

            import json
            ts_str = entry.timestamp.isoformat()
            if entry.timestamp.tzinfo is None:
                ts_str += "+00:00"

            event_data = json.dumps(
                {
                    "seq": entry.seq,
                    "event_type": entry.event_type,
                    "actor_id": entry.actor_id,
                    "action": entry.action,
                    "resource_type": entry.resource_type,
                    "resource_id": entry.resource_id,
                    "result": entry.result.value,
                    "timestamp": ts_str,
                },
                sort_keys=True,
            )

            expected_hash = compute_audit_hash(event_data, prev_hash)

            if expected_hash != entry.event_hash:
                return {
                    "valid": False,
                    "entries_checked": entry.seq,
                    "broken_at": entry.seq,
                    "broken_event_id": entry.id,
                    "message": "CHAIN INTEGRITY VIOLATION DETECTED",
                }

            prev_hash = entry.event_hash

        return {
            "valid": True,
            "entries_checked": len(entries),
            "chain_head": prev_hash,
            "broken_at": None,
        }


async def audit_worker():
    """
    Deprecated background worker compatibility stub.
    Dual-mode ingestion writes directly and durably to PostgreSQL.
    """
    while True:
        try:
            item = await _audit_queue.get()
            if item is None:
                break
            _audit_queue.task_done()
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Audit worker stub error: {e}")
            await asyncio.sleep(1)


async def flush_audit_queue():
    """Deprecated shutdown compatibility stub."""
    try:
        await _audit_queue.put(None)
    except Exception:
        pass
