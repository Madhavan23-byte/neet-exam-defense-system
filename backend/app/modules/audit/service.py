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
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import AsyncSessionLocal
from app.core.models import (
    AuditChainLink,
    AuditEpochSeal,
    AuditLog,
    AuditResult,
    new_uuid,
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
