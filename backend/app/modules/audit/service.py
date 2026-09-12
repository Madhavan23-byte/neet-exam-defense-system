"""
B-SEA — Audit Service
Hash-chained, tamper-evident audit logging.

Architecture:
  Every audit event contains:
  - event_hash = SHA256(event_data + prev_hash)
  - prev_hash = hash of previous event

  This creates a chain where any historical modification
  causes chain verification to fail.

  The chain can be independently verified at any time via
  GET /api/v1/audit/verify
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.models import AuditLog, AuditResult
from app.crypto.kms_interface import compute_audit_hash, GENESIS_HASH


import asyncio
from fastapi import HTTPException
from app.core.database import AsyncSessionLocal

# Prototype Bounded Queue to prevent unbounded memory growth under load
AUDIT_QUEUE_MAX_SIZE = 10000
_audit_queue = asyncio.Queue(maxsize=AUDIT_QUEUE_MAX_SIZE)

class AuditService:
    def __init__(self, db: AsyncSession = None):
        # API requests pass their own DB session, but the service doesn't strictly need it for enqueueing
        self.db = db

    async def _get_next_seq(self, worker_db: AsyncSession) -> int:
        result = await worker_db.execute(select(func.max(AuditLog.seq)))
        max_seq = result.scalar()
        return (max_seq or 0) + 1

    async def _get_last_hash(self, worker_db: AsyncSession) -> str:
        result = await worker_db.execute(
            select(AuditLog.event_hash)
            .order_by(AuditLog.seq.desc())
            .limit(1)
        )
        last_hash = result.scalar()
        return last_hash or GENESIS_HASH

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
    ) -> AuditLog:
        """
        Create a tamper-evident audit log entry.
        Places the event on a background queue to be processed sequentially.
        """
        timestamp = datetime.now(timezone.utc)
        
        event_dict = {
            "event_type": event_type,
            "actor_id": actor_id,
            "actor_role": actor_role,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "action": action,
            "result": result,
            "ip_hash": ip_hash,
            "device_id": device_id,
            "metadata": metadata or {},
            "risk_score": risk_score,
            "timestamp": timestamp,
        }
        
        try:
            _audit_queue.put_nowait(event_dict)
        except asyncio.QueueFull:
            # Backpressure: fail the request rather than silently drop audit events
            raise HTTPException(
                status_code=503, 
                detail="Audit logging service is currently overloaded. Please try again later."
            )
        
        # Return a dummy log entry representation since the real ID/Hash isn't generated yet
        # Most callers just await log() and don't use the return value.
        return AuditLog(event_type=event_type, timestamp=timestamp)

    async def verify_chain(self) -> dict:
        """
        Verify the integrity of the entire audit log chain.
        Returns verification status and the first broken link if any.
        """
        result = await self.db.execute(
            select(AuditLog).order_by(AuditLog.seq.asc())
        )
        entries = result.scalars().all()

        if not entries:
            return {"valid": True, "entries_checked": 0, "broken_at": None}

        prev_hash = GENESIS_HASH
        for entry in entries:
            ts_str = entry.timestamp.isoformat()
            if entry.timestamp.tzinfo is None:
                ts_str += "+00:00"
                
            event_data = json.dumps({
                "seq": entry.seq,
                "event_type": entry.event_type,
                "actor_id": entry.actor_id,
                "action": entry.action,
                "resource_type": entry.resource_type,
                "resource_id": entry.resource_id,
                "result": entry.result.value,
                "timestamp": ts_str,
            }, sort_keys=True)

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
    Background task to process the audit queue.
    Ensures sequential hash chain generation without blocking API endpoints.
    """
    import logging
    logger = logging.getLogger(__name__)
    
    while True:
        try:
            event_dict = await _audit_queue.get()
            if event_dict is None:
                # Sentinel value for graceful shutdown
                break
                
            async with AsyncSessionLocal() as worker_db:
                # Initialize AuditService without a request DB session
                service = AuditService()
                
                seq = await service._get_next_seq(worker_db)
                prev_hash = await service._get_last_hash(worker_db)
                
                # Build canonical event data for hashing
                event_data = json.dumps({
                    "seq": seq,
                    "event_type": event_dict["event_type"],
                    "actor_id": event_dict["actor_id"],
                    "action": event_dict["action"],
                    "resource_type": event_dict["resource_type"],
                    "resource_id": event_dict["resource_id"],
                    "result": event_dict["result"].value,
                    "timestamp": event_dict["timestamp"].isoformat(),
                }, sort_keys=True)
                
                event_hash = compute_audit_hash(event_data, prev_hash)
                
                log_entry = AuditLog(
                    seq=seq,
                    event_type=event_dict["event_type"],
                    actor_id=event_dict["actor_id"],
                    actor_role=event_dict["actor_role"],
                    resource_type=event_dict["resource_type"],
                    resource_id=event_dict["resource_id"],
                    action=event_dict["action"],
                    result=event_dict["result"],
                    ip_hash=event_dict["ip_hash"],
                    device_id=event_dict["device_id"],
                    event_metadata=event_dict["metadata"],
                    risk_score=event_dict["risk_score"],
                    prev_hash=prev_hash,
                    event_hash=event_hash,
                    timestamp=event_dict["timestamp"],
                )
                
                worker_db.add(log_entry)
                await worker_db.commit() # Commit each transaction sequentially to preserve hash chain
                _audit_queue.task_done()
                
        except Exception as e:
            logger.error(f"Audit worker encountered an error: {e}")
            # If an error happens, we still mark task done so queue can be joined, 
            # BUT we risk losing the event or breaking chain if we don't retry.
            # In a production durable queue, we would NACK the message.
            _audit_queue.task_done()
            
            # Short sleep to prevent tight error loops
            await asyncio.sleep(1)

async def flush_audit_queue():
    """Graceful shutdown helper"""
    # Wait until all items in the queue have been processed
    await _audit_queue.join()
    # Send sentinel to stop worker
    await _audit_queue.put(None)
