"""
B-SEA Canonical Audit Event Hashing
Deterministic key-sorted compact UTF-8 JSON serialization following RFC 8785 principles using Python's standard JSON implementation and SHA-256 hashing.

Phase 3C-4A: Append-only database foundation.
The event hash is computed strictly over the immutable event attributes known
at row insertion time. It NEVER depends on sealer-assigned sequence numbers,
chain hashes, or mutable database attributes.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional

# Version of the canonical event schema
CANONICAL_EVENT_SCHEMA_VERSION = 1


def format_canonical_timestamp(dt: datetime) -> str:
    """
    Format a datetime object into a normalized, ISO 8601 UTC timestamp string
    with explicit '+00:00' timezone designator and microsecond precision.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat()


def build_canonical_event_payload(
    event_id: str,
    event_type: str,
    created_at: datetime,
    result: Any,
    actor_id: Optional[str] = None,
    actor_role: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    action: Optional[str] = None,
    ip_hash: Optional[str] = None,
    device_id: Optional[str] = None,
    event_metadata: Optional[Dict[str, Any]] = None,
    risk_score: float = 0.0,
    trace_id: Optional[str] = None,
    kms_request_id: Optional[str] = None,
    version: int = CANONICAL_EVENT_SCHEMA_VERSION,
) -> Dict[str, Any]:
    """
    Construct the authoritative dictionary of fields participating in the
    canonical event representation.

    Exact Participating Fields (16 total):
      1.  version (int)
      2.  id (str)
      3.  event_type (str)
      4.  actor_id (str | None)
      5.  actor_role (str | None)
      6.  resource_type (str | None)
      7.  resource_id (str | None)
      8.  action (str | None)
      9.  result (str: 'SUCCESS' | 'FAILURE' | 'BLOCKED')
      10. ip_hash (str | None)
      11. device_id (str | None)
      12. event_metadata (dict)
      13. risk_score (float)
      14. trace_id (str | None)
      15. kms_request_id (str | None)
      16. created_at (str: ISO 8601 UTC)

    Excluded fields (Assigned later by AuditSealer / KMS):
      - chain_seq (assigned by sealer)
      - prev_chain_hash (assigned by sealer)
      - chain_hash (assigned by sealer)
      - link_id (assigned by sealer)
      - epoch_id (assigned by KMS epoch sealer)
    """
    # Normalize result if it is an Enum
    result_val = result.value if isinstance(result, Enum) else str(result)

    # Normalize metadata
    meta = event_metadata if event_metadata is not None else {}
    if not isinstance(meta, dict):
        raise TypeError(f"event_metadata must be a dictionary, got {type(meta).__name__}")

    return {
        "version": int(version),
        "id": str(event_id),
        "event_type": str(event_type),
        "actor_id": str(actor_id) if actor_id is not None else None,
        "actor_role": str(actor_role) if actor_role is not None else None,
        "resource_type": str(resource_type) if resource_type is not None else None,
        "resource_id": str(resource_id) if resource_id is not None else None,
        "action": str(action) if action is not None else None,
        "result": result_val,
        "ip_hash": str(ip_hash) if ip_hash is not None else None,
        "device_id": str(device_id) if device_id is not None else None,
        "event_metadata": meta,
        "risk_score": float(risk_score),
        "trace_id": str(trace_id) if trace_id is not None else None,
        "kms_request_id": str(kms_request_id) if kms_request_id is not None else None,
        "created_at": format_canonical_timestamp(created_at),
    }


def serialize_canonical_event(event_dict: Dict[str, Any]) -> str:
    """
    Deterministic key-sorted compact UTF-8 JSON serialization following RFC 8785 principles using Python's standard JSON implementation:
    - UTF-8 representation
    - Keys sorted lexicographically at all nesting levels
    - Compact separators without superfluous whitespace: (',', ':')
    - Unicode characters preserved without escape sequences (ensure_ascii=False)
    """
    return json.dumps(
        event_dict,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def compute_event_hash(event_dict: Dict[str, Any]) -> str:
    """
    Compute authoritative SHA-256 hex digest of the canonical event representation.
    Returns 64-character lowercase hex string.
    """
    serialized = serialize_canonical_event(event_dict)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
