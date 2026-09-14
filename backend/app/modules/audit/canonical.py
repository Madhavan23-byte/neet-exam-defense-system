"""
B-SEA Canonical Audit Event Hashing and Cryptographic Primitives
Deterministic key-sorted compact JSON serialization following RFC 8785 principles
using Python's standard json implementation, 72-byte canonical chain hashing,
and RFC 6962 domain-separated binary Merkle trees.

Phase 3C-4B Authoritative Specification.
"""
from __future__ import annotations

import hashlib
import json
import re
import struct
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union

# Version of the canonical event schema
CANONICAL_EVENT_SCHEMA_VERSION = 1
CANONICAL_MANIFEST_SCHEMA_VERSION = 1
DEFAULT_POLICY_VERSION = "BSEA-AUDIT-v1"

# Standard B-SEA Genesis Constants (64 lowercase hexadecimal zeros)
GENESIS_CHAIN_HASH = "0" * 64
GENESIS_EPOCH_HASH = "0" * 64

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)


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
    """
    result_val = result.value if isinstance(result, Enum) else str(result)
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
    Deterministic key-sorted compact JSON serialization following RFC 8785 principles
    using Python's standard json implementation:
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


# ─────────────────────────────────────────────────────────────────────────────
# Phase 3C-4B Canonical Chain Hash Primitive
# ─────────────────────────────────────────────────────────────────────────────

def validate_hex64(val: str, name: str = "hash") -> str:
    """Validate that a string is a 64-character lowercase hexadecimal digest."""
    if not isinstance(val, str) or not _HEX64_RE.match(val):
        raise ValueError(f"{name} must be exactly 64 hexadecimal characters, got {val!r}")
    return val.lower()


def compute_canonical_chain_hash(
    prev_chain_hash_hex: str,
    event_hash_hex: str,
    chain_seq: int,
) -> str:
    """
    Compute authoritative SHA-256 chain hash for audit_chain_links.

    Exact 72-byte binary preimage:
      - 32 bytes: raw bytes of prev_chain_hash (decoded from 64-char hex)
      - 32 bytes: raw bytes of event_hash (decoded from 64-char hex)
      -  8 bytes: big-endian unsigned 64-bit integer of chain_seq (>Q)

    Returns:
      64-character lowercase hexadecimal SHA-256 digest.
    """
    prev_clean = validate_hex64(prev_chain_hash_hex, "prev_chain_hash")
    event_clean = validate_hex64(event_hash_hex, "event_hash")

    if not isinstance(chain_seq, int) or isinstance(chain_seq, bool) or chain_seq < 1:
        raise ValueError(f"chain_seq must be a positive non-zero integer >= 1, got {chain_seq!r}")

    prev_bytes = bytes.fromhex(prev_clean)
    event_bytes = bytes.fromhex(event_clean)
    seq_bytes = struct.pack(">Q", chain_seq)

    preimage = prev_bytes + event_bytes + seq_bytes  # Exactly 72 bytes
    if len(preimage) != 72:
        raise AssertionError(f"Preimage length must be exactly 72 bytes, got {len(preimage)}")

    return hashlib.sha256(preimage).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# RFC 6962 Domain-Separated Binary Merkle Tree
# ─────────────────────────────────────────────────────────────────────────────

def compute_merkle_root(chain_hashes: List[str]) -> str:
    """
    Compute the RFC 6962-compliant domain-separated binary Merkle root hash.

    Algorithm:
      1. Leaf hash:
         leaf_hash = SHA-256(0x00 || chain_hash_bytes)   (33 bytes preimage)
      2. Parent hash:
         parent_hash = SHA-256(0x01 || left_child_bytes || right_child_bytes) (65 bytes preimage)
      3. If a level contains an odd number of nodes (> 1), duplicate the final node.
      4. Single-link epoch (N=1): Merkle root is defined strictly as its leaf hash.
      5. Empty epoch (N=0): Forbidden. Raises ValueError.

    Returns:
      64-character lowercase hexadecimal SHA-256 root digest.
    """
    if not chain_hashes:
        raise ValueError("Cannot compute Merkle root of an empty list of chain hashes")

    # Step 1: Compute leaf nodes with 0x00 domain separator
    current_level: List[bytes] = []
    for idx, h in enumerate(chain_hashes):
        clean_h = validate_hex64(h, f"chain_hashes[{idx}]")
        leaf_bytes = bytes.fromhex(clean_h)
        leaf_hash = hashlib.sha256(b"\x00" + leaf_bytes).digest()
        current_level.append(leaf_hash)

    # Single-link epoch: Merkle root = its leaf hash
    if len(current_level) == 1:
        return current_level[0].hex()

    # Step 2: Build tree upwards with 0x01 domain separator
    while len(current_level) > 1:
        next_level: List[bytes] = []
        if len(current_level) % 2 == 1:
            current_level.append(current_level[-1])

        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1]
            parent_hash = hashlib.sha256(b"\x01" + left + right).digest()
            next_level.append(parent_hash)

        current_level = next_level

    return current_level[0].hex()


# ─────────────────────────────────────────────────────────────────────────────
# Canonical Epoch Manifest & Previous Seal Hashing
# ─────────────────────────────────────────────────────────────────────────────

def build_canonical_epoch_manifest(
    epoch_id: int,
    start_chain_seq: int,
    end_chain_seq: int,
    record_count: int,
    epoch_root_hash: str,
    prev_seal_hash: str,
    kms_key_id: str,
    manifest_version: int = CANONICAL_MANIFEST_SCHEMA_VERSION,
    policy_version: str = DEFAULT_POLICY_VERSION,
) -> Dict[str, Any]:
    """
    Construct the authoritative dictionary of fields participating in the
    canonical epoch manifest for KMS Ed25519 digital signing.

    Exact Participating Fields (9 total):
      1. manifest_version (int)
      2. policy_version (str)
      3. epoch_id (int)
      4. start_chain_seq (int)
      5. end_chain_seq (int)
      6. record_count (int)
      7. epoch_root_hash (str: 64 hex)
      8. prev_seal_hash (str: 64 hex)
      9. kms_key_id (str: exact KMS key ARN)

    Note: Dynamic retry timestamps are STRICTLY EXCLUDED to ensure
    byte-for-byte reproducibility during crash recovery.
    """
    if not isinstance(epoch_id, int) or isinstance(epoch_id, bool) or epoch_id < 1:
        raise ValueError(f"epoch_id must be an integer >= 1, got {epoch_id!r}")
    if not isinstance(start_chain_seq, int) or isinstance(start_chain_seq, bool) or start_chain_seq < 1:
        raise ValueError(f"start_chain_seq must be an integer >= 1, got {start_chain_seq!r}")
    if not isinstance(end_chain_seq, int) or isinstance(end_chain_seq, bool) or end_chain_seq < start_chain_seq:
        raise ValueError(f"end_chain_seq must be >= start_chain_seq, got {end_chain_seq!r}")
    expected_count = end_chain_seq - start_chain_seq + 1
    if record_count != expected_count:
        raise ValueError(
            f"record_count mismatch: got {record_count}, expected {expected_count} "
            f"(end_chain_seq - start_chain_seq + 1)"
        )

    clean_root = validate_hex64(epoch_root_hash, "epoch_root_hash")
    clean_prev = validate_hex64(prev_seal_hash, "prev_seal_hash")

    if not kms_key_id or not isinstance(kms_key_id, str) or not kms_key_id.strip():
        raise ValueError("kms_key_id must be a non-empty string representing the exact KMS Key ARN")

    return {
        "manifest_version": int(manifest_version),
        "policy_version": str(policy_version),
        "epoch_id": int(epoch_id),
        "start_chain_seq": int(start_chain_seq),
        "end_chain_seq": int(end_chain_seq),
        "record_count": int(record_count),
        "epoch_root_hash": clean_root,
        "prev_seal_hash": clean_prev,
        "kms_key_id": str(kms_key_id).strip(),
    }


def serialize_canonical_epoch_manifest(manifest_dict: Dict[str, Any]) -> bytes:
    """
    Serialize canonical epoch manifest into deterministic UTF-8 bytes following
    RFC 8785 principles using standard json implementation.
    """
    return json.dumps(
        manifest_dict,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def compute_prev_seal_hash(previous_manifest: Union[Dict[str, Any], bytes]) -> str:
    """
    Compute SHA-256 digest of previous epoch's canonical manifest bytes.
    Strictly EXCLUDES digital signature (signature is verified separately).
    Accepts either the previous canonical manifest dictionary or pre-serialized bytes.
    """
    if isinstance(previous_manifest, bytes):
        manifest_bytes = previous_manifest
    else:
        manifest_bytes = serialize_canonical_epoch_manifest(previous_manifest)
    return hashlib.sha256(manifest_bytes).hexdigest()


# Alias for naming consistency across Phase 3C-4B specifications
compute_canonical_event_hash = compute_event_hash


def get_kms_signing_key_id(kms: Any) -> str:
    """
    Extract the active asymmetric signing key ID / ARN from a KMS provider.
    Works for both AWSKMSProvider and MockKMS.
    """
    if hasattr(kms, "_signing_key_id") and kms._signing_key_id:
        return str(kms._signing_key_id)
    if hasattr(kms, "_key_id") and kms._key_id:
        return str(kms._key_id)
    if hasattr(kms, "key_id") and kms.key_id:
        return str(kms.key_id)
    return "mock-kms-key-001"
