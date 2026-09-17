"""
B-SEA Phase 3C-5D: Security Incident Management ?" Threat Vector Identity
Conforming to BSEA_PHASE3C_5D_SECURITY_INCIDENT_MANAGEMENT_ARCHITECTURE_REVIEW_REV06.md Section 7.

Threat vector identity calculation is:
  threat_vector_key = SHA-256(JCS(D))
where D is a normalized dictionary of exactly 4 keys:
  - canonical_rule_id
  - dimensions
  - exam_id
  - policy_version

Strict Invariants:
  - ZERO temporal parameters (timestamps, generations, correlation windows, incident IDs).
  - RFC 8785 JCS byte-level deterministic serialization.
  - Strict stripping of null/empty/whitespace-only dimension keys; dimension set cannot be empty.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import uuid
from typing import Any, Dict, Optional, Set

from app.modules.incidents.exceptions import TemporalIdentityError, InvalidDimensionError

FORBIDDEN_TEMPORAL_KEYS: Set[str] = {
    "timestamp",
    "generation",
    "window",
    "time",
    "detected_at",
    "created_at",
    "updated_at",
    "first_seen_at",
    "latest_seen_at",
    "first_signal_at",
    "latest_signal_at",
    "window_seconds",
    "time_window_seconds",
    "incident_id",
    "incident_number",
    "event_count",
    "dedup_count",
}


def normalize_dimension_value(key: str, val: Any) -> str:
    """Normalize dimension value according to Rev-06 Section 7.3 semantic typing rules."""
    if val is None:
        return ""
    s_val = str(val).strip()
    if not s_val:
        return ""

    # Check for IP address (IPv4/IPv6 canonical exploded notation)
    try:
        ip = ipaddress.ip_address(s_val)
        return ip.exploded
    except ValueError:
        pass

    # Check for UUID (canonical lowercase hyphenated)
    try:
        u = uuid.UUID(s_val)
        return str(u).lower()
    except (ValueError, AttributeError):
        pass

    # Standard identifier: trimmed uppercase
    return s_val.upper()


def normalize_dimensions(raw_dims: Dict[str, Any]) -> Dict[str, str]:
    """
    Validate and normalize dimension dictionary according to Rev-06 Section 7.3.
    Rejects temporal keys, validates key regex ^[a-z][a-z0-9_]*$,
    strips empty/null/whitespace-only values, and ensures dimensions set is non-empty.
    """
    if not raw_dims or not isinstance(raw_dims, dict):
        raise InvalidDimensionError("A dimension set cannot be empty.")

    normalized: Dict[str, str] = {}
    for k, v in raw_dims.items():
        k_clean = str(k).strip().lower()

        # Guard against temporal contamination
        if k_clean in FORBIDDEN_TEMPORAL_KEYS:
            raise TemporalIdentityError(
                f"Temporal key '{k_clean}' is strictly forbidden in threat vector identity."
            )

        if not re.match(r"^[a-z][a-z0-9_]*$", k_clean):
            raise InvalidDimensionError(
                f"Invalid dimension key '{k}'. Must match ^[a-z][a-z0-9_]*$"
            )

        v_clean = normalize_dimension_value(k_clean, v)
        # Empty/null values are strictly stripped prior to canonicalization
        if v_clean:
            normalized[k_clean] = v_clean

    if not normalized:
        raise InvalidDimensionError(
            "A dimension set cannot be empty after stripping null/empty values."
        )

    return normalized


def normalize_canonical_rule_id(rule_id: str) -> str:
    """Trim, uppercase, and strip version suffixes from rule ID."""
    if not rule_id or not isinstance(rule_id, str):
        raise ValueError("canonical_rule_id cannot be empty.")
    clean = rule_id.strip().upper()
    # Strip trailing patch or version suffixes like .V1, .V2, -V1
    clean = re.sub(r"[.-]V\d+$", "", clean)
    if not clean:
        raise ValueError("canonical_rule_id cannot be empty after normalization.")
    return clean


def normalize_exam_id(exam_id: Optional[str]) -> str:
    """Normalize exam_id: trimmed uppercase string, or 'GLOBAL' for cross-exam events."""
    if not exam_id or not str(exam_id).strip():
        return "GLOBAL"
    clean = str(exam_id).strip()
    if clean.upper() == "GLOBAL":
        return "GLOBAL"
    # Check if valid UUID
    try:
        u = uuid.UUID(clean)
        return str(u).lower()
    except ValueError:
        return clean.upper()


def normalize_policy_version(policy_version: Optional[str]) -> str:
    """Normalize policy version: trimmed lowercase string, defaulting to 'v1'."""
    if not policy_version or not str(policy_version).strip():
        return "v1"
    clean = str(policy_version).strip().lower()
    # If version has prefix like 'bsea-rules-v1' or 'v1.0.0', normalize to major version
    m = re.search(r"v\d+", clean)
    if m:
        return m.group(0)
    return clean


def serialize_jcs_document(doc: Dict[str, Any]) -> str:
    """
    RFC 8785 JSON Canonicalization Scheme (JCS) serialization.
    - Keys sorted lexicographically at all nesting levels.
    - Compact separators (',', ':') with zero extraneous whitespace.
    - Unicode characters preserved without escape sequences.
    """
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def generate_threat_vector_key(
    canonical_rule_id: str,
    dimensions: Dict[str, Any],
    exam_id: Optional[str] = None,
    policy_version: str = "v1",
) -> str:
    """
    Derive the authoritative, stable, time-independent SHA-256 threat vector identity.
    Conforms to Rev-06 Section 7.
    """
    norm_rule = normalize_canonical_rule_id(canonical_rule_id)
    norm_dims = normalize_dimensions(dimensions)
    norm_exam = normalize_exam_id(exam_id)
    norm_policy = normalize_policy_version(policy_version)

    doc = {
        "canonical_rule_id": norm_rule,
        "dimensions": norm_dims,
        "exam_id": norm_exam,
        "policy_version": norm_policy,
    }

    serialized = serialize_jcs_document(doc)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def derive_advisory_lock_key(threat_vector_key: str) -> int:
    """
    Derive a 64-bit signed integer lock key matching PostgreSQL:
    SELECT pg_advisory_xact_lock(('x' || substr(:threat_vector_key, 1, 16))::bit(64)::bigint);
    """
    if len(threat_vector_key) < 16:
        raise ValueError("threat_vector_key must be at least 16 hex characters.")
    hex_prefix = threat_vector_key[:16]
    unsigned_val = int(hex_prefix, 16)
    # Convert unsigned 64-bit to signed 64-bit integer
    if unsigned_val >= (1 << 63):
        signed_val = unsigned_val - (1 << 64)
    else:
        signed_val = unsigned_val
    return signed_val
