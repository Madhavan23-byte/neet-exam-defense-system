"""
B-SEA Phase 3C-5E: Containment Identity & Canonicalization Engine
Conforming strictly to docs/BSEA_PHASE3C5E_ARCHITECTURE_REV04_1.md Section 5.

Implements the 4-tier decoupled identity architecture:
1. IntentKey: SHA-256(incident_id || generation || action_type || canonical_target_urn)
   - Strictly INDEPENDENT of RequesterID.
2. RequestKey: SHA-256(intent_key || requester_id || request_nonce || timestamp)
3. AuthNonce / BreakGlassNonce: 256-bit cryptographically secure pseudorandom hex.
4. ExecutionRunId: UUIDv4 per physical execution attempt.
   - Generates ExternalOperationID = SHA-256(ExecutionRunId || IntentKey).
"""
from __future__ import annotations

import hashlib
import json
import secrets
import unicodedata
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Union, Optional, List

from app.modules.containment.models import ContainmentActionType


def jcs_canonicalize(obj: Any) -> str:
    """
    RFC 8785 JSON Canonicalization Scheme (JCS) deterministic serialization.
    - Keys sorted lexicographically by UTF-16 code units.
    - No whitespace between tokens.
    - Unicode NFC normalization.
    """
    if isinstance(obj, dict):
        items = []
        for k in sorted(obj.keys()):
            val = obj[k]
            norm_k = unicodedata.normalize("NFC", str(k))
            items.append(f"{json.dumps(norm_k, ensure_ascii=False)}:{jcs_canonicalize(val)}")
        return "{" + ",".join(items) + "}"
    elif isinstance(obj, list):
        items = [jcs_canonicalize(x) for x in obj]
        return "[" + ",".join(items) + "]"
    elif isinstance(obj, str):
        norm_s = unicodedata.normalize("NFC", obj)
        return json.dumps(norm_s, ensure_ascii=False)
    elif isinstance(obj, bool):
        return "true" if obj else "false"
    elif obj is None:
        return "null"
    elif isinstance(obj, (int, float)):
        return json.dumps(obj)
    else:
        return json.dumps(str(obj), ensure_ascii=False)


def canonicalize_target_urn(target_type: Union[str, ContainmentActionType], target_id: Union[str, Dict[str, Any]]) -> str:
    """
    Generate canonical target URN in lowercase with NFC normalization.
    Supports both string IDs and target parameter dictionaries.
    e.g. urn:bsea:session:cand_sess_1234
    """
    type_str = target_type.value if isinstance(target_type, ContainmentActionType) else str(target_type)
    
    # Map action types to concise resource types
    if "session" in type_str.lower():
        res_type = "session"
    elif "acct" in type_str.lower() or "user" in type_str.lower():
        res_type = "user"
    elif "centre" in type_str.lower():
        res_type = "centre"
    elif "form" in type_str.lower():
        res_type = "form"
    elif "q_" in type_str.lower() or "question" in type_str.lower():
        res_type = "question"
    elif "crypto" in type_str.lower():
        res_type = "key"
    else:
        res_type = type_str.lower()

    if isinstance(target_id, dict):
        found_id = None
        for k in ["session_id", "candidate_session_id", "user_id", "question_id", "centre_id", "form_id", "key_id", "target_id", "id"]:
            if k in target_id:
                found_id = str(target_id[k])
                break
        if not found_id:
            for v in target_id.values():
                if isinstance(v, (str, int)):
                    found_id = str(v)
                    break
        clean_id = unicodedata.normalize("NFC", (found_id or "default").strip().lower())
    else:
        clean_id = unicodedata.normalize("NFC", str(target_id).strip().lower())

    clean_type = unicodedata.normalize("NFC", res_type.strip().lower())
    return f"urn:bsea:{clean_type}:{clean_id}"


def compute_intent_key(*args, **kwargs) -> str:
    """
    Compute Tier 1 IntentKey.
    SHA-256(incident_id || generation || action_type || canonical_target_urn)
    CRITICAL INVARIANT: RequesterID is strictly excluded.
    """
    action_type = None
    canonical_target_urn = None
    incident_id = None
    generation = None

    # Positional args inspection
    if len(args) == 4:
        if isinstance(args[0], ContainmentActionType) or (isinstance(args[0], str) and args[0].startswith("ACT_")):
            action_type = args[0]
            canonical_target_urn = args[1]
            incident_id = args[2]
            generation = args[3]
        else:
            incident_id = args[0]
            generation = args[1]
            action_type = args[2]
            canonical_target_urn = args[3]

    # Keyword overrides
    if "action_type" in kwargs:
        action_type = kwargs["action_type"]
    if "canonical_target_urn" in kwargs:
        canonical_target_urn = kwargs["canonical_target_urn"]
    if "incident_id" in kwargs:
        incident_id = kwargs["incident_id"]
    if "generation" in kwargs:
        generation = kwargs["generation"]
    elif "incident_generation" in kwargs:
        generation = kwargs["incident_generation"]

    act_str = action_type.value if isinstance(action_type, ContainmentActionType) else str(action_type or "")
    payload = {
        "action_type": act_str.strip(),
        "canonical_target_urn": str(canonical_target_urn or "").strip().lower(),
        "generation": int(generation or 1),
        "incident_id": str(incident_id or "").strip().lower(),
    }
    jcs_str = jcs_canonicalize(payload)
    return hashlib.sha256(jcs_str.encode("utf-8")).hexdigest()


def compute_request_key(
    intent_key: str,
    requester_id: str,
    request_nonce: Optional[str] = None,
    timestamp_iso: Optional[str] = None,
    *,
    request_time: Optional[Any] = None,
    **kwargs,
) -> str:
    """
    Compute Tier 2 RequestKey.
    SHA-256(intent_key || requester_id || request_nonce || timestamp)
    """
    nonce = request_nonce or kwargs.get("nonce") or generate_crypto_nonce()
    t = timestamp_iso or (request_time.isoformat() if hasattr(request_time, "isoformat") else None)
    if not t:
        t = datetime.now(timezone.utc).isoformat()
    payload = {
        "intent_key": str(intent_key).strip().lower(),
        "request_nonce": str(nonce).strip().lower(),
        "requester_id": str(requester_id).strip().lower(),
        "timestamp": str(t).strip(),
    }
    jcs_str = jcs_canonicalize(payload)
    return hashlib.sha256(jcs_str.encode("utf-8")).hexdigest()


def compute_scope_hash(scope_dict: Dict[str, Any]) -> str:
    """Compute SHA-256 hash over canonical JCS scope dictionary."""
    jcs_str = jcs_canonicalize(scope_dict)
    return hashlib.sha256(jcs_str.encode("utf-8")).hexdigest()


def compute_target_snapshot_hash(target_snapshot_dict: Dict[str, Any]) -> str:
    """Compute SHA-256 hash over canonical target state snapshot."""
    jcs_str = jcs_canonicalize(target_snapshot_dict)
    return hashlib.sha256(jcs_str.encode("utf-8")).hexdigest()


def compute_policy_fingerprint(*args, **kwargs) -> str:
    """Compute SHA-256 policy fingerprint from policy version and risk parameters."""
    parts = [str(x.value if hasattr(x, "value") else x) for x in args if x is not None]
    for k in sorted(kwargs.keys()):
        v = kwargs[k]
        if v is not None:
            parts.append(str(v.value if hasattr(v, "value") else v))
    raw = ":".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def compute_external_operation_id(*args, **kwargs) -> str:
    """
    Generate deterministic ExternalOperationID for idempotent subsystem dispatch.
    SHA-256(execution_run_id || intent_key)
    """
    parts = [str(x.value if hasattr(x, "value") else x) for x in args if x is not None]
    for k in sorted(kwargs.keys()):
        v = kwargs[k]
        if v is not None:
            parts.append(str(v.value if hasattr(v, "value") else v))
    raw = ":".join(parts)
    hash_val = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return hash_val


def generate_crypto_nonce() -> str:
    """Generate 256-bit cryptographically secure pseudorandom hex string."""
    return secrets.token_hex(32)
