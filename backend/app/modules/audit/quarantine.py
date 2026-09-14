"""
B-SEA Multi-Party Cryptographic Audit Poison Quarantine Module.

Phase 3C-5A Reference Implementation.
Provides non-destructive quarantine of malformed/poison audit events without
modifying immutable raw audit_logs rows or compromising canonical chain integrity.
"""
from __future__ import annotations

import base64
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.models import AuditChainLink, AuditLog, AuditPoisonQuarantine

logger = logging.getLogger(__name__)

DEFAULT_QUARANTINE_POLICY_VERSION = "BSEA-QUARANTINE-v1"


class QuarantineError(Exception):
    """Base exception for audit quarantine errors."""
    pass


class QuarantineAuthorizationError(QuarantineError):
    """Raised when cryptographic verification or authorization checks fail."""
    pass


class QuarantineReplayError(QuarantineError):
    """Raised when an authorization nonce replay is detected."""
    pass


class QuarantineConflictError(QuarantineError):
    """Raised when an audit event is already chained or already quarantined."""
    pass


def build_quarantine_authorization_payload(
    audit_log_id: str,
    detected_event_hash: Optional[str],
    quarantine_reason: str,
    incident_reference: str,
    operator_1_id: str,
    operator_2_id: str,
    policy_version: str = DEFAULT_QUARANTINE_POLICY_VERSION,
    authorization_nonce: str = "",
) -> bytes:
    """
    Constructs the canonical byte representation of the quarantine authorization.
    Serialized via deterministic key-sorted compact UTF-8 JSON serialization
    following RFC 8785 principles using Python's standard JSON implementation.
    """
    payload_dict = {
        "audit_log_id": str(audit_log_id),
        "authorization_nonce": str(authorization_nonce),
        "detected_event_hash": str(detected_event_hash or ""),
        "incident_reference": str(incident_reference),
        "operator_1_id": str(operator_1_id),
        "operator_2_id": str(operator_2_id),
        "policy_version": str(policy_version),
        "quarantine_reason": str(quarantine_reason),
    }
    return json.dumps(
        payload_dict,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


class OperatorKeyRegistry:
    """
    Minimal trusted operator registry for multi-party quarantine controls.
    Maps (operator_id, key_id) to registered Ed25519 public keys.
    """

    def __init__(self):
        self._keys: Dict[Tuple[str, str], ed25519.Ed25519PublicKey] = {}

    def register_key(
        self,
        operator_id: str,
        key_id: str,
        public_key: Union[ed25519.Ed25519PublicKey, bytes, str],
    ) -> None:
        """Register an authorized operator public key."""
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            pk = public_key
        elif isinstance(public_key, bytes):
            pk = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
        elif isinstance(public_key, str):
            try:
                # Try hex then base64
                pk_bytes = bytes.fromhex(public_key) if len(public_key) == 64 else base64.b64decode(public_key)
                pk = ed25519.Ed25519PublicKey.from_public_bytes(pk_bytes)
            except Exception as e:
                raise ValueError(f"Invalid public key format for ({operator_id}, {key_id}): {e}") from e
        else:
            raise TypeError(f"Unsupported public key type: {type(public_key)}")

        self._keys[(operator_id, key_id)] = pk
        logger.info(f"Registered operator key: operator={operator_id}, key_id={key_id}")

    def verify_operator_signature(
        self,
        operator_id: str,
        key_id: str,
        payload: bytes,
        signature_b64: str,
    ) -> bool:
        """Verify an operator's Ed25519 signature against registered public key."""
        pk = self._keys.get((operator_id, key_id))
        if pk is None:
            logger.warning(f"Operator key not found in registry: operator={operator_id}, key_id={key_id}")
            return False

        try:
            sig_bytes = base64.b64decode(signature_b64)
            pk.verify(sig_bytes, payload)
            return True
        except (InvalidSignature, ValueError, Exception) as e:
            logger.warning(f"Signature verification failed for operator {operator_id}: {e}")
            return False


_global_registry = OperatorKeyRegistry()


def get_operator_key_registry() -> OperatorKeyRegistry:
    """Access the global operator key registry."""
    return _global_registry


async def verify_and_quarantine_audit_event(
    session: AsyncSession,
    audit_log_id: str,
    detected_event_hash: Optional[str],
    quarantine_reason: str,
    incident_reference: str,
    operator_1_id: str,
    operator_1_key_id: str,
    operator_1_signature_b64: str,
    operator_2_id: str,
    operator_2_key_id: str,
    operator_2_signature_b64: str,
    authorization_nonce: str,
    policy_version: str = DEFAULT_QUARANTINE_POLICY_VERSION,
    registry: Optional[OperatorKeyRegistry] = None,
) -> AuditPoisonQuarantine:
    """
    Verify dual-operator cryptographic authorization and insert record into audit_poison_quarantine.
    Enforces distinct operators, valid signatures over identical canonical payload,
    replay protection, and non-transplantation invariants.
    """
    # 1. Enforce distinct operator identities and distinct key IDs
    if operator_1_id == operator_2_id:
        raise QuarantineAuthorizationError("Dual-custody violation: operator_1_id and operator_2_id must be distinct.")
    if operator_1_key_id == operator_2_key_id:
        raise QuarantineAuthorizationError("Dual-custody violation: operator_1_key_id and operator_2_key_id must be distinct.")
    if not authorization_nonce or not authorization_nonce.strip():
        raise QuarantineAuthorizationError("Authorization nonce must be non-empty.")

    reg = registry or get_operator_key_registry()

    # 2. Check audit_log_id exists in audit_logs
    res_log = await session.execute(
        select(AuditLog).where(AuditLog.id == audit_log_id)
    )
    log_entry = res_log.scalar_one_or_none()
    if log_entry is None:
        raise QuarantineError(f"Audit event not found: {audit_log_id}")

    # 3. Non-transplantation: verify detected_event_hash matches the target record
    stored_hash = log_entry.event_hash or ""
    given_hash = detected_event_hash or ""
    if stored_hash.lower() != given_hash.lower():
        raise QuarantineAuthorizationError(
            f"Transplantation detected: given detected_event_hash '{given_hash}' does not match stored hash '{stored_hash}'"
        )

    # 4. Check if already chained in audit_chain_links
    res_link = await session.execute(
        select(AuditChainLink).where(AuditChainLink.audit_log_id == audit_log_id)
    )
    if res_link.scalar_one_or_none() is not None:
        raise QuarantineConflictError(
            f"Cannot quarantine audit event {audit_log_id}: already incorporated into canonical audit_chain_links."
        )

    # 5. Check if already quarantined
    res_q = await session.execute(
        select(AuditPoisonQuarantine).where(AuditPoisonQuarantine.audit_log_id == audit_log_id)
    )
    if res_q.scalar_one_or_none() is not None:
        raise QuarantineConflictError(f"Audit event {audit_log_id} is already quarantined.")

    # 6. Check authorization_nonce uniqueness (replay protection)
    res_nonce = await session.execute(
        select(AuditPoisonQuarantine).where(AuditPoisonQuarantine.authorization_nonce == authorization_nonce)
    )
    if res_nonce.scalar_one_or_none() is not None:
        raise QuarantineReplayError(f"Authorization nonce '{authorization_nonce}' has already been used.")

    # 7. Construct canonical authorization payload bytes
    canonical_payload = build_quarantine_authorization_payload(
        audit_log_id=audit_log_id,
        detected_event_hash=detected_event_hash,
        quarantine_reason=quarantine_reason,
        incident_reference=incident_reference,
        operator_1_id=operator_1_id,
        operator_2_id=operator_2_id,
        policy_version=policy_version,
        authorization_nonce=authorization_nonce,
    )

    # 8. Cryptographically verify Operator 1 signature
    v1 = reg.verify_operator_signature(
        operator_1_id, operator_1_key_id, canonical_payload, operator_1_signature_b64
    )
    if not v1:
        raise QuarantineAuthorizationError(
            f"Operator 1 ({operator_1_id}) signature verification failed against registered key {operator_1_key_id}."
        )

    # 9. Cryptographically verify Operator 2 signature
    v2 = reg.verify_operator_signature(
        operator_2_id, operator_2_key_id, canonical_payload, operator_2_signature_b64
    )
    if not v2:
        raise QuarantineAuthorizationError(
            f"Operator 2 ({operator_2_id}) signature verification failed against registered key {operator_2_key_id}."
        )

    # 10. Persist immutable quarantine record
    quarantine_entry = AuditPoisonQuarantine(
        audit_log_id=audit_log_id,
        detected_event_hash=detected_event_hash,
        quarantine_reason=quarantine_reason,
        incident_reference=incident_reference,
        policy_version=policy_version,
        authorization_nonce=authorization_nonce,
        operator_1_id=operator_1_id,
        operator_1_key_id=operator_1_key_id,
        operator_1_signature_b64=operator_1_signature_b64,
        operator_2_id=operator_2_id,
        operator_2_key_id=operator_2_key_id,
        operator_2_signature_b64=operator_2_signature_b64,
        quarantined_at=datetime.now(timezone.utc),
    )
    session.add(quarantine_entry)
    await session.commit()
    await session.refresh(quarantine_entry)

    logger.info(
        f"AUDIT POISON QUARANTINE APPLIED: audit_log_id={audit_log_id}, incident={incident_reference}, "
        f"operators=({operator_1_id}, {operator_2_id})"
    )
    return quarantine_entry
