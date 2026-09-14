"""
B-SEA Administrative Audit Quarantine CLI Tool.

Phase 3C-5A Reference Implementation.
Provides administrative commands for generating authorization payloads,
signing with operator private keys, and submitting dual-operator quarantine tickets.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import sys
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ed25519

from app.core.database import AsyncSessionLocal
from app.modules.audit.quarantine import (
    DEFAULT_QUARANTINE_POLICY_VERSION,
    build_quarantine_authorization_payload,
    get_operator_key_registry,
    verify_and_quarantine_audit_event,
)


def sign_payload_with_key(payload_bytes: bytes, private_key_pem_or_bytes: bytes) -> str:
    """Sign payload using Ed25519 private key bytes, return base64 signature."""
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_pem_or_bytes)
    sig = sk.sign(payload_bytes)
    return base64.b64encode(sig).decode("utf-8")


async def apply_quarantine_cmd(
    audit_log_id: str,
    detected_event_hash: Optional[str],
    quarantine_reason: str,
    incident_reference: str,
    operator_1_id: str,
    operator_1_key_id: str,
    operator_1_sig_b64: str,
    operator_2_id: str,
    operator_2_key_id: str,
    operator_2_sig_b64: str,
    authorization_nonce: str,
    policy_version: str = DEFAULT_QUARANTINE_POLICY_VERSION,
) -> dict:
    """Execute dual-custody quarantine authorization."""
    async with AsyncSessionLocal() as session:
        entry = await verify_and_quarantine_audit_event(
            session=session,
            audit_log_id=audit_log_id,
            detected_event_hash=detected_event_hash,
            quarantine_reason=quarantine_reason,
            incident_reference=incident_reference,
            operator_1_id=operator_1_id,
            operator_1_key_id=operator_1_key_id,
            operator_1_signature_b64=operator_1_sig_b64,
            operator_2_id=operator_2_id,
            operator_2_key_id=operator_2_key_id,
            operator_2_signature_b64=operator_2_sig_b64,
            authorization_nonce=authorization_nonce,
            policy_version=policy_version,
        )
        return {
            "status": "QUARANTINED",
            "quarantine_id": entry.quarantine_id,
            "audit_log_id": entry.audit_log_id,
            "incident_reference": entry.incident_reference,
            "quarantined_at": entry.quarantined_at.isoformat(),
        }


def main():
    parser = argparse.ArgumentParser(description="B-SEA Audit Poison Quarantine CLI")
    subparsers = parser.add_subparsers(dest="command")

    # Payload generator
    p_build = subparsers.add_parser("build-payload", help="Generate canonical authorization payload JSON")
    p_build.add_argument("--audit-log-id", required=True)
    p_build.add_argument("--detected-hash", default="")
    p_build.add_argument("--reason", required=True)
    p_build.add_argument("--incident", required=True)
    p_build.add_argument("--op1-id", required=True)
    p_build.add_argument("--op2-id", required=True)
    p_build.add_argument("--nonce", required=True)

    args = parser.parse_args()
    if args.command == "build-payload":
        raw = build_quarantine_authorization_payload(
            audit_log_id=args.audit_log_id,
            detected_event_hash=args.detected_hash,
            quarantine_reason=args.reason,
            incident_reference=args.incident,
            operator_1_id=args.op1_id,
            operator_2_id=args.op2_id,
            authorization_nonce=args.nonce,
        )
        print(raw.decode("utf-8"))


if __name__ == "__main__":
    main()
