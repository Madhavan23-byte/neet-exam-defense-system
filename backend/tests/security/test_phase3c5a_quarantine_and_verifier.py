"""
B-SEA Phase 3C-5A Authoritative Security Test Suite:
Dual-Operator Poison Quarantine & 10-Point Deep Audit Verifier

Section Mandates:
1. Unquarantined poison audit event fails closed (PoisonAuditEventError halts sealer).
2. Dual-operator cryptographic quarantine authorization via Ed25519 signatures.
3. Sealer skips quarantined poison event and continues sealing candidates cleanly.
4. Quarantined events MUST NEVER enter audit_chain_links.
5. Dual-custody identity constraints: operator_1_id != operator_2_id enforced (Service + DB).
6. Dual-custody key constraints: operator_1_key_id != operator_2_key_id enforced (Service + DB).
7. Unregistered operator or invalid signature strictly rejected.
8. Replay protection: reused authorization_nonce strictly rejected (Service + DB).
9. Anti-transplantation: mismatched detected_event_hash strictly rejected.
10. Database immutability: UPDATE and DELETE on audit_poison_quarantine rejected by trigger.
11. 10-Point Deep Audit Verifier PASS on production baseline (5,982 records, 6 epochs).
12. Deep Verifier detects historical legacy event hash preservation mismatch (Point 7).
13. Deep Verifier detects live canonical recomputation mismatch following RFC 8785 principles (Point 8).
14. Deep Verifier detects quarantine contamination in audit_chain_links (Point 9).
15. Deep Verifier detects unquarantined poison backlog event (Point 9).
16. Deep Verifier replica staleness triggers authorized primary fallback (Point 10).
17. Deep Verifier returns strictly from {PASS, FAIL, UNAVAILABLE, INSUFFICIENT_FRESHNESS, UNRESOLVED}.
"""
import asyncio
import base64
import json
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError, InternalError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import AsyncSessionLocal, engine
from app.core.models import (
    AuditChainLink,
    AuditEpochSeal,
    AuditLog,
    AuditPoisonQuarantine,
    AuditResult,
    new_uuid,
)
from app.modules.audit.canonical import (
    build_canonical_event_payload,
    compute_canonical_chain_hash,
    compute_canonical_event_hash,
)
from app.modules.audit.quarantine import (
    DEFAULT_QUARANTINE_POLICY_VERSION,
    OperatorKeyRegistry,
    QuarantineAuthorizationError,
    QuarantineConflictError,
    QuarantineReplayError,
    build_quarantine_authorization_payload,
    get_operator_key_registry,
    verify_and_quarantine_audit_event,
)
from app.modules.audit.sealer import AuditSealer, PoisonAuditEventError
from app.modules.audit.service import DEFAULT_LEGACY_CUTOVER_SEQ, AuditService


def generate_operator_keypair():
    priv = ed25519.Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_b64 = base64.b64encode(pub_bytes).decode("utf-8")
    return priv, pub_b64


def sign_payload(priv_key: ed25519.Ed25519PrivateKey, payload: bytes) -> str:
    sig = priv_key.sign(payload)
    return base64.b64encode(sig).decode("utf-8")


# ── Test Fixtures ─────────────────────────────────────────────

@pytest.fixture(scope="module")
def operator_keys():
    priv1, pub1_b64 = generate_operator_keypair()
    priv2, pub2_b64 = generate_operator_keypair()
    op1_id = "op-secops-alpha"
    op1_key_id = "key-alpha-v1"
    op2_id = "op-lead-bravo"
    op2_key_id = "key-bravo-v1"

    reg = get_operator_key_registry()
    reg.register_key(op1_id, op1_key_id, pub1_b64)
    reg.register_key(op2_id, op2_key_id, pub2_b64)

    return {
        "op1_id": op1_id,
        "op1_key_id": op1_key_id,
        "priv1": priv1,
        "pub1_b64": pub1_b64,
        "op2_id": op2_id,
        "op2_key_id": op2_key_id,
        "priv2": priv2,
        "pub2_b64": pub2_b64,
        "registry": reg,
    }


# ── Test 1: Poison event halts sealer when unquarantined ────────

@pytest.mark.asyncio
async def test_01_poison_event_halts_sealer_unquarantined():
    """Unquarantined malformed/poison event in audit_logs immediately halts sealer (fails closed)."""
    poison_id = new_uuid()
    async with AsyncSessionLocal() as session:
        poison_log = AuditLog(
            id=poison_id,
            event_type="POISON_EVENT_TEST",
            event_hash="malformed_non_hex_hash_12345",
            result=AuditResult.SUCCESS,
            created_at=datetime.now(timezone.utc),
            timestamp=datetime.now(timezone.utc),
        )
        session.add(poison_log)
        await session.commit()

    sealer = AuditSealer()
    try:
        async with engine.connect() as conn:
            locked = await sealer.acquire_leadership(conn)
            assert locked is True
            try:
                with pytest.raises(PoisonAuditEventError, match="poison audit event detected"):
                    await sealer.incorporate_unsealed_events(conn)
            finally:
                await sealer.release_leadership(conn)
    finally:
        # Administrative cleanup
        async with engine.connect() as conn:
            await conn.execute(text("ALTER TABLE audit_logs DISABLE TRIGGER trg_audit_logs_immutable;"))
            await conn.execute(text("DELETE FROM audit_logs WHERE id = :p_id;"), {"p_id": poison_id})
            await conn.execute(text("ALTER TABLE audit_logs ENABLE TRIGGER trg_audit_logs_immutable;"))
            await conn.commit()


# ── Test 2: Dual-operator cryptographic quarantine authorization ─

@pytest.mark.asyncio
async def test_02_dual_operator_quarantine_payload_and_signatures(operator_keys):
    """Dual-operator quarantine verification validates cryptographic Ed25519 signatures and persists record."""
    poison_id = new_uuid()
    poison_hash = "f" * 64
    async with AsyncSessionLocal() as session:
        log_row = AuditLog(
            id=poison_id,
            event_type="POISON_FOR_QUARANTINE",
            event_hash=poison_hash,
            result=AuditResult.SUCCESS,
            created_at=datetime.now(timezone.utc),
            timestamp=datetime.now(timezone.utc),
        )
        session.add(log_row)
        await session.commit()

    nonce = f"nonce-{uuid.uuid4().hex}"
    reason = "Corrupted event payload discovered during audit"
    incident_ref = "INC-2026-09-001"

    payload = build_quarantine_authorization_payload(
        audit_log_id=poison_id,
        detected_event_hash=poison_hash,
        quarantine_reason=reason,
        incident_reference=incident_ref,
        operator_1_id=operator_keys["op1_id"],
        operator_2_id=operator_keys["op2_id"],
        policy_version=DEFAULT_QUARANTINE_POLICY_VERSION,
        authorization_nonce=nonce,
    )

    sig1_b64 = sign_payload(operator_keys["priv1"], payload)
    sig2_b64 = sign_payload(operator_keys["priv2"], payload)

    try:
        async with AsyncSessionLocal() as session:
            quarantine_entry = await verify_and_quarantine_audit_event(
                session=session,
                audit_log_id=poison_id,
                detected_event_hash=poison_hash,
                quarantine_reason=reason,
                incident_reference=incident_ref,
                operator_1_id=operator_keys["op1_id"],
                operator_1_key_id=operator_keys["op1_key_id"],
                operator_1_signature_b64=sig1_b64,
                operator_2_id=operator_keys["op2_id"],
                operator_2_key_id=operator_keys["op2_key_id"],
                operator_2_signature_b64=sig2_b64,
                authorization_nonce=nonce,
                registry=operator_keys["registry"],
            )
            await session.commit()

            assert quarantine_entry.quarantine_id is not None
            assert quarantine_entry.audit_log_id == poison_id
            assert quarantine_entry.operator_1_id == operator_keys["op1_id"]
            assert quarantine_entry.operator_2_id == operator_keys["op2_id"]
            assert quarantine_entry.authorization_nonce == nonce
    finally:
        # Clean up test rows
        async with engine.connect() as conn:
            await conn.execute(text("ALTER TABLE audit_poison_quarantine DISABLE TRIGGER trg_audit_poison_quarantine_immutable;"))
            await conn.execute(text("DELETE FROM audit_poison_quarantine WHERE audit_log_id = :p_id;"), {"p_id": poison_id})
            await conn.execute(text("ALTER TABLE audit_poison_quarantine ENABLE TRIGGER trg_audit_poison_quarantine_immutable;"))
            await conn.execute(text("ALTER TABLE audit_logs DISABLE TRIGGER trg_audit_logs_immutable;"))
            await conn.execute(text("DELETE FROM audit_logs WHERE id = :p_id;"), {"p_id": poison_id})
            await conn.execute(text("ALTER TABLE audit_logs ENABLE TRIGGER trg_audit_logs_immutable;"))
            await conn.commit()


# ── Test 3: Sealer bypasses quarantined event and seals subsequent candidates ─

@pytest.mark.asyncio
async def test_03_quarantine_enables_sealer_to_bypass_poison_event(operator_keys):
    """Quarantining a poison event allows sealer to proceed; quarantined event NEVER enters audit_chain_links."""
    poison_id = new_uuid()
    poison_hash = "e" * 64
    valid_log = None

    try:
        # 1. Insert poison log
        async with AsyncSessionLocal() as session:
            log_row = AuditLog(
                id=poison_id,
                event_type="POISON_BYPASS_TEST",
                event_hash=poison_hash,
                result=AuditResult.SUCCESS,
                created_at=datetime.now(timezone.utc),
                timestamp=datetime.now(timezone.utc),
            )
            session.add(log_row)
            await session.commit()

        # 2. Quarantine it
        nonce = f"nonce-{uuid.uuid4().hex}"
        payload = build_quarantine_authorization_payload(
            audit_log_id=poison_id,
            detected_event_hash=poison_hash,
            quarantine_reason="Bypass test reason",
            incident_reference="INC-BYPASS-01",
            operator_1_id=operator_keys["op1_id"],
            operator_2_id=operator_keys["op2_id"],
            policy_version=DEFAULT_QUARANTINE_POLICY_VERSION,
            authorization_nonce=nonce,
        )
        sig1 = sign_payload(operator_keys["priv1"], payload)
        sig2 = sign_payload(operator_keys["priv2"], payload)

        async with AsyncSessionLocal() as session:
            await verify_and_quarantine_audit_event(
                session=session,
                audit_log_id=poison_id,
                detected_event_hash=poison_hash,
                quarantine_reason="Bypass test reason",
                incident_reference="INC-BYPASS-01",
                operator_1_id=operator_keys["op1_id"],
                operator_1_key_id=operator_keys["op1_key_id"],
                operator_1_signature_b64=sig1,
                operator_2_id=operator_keys["op2_id"],
                operator_2_key_id=operator_keys["op2_key_id"],
                operator_2_signature_b64=sig2,
                authorization_nonce=nonce,
                registry=operator_keys["registry"],
            )
            await session.commit()

        # 3. Log a subsequent valid event
        audit_svc = AuditService()
        valid_log = await audit_svc.log_security_event(
            event_type="VALID_AFTER_QUARANTINE",
            action=f"ACT_{new_uuid()}",
        )

        # 4. Run sealer
        sealer = AuditSealer()
        res = await sealer.run_once()
        assert res.status in ("SUCCESS", "NOOP")

        # 5. Assert poison event NEVER entered audit_chain_links
        async with engine.connect() as conn:
            poison_chained = await conn.execute(
                text("SELECT 1 FROM audit_chain_links WHERE audit_log_id = :p_id;"),
                {"p_id": poison_id},
            )
            assert poison_chained.fetchone() is None, "CRITICAL: Quarantined event was incorporated into audit_chain_links!"

            # Assert valid event WAS incorporated
            valid_chained = await conn.execute(
                text("SELECT 1 FROM audit_chain_links WHERE audit_log_id = :v_id;"),
                {"v_id": valid_log.id},
            )
            assert valid_chained.fetchone() is not None, "Valid event after quarantine was not incorporated!"

    finally:
        # Administrative cleanup of test rows including the chain link
        async with engine.connect() as conn:
            await conn.execute(text("ALTER TABLE audit_chain_links DISABLE TRIGGER trg_audit_chain_links_immutable;"))
            if valid_log:
                await conn.execute(text("DELETE FROM audit_chain_links WHERE audit_log_id = :v_id;"), {"v_id": valid_log.id})
            await conn.execute(text("DELETE FROM audit_chain_links WHERE audit_log_id = :p_id;"), {"p_id": poison_id})
            await conn.execute(text("ALTER TABLE audit_chain_links ENABLE TRIGGER trg_audit_chain_links_immutable;"))

            await conn.execute(text("ALTER TABLE audit_poison_quarantine DISABLE TRIGGER trg_audit_poison_quarantine_immutable;"))
            await conn.execute(text("DELETE FROM audit_poison_quarantine WHERE audit_log_id = :p_id;"), {"p_id": poison_id})
            await conn.execute(text("ALTER TABLE audit_poison_quarantine ENABLE TRIGGER trg_audit_poison_quarantine_immutable;"))

            await conn.execute(text("ALTER TABLE audit_logs DISABLE TRIGGER trg_audit_logs_immutable;"))
            await conn.execute(text("DELETE FROM audit_logs WHERE id = :p_id;"), {"p_id": poison_id})
            if valid_log:
                await conn.execute(text("DELETE FROM audit_logs WHERE id = :v_id;"), {"v_id": valid_log.id})
            await conn.execute(text("ALTER TABLE audit_logs ENABLE TRIGGER trg_audit_logs_immutable;"))
            await conn.commit()


# ── Test 4: Dual-custody identity constraints (operator_1 != operator_2) ─────

@pytest.mark.asyncio
async def test_04_dual_custody_same_operator_rejected(operator_keys):
    """Single operator signing both roles is rejected by service and DB check constraint."""
    poison_id = new_uuid()
    nonce = f"nonce-{uuid.uuid4().hex}"

    # Service layer rejection
    async with AsyncSessionLocal() as session:
        with pytest.raises(QuarantineAuthorizationError, match="operator_1_id and operator_2_id must be distinct"):
            await verify_and_quarantine_audit_event(
                session=session,
                audit_log_id=poison_id,
                detected_event_hash="hash",
                quarantine_reason="reason",
                incident_reference="INC-01",
                operator_1_id="same-operator",
                operator_1_key_id="key-1",
                operator_1_signature_b64="sig1",
                operator_2_id="same-operator",
                operator_2_key_id="key-2",
                operator_2_signature_b64="sig2",
                authorization_nonce=nonce,
            )

    # Database constraint rejection (ck_quarantine_distinct_operators)
    async with engine.connect() as conn:
        with pytest.raises((IntegrityError, Exception)):
            async with conn.begin():
                await conn.execute(
                    text("""
                        INSERT INTO audit_poison_quarantine (
                            quarantine_id, audit_log_id, detected_event_hash, quarantine_reason,
                            incident_reference, operator_1_id, operator_1_key_id, operator_1_signature_b64,
                            operator_2_id, operator_2_key_id, operator_2_signature_b64,
                            policy_version, authorization_nonce, quarantined_at
                        ) VALUES (
                            :qid, :alid, 'hash', 'reason', 'INC-01',
                            'same_op', 'key1', 'sig1',
                            'same_op', 'key2', 'sig2',
                            'v1', :nonce, NOW()
                        );
                    """),
                    {"qid": new_uuid(), "alid": poison_id, "nonce": nonce},
                )


# ── Test 5: Dual-custody key constraints (operator_1_key != operator_2_key) ──

@pytest.mark.asyncio
async def test_05_dual_custody_same_key_rejected(operator_keys):
    """Using identical key ID for both operators is rejected by service and DB check constraint."""
    poison_id = new_uuid()
    nonce = f"nonce-{uuid.uuid4().hex}"

    # Service layer rejection
    async with AsyncSessionLocal() as session:
        with pytest.raises(QuarantineAuthorizationError, match="operator_1_key_id and operator_2_key_id must be distinct"):
            await verify_and_quarantine_audit_event(
                session=session,
                audit_log_id=poison_id,
                detected_event_hash="hash",
                quarantine_reason="reason",
                incident_reference="INC-01",
                operator_1_id="op1",
                operator_1_key_id="same-key-id",
                operator_1_signature_b64="sig1",
                operator_2_id="op2",
                operator_2_key_id="same-key-id",
                operator_2_signature_b64="sig2",
                authorization_nonce=nonce,
            )

    # Database constraint rejection (ck_quarantine_distinct_keys)
    async with engine.connect() as conn:
        with pytest.raises((IntegrityError, Exception)):
            async with conn.begin():
                await conn.execute(
                    text("""
                        INSERT INTO audit_poison_quarantine (
                            quarantine_id, audit_log_id, detected_event_hash, quarantine_reason,
                            incident_reference, operator_1_id, operator_1_key_id, operator_1_signature_b64,
                            operator_2_id, operator_2_key_id, operator_2_signature_b64,
                            policy_version, authorization_nonce, quarantined_at
                        ) VALUES (
                            :qid, :alid, 'hash', 'reason', 'INC-01',
                            'op1', 'same_key', 'sig1',
                            'op2', 'same_key', 'sig2',
                            'v1', :nonce, NOW()
                        );
                    """),
                    {"qid": new_uuid(), "alid": poison_id, "nonce": nonce},
                )


# ── Test 6: Unregistered operator or forged signature rejected ────────────────

@pytest.mark.asyncio
async def test_06_unregistered_operator_or_invalid_signature_rejected(operator_keys):
    """Unregistered operator or corrupted/forged signature is strictly rejected."""
    poison_id = new_uuid()
    poison_hash = "a" * 64
    async with AsyncSessionLocal() as session:
        log_row = AuditLog(
            id=poison_id,
            event_type="POISON_SIG_TEST",
            event_hash=poison_hash,
            result=AuditResult.SUCCESS,
            created_at=datetime.now(timezone.utc),
            timestamp=datetime.now(timezone.utc),
        )
        session.add(log_row)
        await session.commit()

    nonce = f"nonce-{uuid.uuid4().hex}"
    payload = build_quarantine_authorization_payload(
        audit_log_id=poison_id,
        detected_event_hash=poison_hash,
        quarantine_reason="Test",
        incident_reference="INC-01",
        operator_1_id="unregistered-op",
        operator_2_id=operator_keys["op2_id"],
        policy_version=DEFAULT_QUARANTINE_POLICY_VERSION,
        authorization_nonce=nonce,
    )
    sig1 = sign_payload(operator_keys["priv1"], payload)
    sig2 = sign_payload(operator_keys["priv2"], payload)

    try:
        # Case A: Unregistered operator
        async with AsyncSessionLocal() as session:
            with pytest.raises(QuarantineAuthorizationError, match="signature verification failed"):
                await verify_and_quarantine_audit_event(
                    session=session,
                    audit_log_id=poison_id,
                    detected_event_hash=poison_hash,
                    quarantine_reason="Test",
                    incident_reference="INC-01",
                    operator_1_id="unregistered-op",
                    operator_1_key_id="unregistered-key",
                    operator_1_signature_b64=sig1,
                    operator_2_id=operator_keys["op2_id"],
                    operator_2_key_id=operator_keys["op2_key_id"],
                    operator_2_signature_b64=sig2,
                    authorization_nonce=nonce,
                    registry=operator_keys["registry"],
                )

        # Case B: Forged/corrupted signature
        corrupt_sig = base64.b64encode(b"invalid_signature_bytes_32_chars_ok!").decode("utf-8")
        async with AsyncSessionLocal() as session:
            with pytest.raises(QuarantineAuthorizationError, match="signature verification failed"):
                await verify_and_quarantine_audit_event(
                    session=session,
                    audit_log_id=poison_id,
                    detected_event_hash=poison_hash,
                    quarantine_reason="Test",
                    incident_reference="INC-01",
                    operator_1_id=operator_keys["op1_id"],
                    operator_1_key_id=operator_keys["op1_key_id"],
                    operator_1_signature_b64=corrupt_sig,
                    operator_2_id=operator_keys["op2_id"],
                    operator_2_key_id=operator_keys["op2_key_id"],
                    operator_2_signature_b64=sig2,
                    authorization_nonce=nonce,
                    registry=operator_keys["registry"],
                )
    finally:
        async with engine.connect() as conn:
            await conn.execute(text("ALTER TABLE audit_logs DISABLE TRIGGER trg_audit_logs_immutable;"))
            await conn.execute(text("DELETE FROM audit_logs WHERE id = :p_id;"), {"p_id": poison_id})
            await conn.execute(text("ALTER TABLE audit_logs ENABLE TRIGGER trg_audit_logs_immutable;"))
            await conn.commit()


# ── Test 7: Nonce replay rejected ─────────────────────────────

@pytest.mark.asyncio
async def test_07_replay_protection_nonce_reuse_rejected(operator_keys):
    """Replaying an authorization nonce is rejected by service and DB unique constraint."""
    poison1_id = new_uuid()
    poison2_id = new_uuid()
    h1 = "1" * 64
    h2 = "2" * 64

    async with AsyncSessionLocal() as session:
        session.add(AuditLog(id=poison1_id, event_type="P1", event_hash=h1, result=AuditResult.SUCCESS, created_at=datetime.now(timezone.utc), timestamp=datetime.now(timezone.utc)))
        session.add(AuditLog(id=poison2_id, event_type="P2", event_hash=h2, result=AuditResult.SUCCESS, created_at=datetime.now(timezone.utc), timestamp=datetime.now(timezone.utc)))
        await session.commit()

    shared_nonce = f"reused-nonce-{uuid.uuid4().hex}"

    # Quarantine 1
    p1 = build_quarantine_authorization_payload(poison1_id, h1, "R1", "INC-1", operator_keys["op1_id"], operator_keys["op2_id"], DEFAULT_QUARANTINE_POLICY_VERSION, shared_nonce)
    s1_1 = sign_payload(operator_keys["priv1"], p1)
    s1_2 = sign_payload(operator_keys["priv2"], p1)

    async with AsyncSessionLocal() as session:
        await verify_and_quarantine_audit_event(
            session=session,
            audit_log_id=poison1_id,
            detected_event_hash=h1,
            quarantine_reason="R1",
            incident_reference="INC-1",
            operator_1_id=operator_keys["op1_id"],
            operator_1_key_id=operator_keys["op1_key_id"],
            operator_1_signature_b64=s1_1,
            operator_2_id=operator_keys["op2_id"],
            operator_2_key_id=operator_keys["op2_key_id"],
            operator_2_signature_b64=s1_2,
            authorization_nonce=shared_nonce,
            registry=operator_keys["registry"],
        )
        await session.commit()

    try:
        # Quarantine 2 with same nonce -> raises QuarantineReplayError
        p2 = build_quarantine_authorization_payload(poison2_id, h2, "R2", "INC-2", operator_keys["op1_id"], operator_keys["op2_id"], DEFAULT_QUARANTINE_POLICY_VERSION, shared_nonce)
        s2_1 = sign_payload(operator_keys["priv1"], p2)
        s2_2 = sign_payload(operator_keys["priv2"], p2)

        async with AsyncSessionLocal() as session:
            with pytest.raises(QuarantineReplayError, match="has already been used"):
                await verify_and_quarantine_audit_event(
                    session=session,
                    audit_log_id=poison2_id,
                    detected_event_hash=h2,
                    quarantine_reason="R2",
                    incident_reference="INC-2",
                    operator_1_id=operator_keys["op1_id"],
                    operator_1_key_id=operator_keys["op1_key_id"],
                    operator_1_signature_b64=s2_1,
                    operator_2_id=operator_keys["op2_id"],
                    operator_2_key_id=operator_keys["op2_key_id"],
                    operator_2_signature_b64=s2_2,
                    authorization_nonce=shared_nonce,
                    registry=operator_keys["registry"],
                )
    finally:
        async with engine.connect() as conn:
            await conn.execute(text("ALTER TABLE audit_poison_quarantine DISABLE TRIGGER trg_audit_poison_quarantine_immutable;"))
            await conn.execute(text("DELETE FROM audit_poison_quarantine WHERE audit_log_id IN (:p1, :p2);"), {"p1": poison1_id, "p2": poison2_id})
            await conn.execute(text("ALTER TABLE audit_poison_quarantine ENABLE TRIGGER trg_audit_poison_quarantine_immutable;"))
            await conn.execute(text("ALTER TABLE audit_logs DISABLE TRIGGER trg_audit_logs_immutable;"))
            await conn.execute(text("DELETE FROM audit_logs WHERE id IN (:p1, :p2);"), {"p1": poison1_id, "p2": poison2_id})
            await conn.execute(text("ALTER TABLE audit_logs ENABLE TRIGGER trg_audit_logs_immutable;"))
            await conn.commit()


# ── Test 8: Anti-transplantation attack rejection ─────────────

@pytest.mark.asyncio
async def test_08_transplantation_attack_rejected(operator_keys):
    """Attempting to transplant quarantine authorization to an audit event with different hash is rejected."""
    target_id = new_uuid()
    actual_hash = "3" * 64
    spoofed_hash = "4" * 64

    async with AsyncSessionLocal() as session:
        session.add(AuditLog(id=target_id, event_type="TRANSPLANT_TEST", event_hash=actual_hash, result=AuditResult.SUCCESS, created_at=datetime.now(timezone.utc), timestamp=datetime.now(timezone.utc)))
        await session.commit()

    nonce = f"nonce-{uuid.uuid4().hex}"
    payload = build_quarantine_authorization_payload(target_id, spoofed_hash, "Transplant", "INC-T", operator_keys["op1_id"], operator_keys["op2_id"], DEFAULT_QUARANTINE_POLICY_VERSION, nonce)
    s1 = sign_payload(operator_keys["priv1"], payload)
    s2 = sign_payload(operator_keys["priv2"], payload)

    try:
        async with AsyncSessionLocal() as session:
            with pytest.raises(QuarantineAuthorizationError, match="Transplantation detected"):
                await verify_and_quarantine_audit_event(
                    session=session,
                    audit_log_id=target_id,
                    detected_event_hash=spoofed_hash,
                    quarantine_reason="Transplant",
                    incident_reference="INC-T",
                    operator_1_id=operator_keys["op1_id"],
                    operator_1_key_id=operator_keys["op1_key_id"],
                    operator_1_signature_b64=s1,
                    operator_2_id=operator_keys["op2_id"],
                    operator_2_key_id=operator_keys["op2_key_id"],
                    operator_2_signature_b64=s2,
                    authorization_nonce=nonce,
                    registry=operator_keys["registry"],
                )
    finally:
        async with engine.connect() as conn:
            await conn.execute(text("ALTER TABLE audit_logs DISABLE TRIGGER trg_audit_logs_immutable;"))
            await conn.execute(text("DELETE FROM audit_logs WHERE id = :t_id;"), {"t_id": target_id})
            await conn.execute(text("ALTER TABLE audit_logs ENABLE TRIGGER trg_audit_logs_immutable;"))
            await conn.commit()


# ── Test 9: Quarantine immutability triggers (UPDATE & DELETE rejected) ────────

@pytest.mark.asyncio
async def test_09_quarantine_immutability_triggers(operator_keys):
    """PostgreSQL trigger trg_audit_poison_quarantine_immutable rejects UPDATE and DELETE operations."""
    test_id = new_uuid()
    now_dt = datetime.now(timezone.utc)
    raw_payload = build_canonical_event_payload(
        event_id=test_id,
        event_type="IMMUT_TEST",
        created_at=now_dt,
        result=AuditResult.SUCCESS,
    )
    h = compute_canonical_event_hash(raw_payload)

    async with AsyncSessionLocal() as session:
        session.add(AuditLog(id=test_id, event_type="IMMUT_TEST", event_hash=h, result=AuditResult.SUCCESS, created_at=now_dt, timestamp=now_dt))
        await session.commit()

    nonce = f"nonce-{uuid.uuid4().hex}"
    payload = build_quarantine_authorization_payload(test_id, h, "Immut", "INC-IMMUT", operator_keys["op1_id"], operator_keys["op2_id"], DEFAULT_QUARANTINE_POLICY_VERSION, nonce)
    s1 = sign_payload(operator_keys["priv1"], payload)
    s2 = sign_payload(operator_keys["priv2"], payload)

    async with AsyncSessionLocal() as session:
        q = await verify_and_quarantine_audit_event(
            session=session,
            audit_log_id=test_id,
            detected_event_hash=h,
            quarantine_reason="Immut",
            incident_reference="INC-IMMUT",
            operator_1_id=operator_keys["op1_id"],
            operator_1_key_id=operator_keys["op1_key_id"],
            operator_1_signature_b64=s1,
            operator_2_id=operator_keys["op2_id"],
            operator_2_key_id=operator_keys["op2_key_id"],
            operator_2_signature_b64=s2,
            authorization_nonce=nonce,
            registry=operator_keys["registry"],
        )
        await session.commit()
        qid = q.quarantine_id

    try:
        # Assert UPDATE is rejected by trigger
        async with engine.connect() as conn:
            with pytest.raises((InternalError, Exception), match="strictly immutable"):
                async with conn.begin():
                    await conn.execute(
                        text("UPDATE audit_poison_quarantine SET quarantine_reason = 'Tampered' WHERE quarantine_id = :qid;"),
                        {"qid": qid},
                    )

            # Assert DELETE is rejected by trigger
            with pytest.raises((InternalError, Exception), match="strictly immutable"):
                async with conn.begin():
                    await conn.execute(
                        text("DELETE FROM audit_poison_quarantine WHERE quarantine_id = :qid;"),
                        {"qid": qid},
                    )
    finally:
        # Cleanup guaranteed to run
        async with engine.connect() as conn:
            await conn.execute(text("ALTER TABLE audit_poison_quarantine DISABLE TRIGGER trg_audit_poison_quarantine_immutable;"))
            await conn.execute(text("DELETE FROM audit_poison_quarantine WHERE quarantine_id = :qid;"), {"qid": qid})
            await conn.execute(text("ALTER TABLE audit_poison_quarantine ENABLE TRIGGER trg_audit_poison_quarantine_immutable;"))
            await conn.execute(text("ALTER TABLE audit_logs DISABLE TRIGGER trg_audit_logs_immutable;"))
            await conn.execute(text("DELETE FROM audit_logs WHERE id = :t_id;"), {"t_id": test_id})
            await conn.execute(text("ALTER TABLE audit_logs ENABLE TRIGGER trg_audit_logs_immutable;"))
            await conn.commit()


# ── Test 10: 10-Point Deep Audit Verifier PASS on clean state ──────────────────

@pytest.mark.asyncio
async def test_10_deep_verifier_clean_chain_pass():
    """Exhaustive 10-point audit verifier returns PASS across all historical and sealed chain links."""
    audit_svc = AuditService()
    res = await audit_svc.verify_chain_deep()

    assert res["status"] == "PASS", f"Deep verifier failed: {res}"
    assert res["total_links_verified"] >= 5982
    assert res["total_epochs_verified"] >= 6
    assert res["fallback_to_primary_used"] is False
    assert res["legacy_cutover_seq"] == DEFAULT_LEGACY_CUTOVER_SEQ


# ── Test 11: Deep Verifier detects historical legacy hash mismatch (Point 7) ──

@pytest.mark.asyncio
async def test_11_deep_verifier_detects_legacy_hash_tamper():
    """Deep verifier detects modification of legacy audit_chain_link event_hash (chain_seq <= 5982)."""
    # Test via an isolated session without committing
    async with AsyncSessionLocal() as session:
        # Fetch link 1
        res = await session.execute(
            select(AuditChainLink).where(AuditChainLink.chain_seq == 1)
        )
        link1 = res.scalar_one()
        original_hash = link1.event_hash
        link1.event_hash = "0" * 64  # Mutate in session

        audit_svc = AuditService(db=session)
        report = await audit_svc.verify_chain_deep(legacy_cutover_seq=5982)

        assert report["status"] == "FAIL"
        assert report["failure_category"] in ("CANONICAL_CHAIN_HASH_MISMATCH", "LEGACY_EVENT_HASH_MISMATCH")
        await session.rollback()


# ── Test 12: Deep Verifier detects live payload hash mismatch (Point 8) ────────

@pytest.mark.asyncio
async def test_12_deep_verifier_detects_live_payload_tamper():
    """Deep verifier detects live canonical recomputation mismatch following RFC 8785 principles using Python's standard JSON implementation (chain_seq > 5982)."""
    async with AsyncSessionLocal() as session:
        # Query the latest chain link
        res = await session.execute(
            select(AuditChainLink).order_by(AuditChainLink.chain_seq.desc()).limit(1)
        )
        head_link = res.scalar_one()
        next_seq = head_link.chain_seq + 1

        # Create a live event
        live_id = new_uuid()
        now_dt = datetime.now(timezone.utc)
        payload = build_canonical_event_payload(
            event_id=live_id,
            event_type="LIVE_TEST_EVENT",
            created_at=now_dt,
            result=AuditResult.SUCCESS,
            action="ORIGINAL_ACTION",
        )
        correct_hash = compute_canonical_event_hash(payload)
        chain_h = compute_canonical_chain_hash(head_link.chain_hash, correct_hash, next_seq)

        # Insert live_log directly with tampered action to test recomputation mismatch without violating immutability trigger
        live_log = AuditLog(
            id=live_id,
            event_type="LIVE_TEST_EVENT",
            created_at=now_dt,
            timestamp=now_dt,
            result=AuditResult.SUCCESS,
            action="TAMPERED_ACTION_CANONICAL_MISMATCH",
            event_hash=correct_hash,
        )
        live_link = AuditChainLink(
            chain_seq=next_seq,
            audit_log_id=live_id,
            event_hash=correct_hash,
            prev_chain_hash=head_link.chain_hash,
            chain_hash=chain_h,
            created_at=now_dt,
        )
        session.add(live_log)
        session.add(live_link)
        await session.flush()

        # Run verifier with legacy_cutover_seq = head_link.chain_seq
        audit_svc = AuditService(db=session)
        report = await audit_svc.verify_chain_deep(legacy_cutover_seq=head_link.chain_seq)

        assert report["status"] == "FAIL"
        assert report["failure_category"] == "LIVE_PAYLOAD_HASH_MISMATCH"
        assert report["chain_seq"] == next_seq
        await session.rollback()


# ── Test 13: Deep Verifier detects quarantine contamination (Point 9) ─────────

@pytest.mark.asyncio
async def test_13_deep_verifier_detects_quarantine_contamination():
    """Deep verifier detects if a quarantined audit event is illegally incorporated in audit_chain_links."""
    async with AsyncSessionLocal() as session:
        # Find any existing chain link
        res = await session.execute(select(AuditChainLink).limit(1))
        link = res.scalar_one()

        # Simulate fake quarantine entry in session pointing to this already-chained audit_log_id
        fake_q = AuditPoisonQuarantine(
            quarantine_id=new_uuid(),
            audit_log_id=link.audit_log_id,
            detected_event_hash=link.event_hash,
            quarantine_reason="Contamination test",
            incident_reference="INC-CONTAM",
            operator_1_id="op1",
            operator_1_key_id="k1",
            operator_1_signature_b64="s1",
            operator_2_id="op2",
            operator_2_key_id="k2",
            operator_2_signature_b64="s2",
            policy_version="v1",
            authorization_nonce=f"nonce-{uuid.uuid4().hex}",
            quarantined_at=datetime.now(timezone.utc),
        )
        session.add(fake_q)
        await session.flush()

        audit_svc = AuditService(db=session)
        report = await audit_svc.verify_chain_deep()

        assert report["status"] == "FAIL"
        assert report["failure_category"] == "QUARANTINE_CHAIN_CONTAMINATION"
        await session.rollback()


# ── Test 14: Deep Verifier detects unquarantined poison event (Point 9) ────────

@pytest.mark.asyncio
async def test_14_deep_verifier_detects_unquarantined_poison_event():
    """Deep verifier detects unquarantined malformed event in the unsealed backlog."""
    poison_id = new_uuid()
    async with AsyncSessionLocal() as session:
        poison_log = AuditLog(
            id=poison_id,
            event_type="UNQUARANTINED_TEST",
            event_hash="malformed_hash",
            result=AuditResult.SUCCESS,
            created_at=datetime.now(timezone.utc),
            timestamp=datetime.now(timezone.utc),
        )
        session.add(poison_log)
        await session.commit()

    try:
        audit_svc = AuditService()
        report = await audit_svc.verify_chain_deep()
        assert report["status"] == "FAIL"
        assert report["failure_category"] == "UNQUARANTINED_POISON_EVENT"
    finally:
        async with engine.connect() as conn:
            await conn.execute(text("ALTER TABLE audit_logs DISABLE TRIGGER trg_audit_logs_immutable;"))
            await conn.execute(text("DELETE FROM audit_logs WHERE id = :p_id;"), {"p_id": poison_id})
            await conn.execute(text("ALTER TABLE audit_logs ENABLE TRIGGER trg_audit_logs_immutable;"))
            await conn.commit()


# ── Test 15: Deep Verifier replica staleness and fallback (Point 10) ───────────

@pytest.mark.asyncio
async def test_15_deep_verifier_replica_staleness_and_fallback():
    """Deep verifier handles read replica lag correctly:
    - Lag exceeding threshold with authorized fallback: falls back to primary and returns PASS.
    - Lag exceeding threshold without authorized fallback: returns INSUFFICIENT_FRESHNESS.
    - Both replica and primary unavailable: returns UNAVAILABLE.
    """
    audit_svc = AuditService()

    # 1. Simulate stale replica session
    stale_replica = AsyncMock(spec=AsyncSession)
    mock_result = MagicMock()
    mock_result.scalar.return_value = 120.0  # 120 seconds lag (> 5.0s threshold)
    stale_replica.execute.return_value = mock_result

    # With authorized fallback to primary
    res_fallback = await audit_svc.verify_chain_deep(
        read_replica_session=stale_replica,
        max_replica_lag_seconds=5.0,
        authorized_primary_fallback=True,
    )
    assert res_fallback["status"] == "PASS"
    assert res_fallback["fallback_to_primary_used"] is True
    assert res_fallback["replication_lag_seconds"] == 120.0

    # Without authorized fallback
    res_stale = await audit_svc.verify_chain_deep(
        read_replica_session=stale_replica,
        max_replica_lag_seconds=5.0,
        authorized_primary_fallback=False,
    )
    assert res_stale["status"] == "INSUFFICIENT_FRESHNESS"
    assert res_stale["failure_category"] == "REPLICA_STALE"

    # 2. Both replica and primary unavailable
    broken_replica = AsyncMock(spec=AsyncSession)
    broken_replica.execute.side_effect = RuntimeError("Replica connection refused")

    broken_svc = AuditService()
    # Mock primary to fail as well
    with patch("app.modules.audit.service.AsyncSessionLocal", side_effect=RuntimeError("Primary DB unreachable")):
        res_unavail = await broken_svc.verify_chain_deep(
            read_replica_session=broken_replica,
            authorized_primary_fallback=True,
        )
        assert res_unavail["status"] == "UNAVAILABLE"
        assert res_unavail["failure_category"] == "DB_UNAVAILABLE"


# ── Test 16: Deep Verifier status set invariant ────────────────────────────────

@pytest.mark.asyncio
async def test_16_deep_verifier_status_set_invariant():
    """Deep verifier status is guaranteed to be exactly one of the 5 authorized values."""
    allowed_statuses = {"PASS", "FAIL", "UNAVAILABLE", "INSUFFICIENT_FRESHNESS", "UNRESOLVED"}
    audit_svc = AuditService()
    report = await audit_svc.verify_chain_deep()
    assert report["status"] in allowed_statuses
