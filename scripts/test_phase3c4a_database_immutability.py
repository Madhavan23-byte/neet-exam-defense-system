"""
Phase 3C-4A: Audit Data Model & Append-Only Database Foundation Tests
Verification of database immutability triggers, constraints, foreign keys,
and canonical event hashing on PostgreSQL.

Tests:
1. audit_logs UPDATE is rejected by trigger.
2. audit_logs DELETE is rejected by trigger.
3. audit_chain_links UPDATE is rejected by trigger.
4. audit_chain_links DELETE is rejected by trigger.
5. audit_epoch_seals UPDATE is rejected by trigger.
6. audit_epoch_seals DELETE is rejected by trigger.
7. duplicate chain_seq is rejected by unique constraint.
8. duplicate audit_log_id in chain_links is rejected by unique constraint.
9. invalid foreign-key references are rejected by foreign key constraint.
10. malformed epoch ranges are rejected by check constraints.
11. canonical event hash determinism across identical invocations.
12. canonical event hash field sensitivity across all 16 participating fields.
13. legacy audit logs preservation, non-null created_at, and query readability.
"""
from __future__ import annotations

import asyncio
import copy
import uuid
from datetime import datetime, timezone
import pytest
import asyncpg

from app.modules.audit.canonical import (
    build_canonical_event_payload,
    serialize_canonical_event,
    compute_event_hash,
)
from app.core.models import AuditResult

DB_URL = "postgresql://postgres:root@localhost:5432/bsea"


def run_in_rollback(coro_fn):
    """Execute test in an isolated PostgreSQL connection with guaranteed transaction rollback."""
    async def _exec():
        conn = await asyncpg.connect(DB_URL)
        tr = conn.transaction()
        await tr.start()
        try:
            await coro_fn(conn)
        finally:
            await tr.rollback()
            await conn.close()
    asyncio.run(_exec())


# ── Test 1: audit_logs UPDATE is rejected ───────────────────────────────────

def test_audit_logs_update_rejected():
    async def _test(conn):
        log_id = str(uuid.uuid4())
        await conn.execute("""
            INSERT INTO audit_logs (id, event_type, event_hash, result, risk_score, timestamp, created_at)
            VALUES ($1, 'LOGIN_SUCCESS', 'hash_test_1', 'SUCCESS', 0.0, NOW(), NOW());
        """, log_id)

        with pytest.raises(asyncpg.IntegrityConstraintViolationError) as exc_info:
            async with conn.transaction():
                await conn.execute("UPDATE audit_logs SET event_type = 'TAMPERED' WHERE id = $1;", log_id)

        assert "audit_logs is strictly immutable" in str(exc_info.value)
        assert "UPDATE and DELETE operations are forbidden" in str(exc_info.value)

    run_in_rollback(_test)


# ── Test 2: audit_logs DELETE is rejected ───────────────────────────────────

def test_audit_logs_delete_rejected():
    async def _test(conn):
        log_id = str(uuid.uuid4())
        await conn.execute("""
            INSERT INTO audit_logs (id, event_type, event_hash, result, risk_score, timestamp, created_at)
            VALUES ($1, 'LOGIN_SUCCESS', 'hash_test_2', 'SUCCESS', 0.0, NOW(), NOW());
        """, log_id)

        with pytest.raises(asyncpg.IntegrityConstraintViolationError) as exc_info:
            async with conn.transaction():
                await conn.execute("DELETE FROM audit_logs WHERE id = $1;", log_id)

        assert "audit_logs is strictly immutable" in str(exc_info.value)
        assert "UPDATE and DELETE operations are forbidden" in str(exc_info.value)

    run_in_rollback(_test)


# ── Test 3: audit_chain_links UPDATE is rejected ────────────────────────────

def test_audit_chain_links_update_rejected():
    async def _test(conn):
        log_id = str(uuid.uuid4())
        await conn.execute("""
            INSERT INTO audit_logs (id, event_type, event_hash, result, risk_score, timestamp, created_at)
            VALUES ($1, 'QUESTION_VIEW', 'hash_test_3', 'SUCCESS', 0.0, NOW(), NOW());
        """, log_id)

        link_id = await conn.fetchval("""
            INSERT INTO audit_chain_links (chain_seq, audit_log_id, event_hash, prev_chain_hash, chain_hash, created_at)
            VALUES (880001, $1, 'hash_test_3', 'genesis_hash', 'chain_hash_3', NOW())
            RETURNING link_id;
        """, log_id)

        with pytest.raises(asyncpg.IntegrityConstraintViolationError) as exc_info:
            async with conn.transaction():
                await conn.execute("UPDATE audit_chain_links SET chain_hash = 'tampered' WHERE link_id = $1;", link_id)

        assert "audit_chain_links is strictly immutable" in str(exc_info.value)
        assert "UPDATE and DELETE operations are forbidden" in str(exc_info.value)

    run_in_rollback(_test)


# ── Test 4: audit_chain_links DELETE is rejected ────────────────────────────

def test_audit_chain_links_delete_rejected():
    async def _test(conn):
        log_id = str(uuid.uuid4())
        await conn.execute("""
            INSERT INTO audit_logs (id, event_type, event_hash, result, risk_score, timestamp, created_at)
            VALUES ($1, 'QUESTION_VIEW', 'hash_test_4', 'SUCCESS', 0.0, NOW(), NOW());
        """, log_id)

        link_id = await conn.fetchval("""
            INSERT INTO audit_chain_links (chain_seq, audit_log_id, event_hash, prev_chain_hash, chain_hash, created_at)
            VALUES (880002, $1, 'hash_test_4', 'genesis_hash', 'chain_hash_4', NOW())
            RETURNING link_id;
        """, log_id)

        with pytest.raises(asyncpg.IntegrityConstraintViolationError) as exc_info:
            async with conn.transaction():
                await conn.execute("DELETE FROM audit_chain_links WHERE link_id = $1;", link_id)

        assert "audit_chain_links is strictly immutable" in str(exc_info.value)
        assert "UPDATE and DELETE operations are forbidden" in str(exc_info.value)

    run_in_rollback(_test)


# ── Test 5: audit_epoch_seals UPDATE is rejected ────────────────────────────

def test_audit_epoch_seals_update_rejected():
    async def _test(conn):
        await conn.execute("""
            INSERT INTO audit_epoch_seals (
                epoch_id, policy_version, start_chain_seq, end_chain_seq, record_count,
                prev_seal_hash, final_chain_hash, epoch_root_hash, signature_b64, kms_key_id, created_at
            ) VALUES (
                99001, 'BSEA-AUDIT-v1', 1, 100, 100,
                'prev_seal_01', 'final_chain_01', 'root_hash_01', 'sig_b64_01', 'arn:aws:kms:test', NOW()
            );
        """)

        with pytest.raises(asyncpg.IntegrityConstraintViolationError) as exc_info:
            async with conn.transaction():
                await conn.execute("UPDATE audit_epoch_seals SET epoch_root_hash = 'tampered' WHERE epoch_id = 99001;")

        assert "audit_epoch_seals is strictly immutable" in str(exc_info.value)
        assert "UPDATE and DELETE operations are forbidden" in str(exc_info.value)

    run_in_rollback(_test)


# ── Test 6: audit_epoch_seals DELETE is rejected ────────────────────────────

def test_audit_epoch_seals_delete_rejected():
    async def _test(conn):
        await conn.execute("""
            INSERT INTO audit_epoch_seals (
                epoch_id, policy_version, start_chain_seq, end_chain_seq, record_count,
                prev_seal_hash, final_chain_hash, epoch_root_hash, signature_b64, kms_key_id, created_at
            ) VALUES (
                99002, 'BSEA-AUDIT-v1', 101, 200, 100,
                'prev_seal_02', 'final_chain_02', 'root_hash_02', 'sig_b64_02', 'arn:aws:kms:test', NOW()
            );
        """)

        with pytest.raises(asyncpg.IntegrityConstraintViolationError) as exc_info:
            async with conn.transaction():
                await conn.execute("DELETE FROM audit_epoch_seals WHERE epoch_id = 99002;")

        assert "audit_epoch_seals is strictly immutable" in str(exc_info.value)
        assert "UPDATE and DELETE operations are forbidden" in str(exc_info.value)

    run_in_rollback(_test)


# ── Test 7: duplicate chain_seq is rejected ──────────────────────────────────

def test_duplicate_chain_seq_rejected():
    async def _test(conn):
        log_id_1 = str(uuid.uuid4())
        log_id_2 = str(uuid.uuid4())

        await conn.execute("""
            INSERT INTO audit_logs (id, event_type, event_hash, result, risk_score, timestamp, created_at)
            VALUES 
                ($1, 'EV1', 'hash_dup_1', 'SUCCESS', 0.0, NOW(), NOW()),
                ($2, 'EV2', 'hash_dup_2', 'SUCCESS', 0.0, NOW(), NOW());
        """, log_id_1, log_id_2)

        await conn.execute("""
            INSERT INTO audit_chain_links (chain_seq, audit_log_id, event_hash, prev_chain_hash, chain_hash, created_at)
            VALUES (880003, $1, 'hash_dup_1', 'prev_1', 'chain_1', NOW());
        """, log_id_1)

        # Attempt to insert second link with identical chain_seq
        with pytest.raises(asyncpg.UniqueViolationError) as exc_info:
            async with conn.transaction():
                await conn.execute("""
                    INSERT INTO audit_chain_links (chain_seq, audit_log_id, event_hash, prev_chain_hash, chain_hash, created_at)
                    VALUES (880003, $1, 'hash_dup_2', 'prev_2', 'chain_2', NOW());
                """, log_id_2)

        assert "uq_audit_chain_links_chain_seq" in str(exc_info.value) or "chain_seq" in str(exc_info.value)

    run_in_rollback(_test)


# ── Test 8: duplicate audit_log_id in chain_links is rejected ────────────────

def test_duplicate_audit_log_id_in_chain_links_rejected():
    async def _test(conn):
        log_id = str(uuid.uuid4())
        await conn.execute("""
            INSERT INTO audit_logs (id, event_type, event_hash, result, risk_score, timestamp, created_at)
            VALUES ($1, 'EV1', 'hash_single', 'SUCCESS', 0.0, NOW(), NOW());
        """, log_id)

        await conn.execute("""
            INSERT INTO audit_chain_links (chain_seq, audit_log_id, event_hash, prev_chain_hash, chain_hash, created_at)
            VALUES (880004, $1, 'hash_single', 'prev_4', 'chain_4', NOW());
        """, log_id)

        # Attempt to link same audit_log_id again with different chain_seq
        with pytest.raises(asyncpg.UniqueViolationError) as exc_info:
            async with conn.transaction():
                await conn.execute("""
                    INSERT INTO audit_chain_links (chain_seq, audit_log_id, event_hash, prev_chain_hash, chain_hash, created_at)
                    VALUES (880005, $1, 'hash_single', 'prev_5', 'chain_5', NOW());
                """, log_id)

        assert "uq_audit_chain_links_audit_log_id" in str(exc_info.value) or "audit_log_id" in str(exc_info.value)

    run_in_rollback(_test)


# ── Test 9: invalid foreign-key references are rejected ──────────────────────

def test_invalid_foreign_key_references_rejected():
    async def _test(conn):
        non_existent_log_id = str(uuid.uuid4())

        with pytest.raises(asyncpg.ForeignKeyViolationError) as exc_info:
            async with conn.transaction():
                await conn.execute("""
                    INSERT INTO audit_chain_links (chain_seq, audit_log_id, event_hash, prev_chain_hash, chain_hash, created_at)
                    VALUES (880006, $1, 'hash_fk', 'prev_fk', 'chain_fk', NOW());
                """, non_existent_log_id)

        assert "fk_audit_chain_links_audit_log_id" in str(exc_info.value) or "audit_logs" in str(exc_info.value)

    run_in_rollback(_test)


# ── Test 10: malformed epoch ranges are rejected ─────────────────────────────

def test_malformed_epoch_ranges_rejected():
    async def _test(conn):
        # Case A: start_chain_seq > end_chain_seq
        with pytest.raises(asyncpg.CheckViolationError) as exc_a:
            async with conn.transaction():
                await conn.execute("""
                    INSERT INTO audit_epoch_seals (
                        epoch_id, policy_version, start_chain_seq, end_chain_seq, record_count,
                        prev_seal_hash, final_chain_hash, epoch_root_hash, signature_b64, kms_key_id, created_at
                    ) VALUES (
                        99101, 'BSEA-AUDIT-v1', 200, 100, 100,
                        'p', 'f', 'r', 's', 'k', NOW()
                    );
                """)
        assert "ck_audit_epoch_seals_seq_range" in str(exc_a.value)

        # Case B: record_count <= 0
        with pytest.raises(asyncpg.CheckViolationError) as exc_b:
            async with conn.transaction():
                await conn.execute("""
                    INSERT INTO audit_epoch_seals (
                        epoch_id, policy_version, start_chain_seq, end_chain_seq, record_count,
                        prev_seal_hash, final_chain_hash, epoch_root_hash, signature_b64, kms_key_id, created_at
                    ) VALUES (
                        99102, 'BSEA-AUDIT-v1', 1, 10, 0,
                        'p', 'f', 'r', 's', 'k', NOW()
                    );
                """)
        assert "ck_audit_epoch_seals" in str(exc_b.value)

        # Case C: record_count does not match end_chain_seq - start_chain_seq + 1
        with pytest.raises(asyncpg.CheckViolationError) as exc_c:
            async with conn.transaction():
                await conn.execute("""
                    INSERT INTO audit_epoch_seals (
                        epoch_id, policy_version, start_chain_seq, end_chain_seq, record_count,
                        prev_seal_hash, final_chain_hash, epoch_root_hash, signature_b64, kms_key_id, created_at
                    ) VALUES (
                        99103, 'BSEA-AUDIT-v1', 1, 100, 50,
                        'p', 'f', 'r', 's', 'k', NOW()
                    );
                """)
        assert "ck_audit_epoch_seals_count_match" in str(exc_c.value)

        # Case D: start_chain_seq < 1 (0 or negative)
        with pytest.raises(asyncpg.CheckViolationError) as exc_d:
            async with conn.transaction():
                await conn.execute("""
                    INSERT INTO audit_epoch_seals (
                        epoch_id, policy_version, start_chain_seq, end_chain_seq, record_count,
                        prev_seal_hash, final_chain_hash, epoch_root_hash, signature_b64, kms_key_id, created_at
                    ) VALUES (
                        99104, 'BSEA-AUDIT-v1', 0, 9, 10,
                        'p', 'f', 'r', 's', 'k', NOW()
                    );
                """)
        assert "ck_audit_epoch_seals_positive_seq" in str(exc_d.value)

    run_in_rollback(_test)


# ── Test 11: Canonical Event Hash Determinism ────────────────────────────────

def test_canonical_event_hash_determinism():
    fixed_time = datetime(2026, 9, 14, 10, 0, 0, 123456, tzinfo=timezone.utc)
    fixed_id = "550e8400-e29b-41d4-a716-446655440000"

    payload1 = build_canonical_event_payload(
        event_id=fixed_id,
        event_type="CANDIDATE_SUBMIT",
        created_at=fixed_time,
        result=AuditResult.SUCCESS,
        actor_id="usr-123",
        actor_role="CANDIDATE",
        resource_type="exam",
        resource_id="exm-456",
        action="FINAL_SUBMISSION",
        ip_hash="abcde12345",
        device_id="dev-789",
        event_metadata={"score": 85, "answers_count": 50, "nested": {"a": 1, "b": 2}},
        risk_score=0.05,
        trace_id="tr-abc",
        kms_request_id="kms-xyz",
    )

    payload2 = build_canonical_event_payload(
        event_id=fixed_id,
        event_type="CANDIDATE_SUBMIT",
        created_at=fixed_time,
        result="SUCCESS",  # String instead of Enum
        actor_id="usr-123",
        actor_role="CANDIDATE",
        resource_type="exam",
        resource_id="exm-456",
        action="FINAL_SUBMISSION",
        ip_hash="abcde12345",
        device_id="dev-789",
        event_metadata={"nested": {"b": 2, "a": 1}, "score": 85, "answers_count": 50},  # Shuffled keys
        risk_score=0.05,
        trace_id="tr-abc",
        kms_request_id="kms-xyz",
    )

    hash1 = compute_event_hash(payload1)
    hash2 = compute_event_hash(payload2)

    assert hash1 == hash2, "Canonical hash must be strictly deterministic across key ordering and Enum representations"
    assert len(hash1) == 64
    assert all(c in "0123456789abcdef" for c in hash1)


# ── Test 12: Canonical Event Hash Field Sensitivity ──────────────────────────

def test_canonical_event_hash_field_sensitivity():
    fixed_time = datetime(2026, 9, 14, 10, 0, 0, tzinfo=timezone.utc)
    base_kwargs = {
        "event_id": "550e8400-e29b-41d4-a716-446655440000",
        "event_type": "EXAM_RELEASED",
        "created_at": fixed_time,
        "result": AuditResult.SUCCESS,
        "actor_id": "usr-123",
        "actor_role": "RELEASE_AUTHORITY",
        "resource_type": "exam",
        "resource_id": "exm-456",
        "action": "RELEASE",
        "ip_hash": "ip-hash-1",
        "device_id": "device-1",
        "event_metadata": {"version": 1},
        "risk_score": 0.0,
        "trace_id": "trace-1",
        "kms_request_id": "kms-1",
    }

    base_payload = build_canonical_event_payload(**base_kwargs)
    base_hash = compute_event_hash(base_payload)

    # Permute each of the 16 participating fields and verify hash changes
    mutations = [
        ("version", {"version": 2}),
        ("event_id", {"event_id": "550e8400-e29b-41d4-a716-446655440001"}),
        ("event_type", {"event_type": "EXAM_LOCKED"}),
        ("created_at", {"created_at": datetime(2026, 9, 14, 10, 0, 1, tzinfo=timezone.utc)}),
        ("result", {"result": AuditResult.FAILURE}),
        ("actor_id", {"actor_id": "usr-999"}),
        ("actor_role", {"actor_role": "SUPER_ADMIN"}),
        ("resource_type", {"resource_type": "question"}),
        ("resource_id", {"resource_id": "exm-999"}),
        ("action", {"action": "REVOKE"}),
        ("ip_hash", {"ip_hash": "ip-hash-2"}),
        ("device_id", {"device_id": "device-2"}),
        ("event_metadata", {"event_metadata": {"version": 2}}),
        ("risk_score", {"risk_score": 0.5}),
        ("trace_id", {"trace_id": "trace-2"}),
        ("kms_request_id", {"kms_request_id": "kms-2"}),
    ]

    for field_name, delta in mutations:
        modified_kwargs = copy.deepcopy(base_kwargs)
        modified_kwargs.update(delta)
        mod_payload = build_canonical_event_payload(**modified_kwargs)
        mod_hash = compute_event_hash(mod_payload)
        assert mod_hash != base_hash, f"Hash collision or insensitivity detected on field: {field_name}"


# ── Test 13: Historical Audit Logs Preservation & Queryability ───────────────

def test_legacy_audit_logs_readability():
    async def _test(conn):
        total_count = await conn.fetchval("SELECT count(*) FROM audit_logs;")
        assert total_count > 0, "Expected existing historical audit records in database"

        null_created_at = await conn.fetchval("SELECT count(*) FROM audit_logs WHERE created_at IS NULL;")
        assert null_created_at == 0, "No audit_logs row may have NULL created_at"

        rows = await conn.fetch("""
            SELECT id, event_type, created_at, timestamp
            FROM audit_logs
            ORDER BY created_at ASC, id ASC
            LIMIT 10;
        """)
        assert len(rows) == 10
        for r in rows:
            assert r["id"] is not None
            assert r["event_type"] is not None
            assert r["created_at"] is not None
            assert r["timestamp"] is not None

    run_in_rollback(_test)
