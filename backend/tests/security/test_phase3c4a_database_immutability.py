"""
Phase 3C-4A: Audit Data Model & Append-Only Database Foundation Test Suite
Verifies all 18 mandated security, immutability, constraint, migration, and canonical hashing invariants.

Section 8 Requirements:
1. UPDATE audit_logs is rejected.
2. DELETE audit_logs is rejected.
3. UPDATE audit_chain_links is rejected.
4. DELETE audit_chain_links is rejected.
5. UPDATE audit_epoch_seals is rejected.
6. DELETE audit_epoch_seals is rejected.
7. Duplicate chain_seq is rejected.
8. Duplicate audit_log_id is rejected.
9. Invalid audit_log_id FK is rejected.
10. Malformed epoch range is rejected.
11. Existing audit rows remain after migration.
12. Trigger exists after migration.
13. Trigger is removed correctly during downgrade.
14. Upgrade -> downgrade -> upgrade succeeds.
15. Canonical event hash is deterministic.
16. Same logical event produces the same hash regardless of dictionary key insertion order.
17. Changing a protected canonical field changes the hash.
18. Chain-link constraints reject invalid references.
"""
from __future__ import annotations

import asyncio
import copy
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
import pytest
import asyncpg

from app.modules.audit.canonical import (
    build_canonical_event_payload,
    serialize_canonical_event,
    compute_event_hash,
)
from app.core.models import AuditResult

DB_URL = "postgresql://postgres:root@localhost:5432/bsea"
BACKEND_DIR = Path(__file__).resolve().parent.parent.parent


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


# ── Test 1: UPDATE audit_logs is rejected ───────────────────────────────────

def test_01_update_audit_logs_rejected():
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


# ── Test 2: DELETE audit_logs is rejected ───────────────────────────────────

def test_02_delete_audit_logs_rejected():
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


# ── Test 3: UPDATE audit_chain_links is rejected ────────────────────────────

def test_03_update_audit_chain_links_rejected():
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


# ── Test 4: DELETE audit_chain_links is rejected ────────────────────────────

def test_04_delete_audit_chain_links_rejected():
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


# ── Test 5: UPDATE audit_epoch_seals is rejected ────────────────────────────

def test_05_update_audit_epoch_seals_rejected():
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


# ── Test 6: DELETE audit_epoch_seals is rejected ────────────────────────────

def test_06_delete_audit_epoch_seals_rejected():
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


# ── Test 7: Duplicate chain_seq is rejected ──────────────────────────────────

def test_07_duplicate_chain_seq_rejected():
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

        with pytest.raises(asyncpg.UniqueViolationError) as exc_info:
            async with conn.transaction():
                await conn.execute("""
                    INSERT INTO audit_chain_links (chain_seq, audit_log_id, event_hash, prev_chain_hash, chain_hash, created_at)
                    VALUES (880003, $1, 'hash_dup_2', 'prev_2', 'chain_2', NOW());
                """, log_id_2)

        assert "uq_audit_chain_links_chain_seq" in str(exc_info.value) or "chain_seq" in str(exc_info.value)

    run_in_rollback(_test)


# ── Test 8: Duplicate audit_log_id is rejected ────────────────────────────────

def test_08_duplicate_audit_log_id_rejected():
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

        with pytest.raises(asyncpg.UniqueViolationError) as exc_info:
            async with conn.transaction():
                await conn.execute("""
                    INSERT INTO audit_chain_links (chain_seq, audit_log_id, event_hash, prev_chain_hash, chain_hash, created_at)
                    VALUES (880005, $1, 'hash_single', 'prev_5', 'chain_5', NOW());
                """, log_id)

        assert "uq_audit_chain_links_audit_log_id" in str(exc_info.value) or "audit_log_id" in str(exc_info.value)

    run_in_rollback(_test)


# ── Test 9: Invalid audit_log_id FK is rejected ──────────────────────────────

def test_09_invalid_audit_log_id_fk_rejected():
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


# ── Test 10: Malformed epoch range is rejected ───────────────────────────────

def test_10_malformed_epoch_ranges_rejected():
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
        assert "ck_audit_epoch_seals" in str(exc_a.value)

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

        # Case C: record_count != end - start + 1
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

        # Case D: start_chain_seq < 1
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


# ── Test 11: Existing audit rows remain after migration ─────────────────────

def test_11_existing_audit_rows_remain_after_migration():
    async def _test(conn):
        count = await conn.fetchval("SELECT count(*) FROM audit_logs;")
        assert count > 0, "Historical audit_logs records must remain intact"
        null_created_at = await conn.fetchval("SELECT count(*) FROM audit_logs WHERE created_at IS NULL;")
        assert null_created_at == 0, "All audit_logs rows must have valid created_at"
    run_in_rollback(_test)


# ── Test 12: Trigger exists after migration ──────────────────────────────────

def test_12_triggers_exist_after_migration():
    async def _test(conn):
        triggers = await conn.fetch("""
            SELECT trigger_name, event_object_table
            FROM information_schema.triggers
            WHERE event_object_table IN ('audit_logs', 'audit_chain_links', 'audit_epoch_seals')
            ORDER BY event_object_table, trigger_name;
        """)
        trg_map = {(t["event_object_table"], t["trigger_name"]) for t in triggers}
        assert ("audit_logs", "trg_audit_logs_immutable") in trg_map
        assert ("audit_chain_links", "trg_audit_chain_links_immutable") in trg_map
        assert ("audit_epoch_seals", "trg_audit_epoch_seals_immutable") in trg_map
    run_in_rollback(_test)


# ── Test 13: Trigger is removed correctly during downgrade ───────────────────

def test_13_triggers_removed_during_downgrade():
    # Execute downgrade to c4b2d3e4f5a6
    res_down = subprocess.run(
        [sys.executable, "-m", "alembic", "downgrade", "-1"],
        cwd=BACKEND_DIR,
        capture_output=True,
        text=True,
    )
    assert res_down.returncode == 0, f"Alembic downgrade failed: {res_down.stderr}"

    async def _check_no_triggers():
        conn = await asyncpg.connect(DB_URL)
        try:
            triggers = await conn.fetch("""
                SELECT trigger_name FROM information_schema.triggers
                WHERE event_object_table IN ('audit_logs', 'audit_chain_links', 'audit_epoch_seals');
            """)
            assert len(triggers) == 0, f"Expected 0 triggers after downgrade, found: {triggers}"
        finally:
            await conn.close()

    asyncio.run(_check_no_triggers())

    # Restore upgrade so database remains at current head
    res_up = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=BACKEND_DIR,
        capture_output=True,
        text=True,
    )
    assert res_up.returncode == 0, f"Alembic upgrade restoration failed: {res_up.stderr}"


# ── Test 14: Upgrade -> Downgrade -> Upgrade succeeds ────────────────────────

def test_14_upgrade_downgrade_upgrade_succeeds():
    # 1. Downgrade
    res_down = subprocess.run(
        [sys.executable, "-m", "alembic", "downgrade", "-1"],
        cwd=BACKEND_DIR,
        capture_output=True,
        text=True,
    )
    assert res_down.returncode == 0, f"Downgrade failed: {res_down.stderr}"

    # 2. Upgrade
    res_up = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=BACKEND_DIR,
        capture_output=True,
        text=True,
    )
    assert res_up.returncode == 0, f"Upgrade failed: {res_up.stderr}"

    # Verify head reached and tables exist
    async def _verify_tables():
        conn = await asyncpg.connect(DB_URL)
        try:
            tables = await conn.fetch("""
                SELECT table_name FROM information_schema.tables
                WHERE table_name IN ('audit_logs', 'audit_chain_links', 'audit_epoch_seals');
            """)
            names = {t["table_name"] for t in tables}
            assert "audit_logs" in names
            assert "audit_chain_links" in names
            assert "audit_epoch_seals" in names
        finally:
            await conn.close()

    asyncio.run(_verify_tables())


# ── Test 15: Canonical event hash is deterministic ───────────────────────────

def test_15_canonical_event_hash_deterministic():
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

    hash1 = compute_event_hash(payload1)
    hash2 = compute_event_hash(payload2)

    assert hash1 == hash2, "Canonical hash must be strictly deterministic across identical calls"
    assert len(hash1) == 64
    assert all(c in "0123456789abcdef" for c in hash1)


# ── Test 16: Key order independence in canonical hash ────────────────────────

def test_16_canonical_event_hash_key_order_independence():
    fixed_time = datetime(2026, 9, 14, 10, 0, 0, 123456, tzinfo=timezone.utc)
    fixed_id = "550e8400-e29b-41d4-a716-446655440000"

    payload1 = build_canonical_event_payload(
        event_id=fixed_id,
        event_type="CANDIDATE_SUBMIT",
        created_at=fixed_time,
        result=AuditResult.SUCCESS,
        event_metadata={"alpha": 1, "beta": 2, "gamma": {"z": 26, "a": 1}},
    )

    payload2 = build_canonical_event_payload(
        event_id=fixed_id,
        event_type="CANDIDATE_SUBMIT",
        created_at=fixed_time,
        result="SUCCESS",
        event_metadata={"gamma": {"a": 1, "z": 26}, "beta": 2, "alpha": 1},
    )

    hash1 = compute_event_hash(payload1)
    hash2 = compute_event_hash(payload2)

    assert hash1 == hash2, "Canonical hash must be identical regardless of dictionary key insertion order"


# ── Test 17: Changing protected canonical field changes hash ─────────────────

def test_17_changing_protected_canonical_field_changes_hash():
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


# ── Test 18: Chain-link constraints reject invalid references ────────────────

def test_18_chain_link_constraints_reject_invalid_references():
    async def _test(conn):
        # 1. Null audit_log_id rejected
        with pytest.raises(asyncpg.NotNullViolationError):
            async with conn.transaction():
                await conn.execute("""
                    INSERT INTO audit_chain_links (chain_seq, audit_log_id, event_hash, prev_chain_hash, chain_hash, created_at)
                    VALUES (880099, NULL, 'h', 'p', 'c', NOW());
                """)

        # 2. Non-existent audit_log_id FK rejected
        fake_id = str(uuid.uuid4())
        with pytest.raises(asyncpg.ForeignKeyViolationError):
            async with conn.transaction():
                await conn.execute("""
                    INSERT INTO audit_chain_links (chain_seq, audit_log_id, event_hash, prev_chain_hash, chain_hash, created_at)
                    VALUES (880100, $1, 'h', 'p', 'c', NOW());
                """, fake_id)

    run_in_rollback(_test)
