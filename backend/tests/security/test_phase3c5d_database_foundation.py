"""
Phase 3C-5D: Security Incident Management Database Foundation Test Suite.
Verifies all Step 1 database schema, constraints, indexes, OCC versioning,
and append-only immutability trigger requirements from Rev-06.

Section 8 Test Invariants:
1. Security incident creation defaults and initial OCC version=1.
2. Partial unique index uq_active_correlation_token enforces only ONE OPEN incident per threat_vector_key.
3. Generation coexistence: multiple CLOSED generations can coexist with one OPEN generation.
4. Composite unique constraint uq_threat_vector_generation rejects duplicate generations for the same threat_vector_key.
5. Check constraint ck_no_self_duplicate rejects duplicate_of_incident_id == id.
6. Check constraint ck_no_self_preceding rejects preceding_incident_id == id.
7. Unique constraint uq_incident_evidence rejects duplicate evidence linkage.
8. Database-level check constraint ck_incident_comments_max_length enforces comment_text <= 2000 chars.
9. Immutability trigger trg_incident_evidence_links_immutable rejects UPDATE and DELETE on evidence links.
10. Immutability trigger trg_incident_comments_immutable rejects UPDATE and DELETE on incident comments.
11. Immutability trigger trg_security_incidents_no_delete rejects DELETE on security incidents.
12. OCC version field atomic CAS semantics (expected version match succeeds, mismatch updates 0 rows).
13. Backward compatibility: legacy Incident and SecurityEvent models remain untouched and operational.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from pathlib import Path
import pytest
import asyncpg

from app.core.database import AsyncSessionLocal
from app.core.models import (
    User,
    UserRoleEnum,
    SecurityIncident,
    IncidentEvidenceLink,
    IncidentComment,
    SecurityIncidentStatus,
    SecurityIncidentSeverity,
    CorrelationStatus,
    SealVerificationStatus,
    EvidenceType,
    Incident,
    IncidentSeverity,
    IncidentStatus,
    SecurityEvent,
)

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


def run_in_session(coro_fn):
    """Execute test in an isolated SQLAlchemy session with guaranteed rollback."""
    async def _exec():
        async with AsyncSessionLocal() as session:
            try:
                await coro_fn(session)
            finally:
                await session.rollback()
    asyncio.run(_exec())


async def _ensure_test_user(conn) -> str:
    """Helper to ensure a valid user ID exists for foreign key references."""
    user_id = await conn.fetchval("SELECT id FROM users LIMIT 1;")
    if not user_id:
        user_id = str(uuid.uuid4())
        await conn.execute(
            """
            INSERT INTO users (id, email, hashed_password, full_name, role, is_active, created_at)
            VALUES ($1, $2, 'mock_hash', 'Sec Officer Test', 'SECURITY_OFFICER', true, NOW());
            """,
            user_id,
            f"sec_officer_{uuid.uuid4().hex[:8]}@bsea.gov.in",
        )
    return str(user_id)


# --- Test 1: Security incident creation defaults and initial OCC version=1 ---

def test_01_security_incident_creation_defaults():
    async def _test(conn):
        inc_id = str(uuid.uuid4())
        threat_key = "a" * 64
        inc_num = f"INC-{uuid.uuid4().hex[:12].upper()}"

        await conn.execute(
            """
            INSERT INTO security_incidents (
                id, incident_number, threat_vector_key, generation, title, description,
                incident_type, rule_id, canonical_rule_id, exam_id, dimensions_json,
                first_signal_at, latest_signal_at, created_at, updated_at
            ) VALUES (
                $1, $2, $3, 1, 'Suspicious Rapid Navigation', 'Multiple rapid clicks detected.',
                'RAPID_NAVIGATION', 'RULE_001', 'CANONICAL_001', 'exam_1', '{}',
                NOW(), NOW(), NOW(), NOW()
            );
            """,
            inc_id, inc_num, threat_key
        )

        row = await conn.fetchrow("SELECT * FROM security_incidents WHERE id = $1;", inc_id)
        assert row is not None
        assert row["status"] == "TRIAGE"
        assert row["severity"] == "MEDIUM"
        assert row["correlation_status"] == "OPEN"
        assert row["seal_verification_status"] == "UNCONTAINED"
        assert row["version"] == 1
        assert row["generation"] == 1
        assert row["threat_vector_key"] == threat_key

    run_in_rollback(_test)


# --- Test 2: Partial unique index uq_active_correlation_token enforcement ---

def test_02_partial_unique_index_active_correlation_enforcement():
    async def _test(conn):
        threat_key = "c" * 64
        inc_id1 = str(uuid.uuid4())
        inc_id2 = str(uuid.uuid4())

        await conn.execute(
            """
            INSERT INTO security_incidents (
                id, incident_number, threat_vector_key, generation, title, description,
                incident_type, rule_id, canonical_rule_id, exam_id, dimensions_json,
                correlation_status, first_signal_at, latest_signal_at, created_at, updated_at
            ) VALUES (
                $1, $2, $3, 1, 'First Active Incident', 'Active threat.',
                'RAPID_NAVIGATION', 'RULE_001', 'CANONICAL_001', 'exam_1', '{}',
                'OPEN', NOW(), NOW(), NOW(), NOW()
            );
            """,
            inc_id1, f"INC-{uuid.uuid4().hex[:12].upper()}", threat_key
        )

        # Second incident with SAME threat_vector_key and correlation_status = 'OPEN' must fail
        with pytest.raises(asyncpg.UniqueViolationError) as exc_info:
            async with conn.transaction():
                await conn.execute(
                    """
                    INSERT INTO security_incidents (
                        id, incident_number, threat_vector_key, generation, title, description,
                        incident_type, rule_id, canonical_rule_id, exam_id, dimensions_json,
                        correlation_status, first_signal_at, latest_signal_at, created_at, updated_at
                    ) VALUES (
                        $1, $2, $3, 2, 'Conflicting Active Incident', 'Conflicting threat.',
                        'RAPID_NAVIGATION', 'RULE_001', 'CANONICAL_001', 'exam_1', '{}',
                        'OPEN', NOW(), NOW(), NOW(), NOW()
                    );
                    """,
                    inc_id2, f"INC-{uuid.uuid4().hex[:12].upper()}", threat_key
                )

        assert "uq_active_correlation_token" in str(exc_info.value)

    run_in_rollback(_test)


# --- Test 3: Generation coexistence when previous is CLOSED ---

def test_03_generation_coexistence_when_previous_closed():
    async def _test(conn):
        threat_key = "d" * 64
        inc_id1 = str(uuid.uuid4())
        inc_id2 = str(uuid.uuid4())

        # Generation 1 closed
        await conn.execute(
            """
            INSERT INTO security_incidents (
                id, incident_number, threat_vector_key, generation, title, description,
                incident_type, rule_id, canonical_rule_id, exam_id, dimensions_json,
                status, correlation_status, first_signal_at, latest_signal_at, created_at, updated_at
            ) VALUES (
                $1, $2, $3, 1, 'Resolved Generation 1', 'Historic threat.',
                'RAPID_NAVIGATION', 'RULE_001', 'CANONICAL_001', 'exam_1', '{}',
                'RESOLVED', 'CLOSED', NOW(), NOW(), NOW(), NOW()
            );
            """,
            inc_id1, f"INC-{uuid.uuid4().hex[:12].upper()}", threat_key
        )

        # Generation 2 open for same threat_vector_key must SUCCEED
        await conn.execute(
            """
            INSERT INTO security_incidents (
                id, incident_number, threat_vector_key, generation, title, description,
                incident_type, rule_id, canonical_rule_id, exam_id, dimensions_json,
                status, correlation_status, first_signal_at, latest_signal_at, created_at, updated_at
            ) VALUES (
                $1, $2, $3, 2, 'New Generation 2', 'Current threat.',
                'RAPID_NAVIGATION', 'RULE_001', 'CANONICAL_001', 'exam_1', '{}',
                'TRIAGE', 'OPEN', NOW(), NOW(), NOW(), NOW()
            );
            """,
            inc_id2, f"INC-{uuid.uuid4().hex[:12].upper()}", threat_key
        )

        count = await conn.fetchval(
            "SELECT COUNT(*) FROM security_incidents WHERE threat_vector_key = $1;", threat_key
        )
        assert count == 2

    run_in_rollback(_test)


# --- Test 4: Composite generation uniqueness (uq_threat_vector_generation) ---

def test_04_composite_generation_uniqueness():
    async def _test(conn):
        threat_key = "e" * 64
        inc_id1 = str(uuid.uuid4())
        inc_id2 = str(uuid.uuid4())

        await conn.execute(
            """
            INSERT INTO security_incidents (
                id, incident_number, threat_vector_key, generation, title, description,
                incident_type, rule_id, canonical_rule_id, exam_id, dimensions_json,
                correlation_status, first_signal_at, latest_signal_at, created_at, updated_at
            ) VALUES (
                $1, $2, $3, 1, 'Gen 1 First Instance', 'Gen 1.',
                'RAPID_NAVIGATION', 'RULE_001', 'CANONICAL_001', 'exam_1', '{}',
                'CLOSED', NOW(), NOW(), NOW(), NOW()
            );
            """,
            inc_id1, f"INC-{uuid.uuid4().hex[:12].upper()}", threat_key
        )

        # Duplicate (threat_vector_key, generation=1) must FAIL
        with pytest.raises(asyncpg.UniqueViolationError) as exc_info:
            async with conn.transaction():
                await conn.execute(
                    """
                    INSERT INTO security_incidents (
                        id, incident_number, threat_vector_key, generation, title, description,
                        incident_type, rule_id, canonical_rule_id, exam_id, dimensions_json,
                        correlation_status, first_signal_at, latest_signal_at, created_at, updated_at
                    ) VALUES (
                        $1, $2, $3, 1, 'Gen 1 Duplicate Instance', 'Duplicate Gen 1.',
                        'RAPID_NAVIGATION', 'RULE_001', 'CANONICAL_001', 'exam_1', '{}',
                        'CLOSED', NOW(), NOW(), NOW(), NOW()
                    );
                    """,
                    inc_id2, f"INC-{uuid.uuid4().hex[:12].upper()}", threat_key
                )

        assert "uq_threat_vector_generation" in str(exc_info.value)

    run_in_rollback(_test)


# --- Test 5: Check constraint ck_no_self_duplicate ---

def test_05_no_self_duplicate_constraint():
    async def _test(conn):
        inc_id = str(uuid.uuid4())
        threat_key = "f" * 64

        with pytest.raises(asyncpg.CheckViolationError) as exc_info:
            async with conn.transaction():
                await conn.execute(
                    """
                    INSERT INTO security_incidents (
                        id, incident_number, threat_vector_key, generation, title, description,
                        incident_type, rule_id, canonical_rule_id, exam_id, dimensions_json,
                        duplicate_of_incident_id, first_signal_at, latest_signal_at, created_at, updated_at
                    ) VALUES (
                        $1, $2, $3, 1, 'Self Duplicate Test', 'Invalid self reference.',
                        'RAPID_NAVIGATION', 'RULE_001', 'CANONICAL_001', 'exam_1', '{}',
                        $1, NOW(), NOW(), NOW(), NOW()
                    );
                    """,
                    inc_id, f"INC-{uuid.uuid4().hex[:12].upper()}", threat_key
                )

        assert "ck_no_self_duplicate" in str(exc_info.value)

    run_in_rollback(_test)


# --- Test 6: Check constraint ck_no_self_preceding ---

def test_06_no_self_preceding_constraint():
    async def _test(conn):
        inc_id = str(uuid.uuid4())
        threat_key = "1" * 64

        with pytest.raises(asyncpg.CheckViolationError) as exc_info:
            async with conn.transaction():
                await conn.execute(
                    """
                    INSERT INTO security_incidents (
                        id, incident_number, threat_vector_key, generation, title, description,
                        incident_type, rule_id, canonical_rule_id, exam_id, dimensions_json,
                        preceding_incident_id, first_signal_at, latest_signal_at, created_at, updated_at
                    ) VALUES (
                        $1, $2, $3, 1, 'Self Preceding Test', 'Invalid self predecessor.',
                        'RAPID_NAVIGATION', 'RULE_001', 'CANONICAL_001', 'exam_1', '{}',
                        $1, NOW(), NOW(), NOW(), NOW()
                    );
                    """,
                    inc_id, f"INC-{uuid.uuid4().hex[:12].upper()}", threat_key
                )

        assert "ck_no_self_preceding" in str(exc_info.value)

    run_in_rollback(_test)


# --- Test 7: Unique constraint uq_incident_evidence ---

def test_07_evidence_link_uniqueness():
    async def _test(conn):
        user_id = await _ensure_test_user(conn)
        inc_id = str(uuid.uuid4())
        threat_key = "2" * 64
        await conn.execute(
            """
            INSERT INTO security_incidents (
                id, incident_number, threat_vector_key, generation, title, description,
                incident_type, rule_id, canonical_rule_id, exam_id, dimensions_json,
                first_signal_at, latest_signal_at, created_at, updated_at
            ) VALUES (
                $1, $2, $3, 1, 'Evidence Test Parent', 'Parent incident.',
                'RAPID_NAVIGATION', 'RULE_001', 'CANONICAL_001', 'exam_1', '{}',
                NOW(), NOW(), NOW(), NOW()
            );
            """,
            inc_id, f"INC-{uuid.uuid4().hex[:12].upper()}", threat_key
        )

        ev_ref_id = str(uuid.uuid4())
        link_id1 = str(uuid.uuid4())
        link_id2 = str(uuid.uuid4())

        await conn.execute(
            """
            INSERT INTO incident_evidence_links (
                id, incident_id, evidence_type, evidence_reference_id, evidence_hash, attached_by, attached_at
            ) VALUES ($1, $2, 'AUDIT_EVENT', $3, 'hash_abc', $4, NOW());
            """,
            link_id1, inc_id, ev_ref_id, user_id
        )

        # Duplicate link with same (incident_id, evidence_reference_id) must FAIL
        with pytest.raises(asyncpg.UniqueViolationError) as exc_info:
            async with conn.transaction():
                await conn.execute(
                    """
                    INSERT INTO incident_evidence_links (
                        id, incident_id, evidence_type, evidence_reference_id, evidence_hash, attached_by, attached_at
                    ) VALUES ($1, $2, 'AUDIT_EVENT', $3, 'hash_abc', $4, NOW());
                    """,
                    link_id2, inc_id, ev_ref_id, user_id
                )

        assert "uq_incident_evidence" in str(exc_info.value)

    run_in_rollback(_test)


# --- Test 8: Comment length constraint at database level (ck_incident_comments_max_length) ---

def test_08_comment_length_constraint_at_db_level():
    async def _test(conn):
        user_id = await _ensure_test_user(conn)
        inc_id = str(uuid.uuid4())
        threat_key = "3" * 64

        await conn.execute(
            """
            INSERT INTO security_incidents (
                id, incident_number, threat_vector_key, generation, title, description,
                incident_type, rule_id, canonical_rule_id, exam_id, dimensions_json,
                first_signal_at, latest_signal_at, created_at, updated_at
            ) VALUES (
                $1, $2, $3, 1, 'Comment Test Incident', 'Incident for comment length test.',
                'RAPID_NAVIGATION', 'RULE_001', 'CANONICAL_001', 'exam_1', '{}',
                NOW(), NOW(), NOW(), NOW()
            );
            """,
            inc_id, f"INC-{uuid.uuid4().hex[:12].upper()}", threat_key
        )

        # Exactly 2000 characters must succeed
        valid_text = "X" * 2000
        comm_id_valid = str(uuid.uuid4())
        await conn.execute(
            """
            INSERT INTO incident_comments (
                id, incident_id, author_id, comment_text, created_at
            ) VALUES ($1, $2, $3, $4, NOW());
            """,
            comm_id_valid, inc_id, user_id, valid_text
        )

        saved = await conn.fetchval(
            "SELECT length(comment_text) FROM incident_comments WHERE id = $1;", comm_id_valid
        )
        assert saved == 2000

        # 2001 characters must FAIL at database level
        invalid_text = "X" * 2001
        comm_id_invalid = str(uuid.uuid4())
        with pytest.raises((asyncpg.CheckViolationError, asyncpg.StringDataRightTruncationError)) as exc_info:
            async with conn.transaction():
                await conn.execute(
                    """
                    INSERT INTO incident_comments (
                        id, incident_id, author_id, comment_text, created_at
                    ) VALUES ($1, $2, $3, $4, NOW());
                    """,
                    comm_id_invalid, inc_id, user_id, invalid_text
                )

        error_msg = str(exc_info.value)
        assert "ck_incident_comments_max_length" in error_msg or "value too long" in error_msg

    run_in_rollback(_test)


# --- Test 9: Immutability trigger blocks evidence link UPDATE and DELETE ---

def test_09_immutability_trigger_blocks_evidence_link_update_and_delete():
    async def _test(conn):
        user_id = await _ensure_test_user(conn)
        inc_id = str(uuid.uuid4())
        threat_key = "4" * 64
        await conn.execute(
            """
            INSERT INTO security_incidents (
                id, incident_number, threat_vector_key, generation, title, description,
                incident_type, rule_id, canonical_rule_id, exam_id, dimensions_json,
                first_signal_at, latest_signal_at, created_at, updated_at
            ) VALUES (
                $1, $2, $3, 1, 'Trigger Evidence Link Incident', 'Incident for trigger test.',
                'RAPID_NAVIGATION', 'RULE_001', 'CANONICAL_001', 'exam_1', '{}',
                NOW(), NOW(), NOW(), NOW()
            );
            """,
            inc_id, f"INC-{uuid.uuid4().hex[:12].upper()}", threat_key
        )

        link_id = str(uuid.uuid4())
        await conn.execute(
            """
            INSERT INTO incident_evidence_links (
                id, incident_id, evidence_type, evidence_reference_id, evidence_hash, attached_by, attached_at
            ) VALUES ($1, $2, 'DETECTION_SIGNAL', 'sig_123', 'hash_sig', $3, NOW());
            """,
            link_id, inc_id, user_id
        )

        # UPDATE must be rejected by trg_prevent_audit_mutation trigger
        with pytest.raises(asyncpg.IntegrityConstraintViolationError) as exc_update:
            async with conn.transaction():
                await conn.execute(
                    "UPDATE incident_evidence_links SET evidence_reference_id = 'sig_tampered' WHERE id = $1;",
                    link_id
                )
        assert "strictly immutable" in str(exc_update.value)
        assert "UPDATE and DELETE operations are forbidden" in str(exc_update.value)

        # DELETE must be rejected by trg_prevent_audit_mutation trigger
        with pytest.raises(asyncpg.IntegrityConstraintViolationError) as exc_delete:
            async with conn.transaction():
                await conn.execute(
                    "DELETE FROM incident_evidence_links WHERE id = $1;", link_id
                )
        assert "strictly immutable" in str(exc_delete.value)
        assert "UPDATE and DELETE operations are forbidden" in str(exc_delete.value)

    run_in_rollback(_test)


# --- Test 10: Immutability trigger blocks comment UPDATE and DELETE ---

def test_10_immutability_trigger_blocks_comment_update_and_delete():
    async def _test(conn):
        user_id = await _ensure_test_user(conn)
        inc_id = str(uuid.uuid4())
        threat_key = "5" * 64
        await conn.execute(
            """
            INSERT INTO security_incidents (
                id, incident_number, threat_vector_key, generation, title, description,
                incident_type, rule_id, canonical_rule_id, exam_id, dimensions_json,
                first_signal_at, latest_signal_at, created_at, updated_at
            ) VALUES (
                $1, $2, $3, 1, 'Trigger Comment Incident', 'Incident for trigger test.',
                'RAPID_NAVIGATION', 'RULE_001', 'CANONICAL_001', 'exam_1', '{}',
                NOW(), NOW(), NOW(), NOW()
            );
            """,
            inc_id, f"INC-{uuid.uuid4().hex[:12].upper()}", threat_key
        )

        comment_id = str(uuid.uuid4())
        await conn.execute(
            """
            INSERT INTO incident_comments (
                id, incident_id, author_id, comment_text, created_at
            ) VALUES ($1, $2, $3, 'Official forensic note.', NOW());
            """,
            comment_id, inc_id, user_id
        )

        # UPDATE must be rejected by trg_prevent_audit_mutation trigger
        with pytest.raises(asyncpg.IntegrityConstraintViolationError) as exc_update:
            async with conn.transaction():
                await conn.execute(
                    "UPDATE incident_comments SET comment_text = 'Tampered forensic note.' WHERE id = $1;",
                    comment_id
                )
        assert "strictly immutable" in str(exc_update.value)
        assert "UPDATE and DELETE operations are forbidden" in str(exc_update.value)

        # DELETE must be rejected by trg_prevent_audit_mutation trigger
        with pytest.raises(asyncpg.IntegrityConstraintViolationError) as exc_delete:
            async with conn.transaction():
                await conn.execute(
                    "DELETE FROM incident_comments WHERE id = $1;", comment_id
                )
        assert "strictly immutable" in str(exc_delete.value)
        assert "UPDATE and DELETE operations are forbidden" in str(exc_delete.value)

    run_in_rollback(_test)


# --- Test 11: Incident deletion blocked by trigger ---

def test_11_incident_deletion_blocked_by_trigger():
    async def _test(conn):
        inc_id = str(uuid.uuid4())
        threat_key = "6" * 64
        await conn.execute(
            """
            INSERT INTO security_incidents (
                id, incident_number, threat_vector_key, generation, title, description,
                incident_type, rule_id, canonical_rule_id, exam_id, dimensions_json,
                first_signal_at, latest_signal_at, created_at, updated_at
            ) VALUES (
                $1, $2, $3, 1, 'Incident No Delete Test', 'Incident deletion guard.',
                'RAPID_NAVIGATION', 'RULE_001', 'CANONICAL_001', 'exam_1', '{}',
                NOW(), NOW(), NOW(), NOW()
            );
            """,
            inc_id, f"INC-{uuid.uuid4().hex[:12].upper()}", threat_key
        )

        # DELETE must be rejected by trg_security_incidents_no_delete
        with pytest.raises(asyncpg.IntegrityConstraintViolationError) as exc_delete:
            async with conn.transaction():
                await conn.execute("DELETE FROM security_incidents WHERE id = $1;", inc_id)

        assert "strictly immutable" in str(exc_delete.value)
        assert "UPDATE and DELETE operations are forbidden" in str(exc_delete.value)

    run_in_rollback(_test)


# --- Test 12: OCC version field integrity and atomic CAS semantics ---

def test_12_occ_version_field_integrity():
    async def _test(conn):
        inc_id = str(uuid.uuid4())
        threat_key = "7" * 64
        await conn.execute(
            """
            INSERT INTO security_incidents (
                id, incident_number, threat_vector_key, generation, title, description,
                incident_type, rule_id, canonical_rule_id, exam_id, dimensions_json,
                version, first_signal_at, latest_signal_at, created_at, updated_at
            ) VALUES (
                $1, $2, $3, 1, 'Initial OCC Title', 'Initial description.',
                'RAPID_NAVIGATION', 'RULE_001', 'CANONICAL_001', 'exam_1', '{}',
                1, NOW(), NOW(), NOW(), NOW()
            );
            """,
            inc_id, f"INC-{uuid.uuid4().hex[:12].upper()}", threat_key
        )

        # CAS update with expected version = 1 succeeds and increments to 2
        res1 = await conn.execute(
            """
            UPDATE security_incidents
            SET title = 'Updated Title v2', version = version + 1, updated_at = NOW()
            WHERE id = $1 AND version = 1;
            """,
            inc_id
        )
        assert res1 == "UPDATE 1"

        new_version = await conn.fetchval(
            "SELECT version FROM security_incidents WHERE id = $1;", inc_id
        )
        assert new_version == 2

        # Stale CAS update with version = 1 (when current is 2) must match ZERO rows
        res2 = await conn.execute(
            """
            UPDATE security_incidents
            SET title = 'Stale Update', version = version + 1, updated_at = NOW()
            WHERE id = $1 AND version = 1;
            """,
            inc_id
        )
        assert res2 == "UPDATE 0"

        unchanged_title = await conn.fetchval(
            "SELECT title FROM security_incidents WHERE id = $1;", inc_id
        )
        assert unchanged_title == "Updated Title v2"

    run_in_rollback(_test)


# --- Test 13: Backward compatibility of legacy models ---

def test_13_backward_compatibility_legacy_models():
    # Legacy Incident and SecurityEvent must still be instantiable and distinct
    legacy_incident = Incident(
        id=str(uuid.uuid4()),
        title="Legacy Incident Title",
        description="Legacy incident model test",
        severity=IncidentSeverity.HIGH,
        status=IncidentStatus.OPEN,
        created_by=str(uuid.uuid4()),
    )
    assert legacy_incident.__tablename__ == "incidents"
    assert legacy_incident.title == "Legacy Incident Title"

    legacy_event = SecurityEvent(
        id=str(uuid.uuid4()),
        event_type="UNAUTHORIZED_ACCESS",
        severity="HIGH",
        risk_score=75.0,
    )
    assert legacy_event.__tablename__ == "security_events"

    # New model has distinct tablename and Rev-06 architecture
    new_incident = SecurityIncident(
        incident_number="INC-2026-TEST",
        threat_vector_key="8" * 64,
        title="Modern 5D Incident",
        description="Modern 5D Incident Model",
        incident_type="UNAUTHORIZED_ACCESS",
        rule_id="RULE_003",
        canonical_rule_id="CANONICAL_003",
        exam_id="exam_3",
        dimensions_json={},
        version=1,
        correlation_status=CorrelationStatus.OPEN,
    )
    assert new_incident.__tablename__ == "security_incidents"
    assert new_incident.version == 1
    assert new_incident.correlation_status == CorrelationStatus.OPEN
    assert new_incident.__tablename__ != legacy_incident.__tablename__
    assert new_incident.__tablename__ != legacy_event.__tablename__
