"""
Phase 3C-5D: Security Incident Management Foundation ?" Step 2 Service & Correlation Test Matrix
Conforming to BSEA_PHASE3C_5D_SECURITY_INCIDENT_MANAGEMENT_ARCHITECTURE_REVIEW_REV06.md.

Test Matrix:
  test_01: Canonical threat-vector identity determinism (RFC 8785 JCS key order independence)
  test_02: Dimension normalization behavior (semantical typing, trimming, empty rejection)
  test_03: Rejection of temporal data in threat vector identity
  test_04: First signal creates Generation 1
  test_05: Repeated signal within rolling 3600s attaches to same generation
  test_06: Signal after >3600s inactivity creates next generation (Inactivity Rollover)
  test_07: Generation lineage preservation (preceding_incident_id)
  test_08: No generation reuse across closed generations
  test_09: OPEN-generation uniqueness enforced by database and service
  test_10: Concurrent first-generation creation race (multi-connection safety)
  test_11: Concurrent generation rollover race (multi-connection safety)
  test_12: Zero signal loss during concurrent rollover race
  test_13: Human incident reopening does NOT reopen correlation_status
  test_14: Lifecycle transition validation (state machine matrix & role authorization)
  test_15: OCC version field conflict behavior (stale version raises OptimisticLockError)
  test_16: Database failure and transaction rollback isolation (advisory lock auto-release)
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import json
import uuid
from typing import Any, Dict, List
import pytest
import asyncpg
from sqlalchemy import select, update, text

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
)
from app.modules.incidents.identity import (
    generate_threat_vector_key,
    normalize_canonical_rule_id,
    normalize_dimensions,
    normalize_exam_id,
    normalize_policy_version,
    derive_advisory_lock_key,
)
from app.modules.incidents.exceptions import (
    IncidentNotFoundError,
    InvalidStateTransitionError,
    OptimisticLockError,
    InvalidCommentError,
    InvalidEvidenceError,
    UnauthorizedActionError,
    TemporalIdentityError,
    InvalidDimensionError,
)
from app.modules.incidents.service import SecurityIncidentService

DB_URL = "postgresql://postgres:root@localhost:5432/bsea"


def run_async(coro_fn):
    """Synchronous test wrapper running coroutine."""
    asyncio.run(coro_fn())


async def _ensure_officer(conn) -> str:
    user_id = await conn.fetchval(
        "SELECT id FROM users WHERE role = 'SECURITY_OFFICER' LIMIT 1;"
    )
    if not user_id:
        user_id = str(uuid.uuid4())
        await conn.execute(
            """
            INSERT INTO users (id, email, hashed_password, full_name, role, is_active, created_at)
            VALUES ($1, $2, 'mock_hash', 'Security Officer Test', 'SECURITY_OFFICER', true, NOW());
            """,
            user_id,
            f"sec_officer_{uuid.uuid4().hex[:8]}@bsea.gov.in",
        )
    return str(user_id)


async def _ensure_superadmin(conn) -> str:
    user_id = await conn.fetchval(
        "SELECT id FROM users WHERE role = 'SUPER_ADMIN' LIMIT 1;"
    )
    if not user_id:
        user_id = str(uuid.uuid4())
        await conn.execute(
            """
            INSERT INTO users (id, email, hashed_password, full_name, role, is_active, created_at)
            VALUES ($1, $2, 'mock_hash', 'Super Admin Test', 'SUPER_ADMIN', true, NOW());
            """,
            user_id,
            f"super_admin_{uuid.uuid4().hex[:8]}@bsea.gov.in",
        )
    return str(user_id)


# === Test 01: Canonical Threat-Vector Identity Determinism ===

def test_01_canonical_threat_vector_identity_determinism():
    # RFC 8785 JCS key order independence: two dicts with reverse key ordering must produce identical key
    dims1 = {"node_id": "NODE-042", "candidate_id": "CAND-001"}
    dims2 = {"candidate_id": "CAND-001", "node_id": "NODE-042"}

    k1 = generate_threat_vector_key("R-003", dims1, exam_id="EXAM-99", policy_version="v1")
    k2 = generate_threat_vector_key("R-003", dims2, exam_id="EXAM-99", policy_version="v1")

    assert k1 == k2
    assert len(k1) == 64
    assert all(c in "0123456789abcdef" for c in k1)


# === Test 02: Dimension Normalization Behavior ===

def test_02_dimension_normalization_behavior():
    # 1. IP address expansion and UUID lowercase
    dims = {
        "candidate_id": "cand-001",
        "ip_address": "192.168.1.1",
        "session_id": "550E8400-E29B-41D4-A716-446655440000",
        "empty_field": "   ",
        "none_field": None,
    }
    norm = normalize_dimensions(dims)
    assert norm["candidate_id"] == "CAND-001"
    assert norm["ip_address"] == "192.168.1.1"
    assert norm["session_id"] == "550e8400-e29b-41d4-a716-446655440000"
    assert "empty_field" not in norm
    assert "none_field" not in norm

    # 2. Rule ID normalization
    assert normalize_canonical_rule_id("rule-a.v1") == "RULE-A"
    assert normalize_canonical_rule_id("R-003-V2") == "R-003"

    # 3. Empty dimension rejection
    with pytest.raises(InvalidDimensionError):
        normalize_dimensions({})

    with pytest.raises(InvalidDimensionError):
        normalize_dimensions({"blank": "   "})


# === Test 03: Rejection of Temporal Data in Threat Vector Identity ===

def test_03_rejection_of_temporal_data_in_identity():
    # Attempting to put temporal parameters in dimensions must be rejected
    for forbidden_key in ["timestamp", "generation", "window", "detected_at", "created_at"]:
        with pytest.raises(TemporalIdentityError) as exc_info:
            generate_threat_vector_key("RULE-A", {"actor_id": "usr-1", forbidden_key: "2026-09-16"})
        assert "strictly forbidden" in str(exc_info.value)


# === Test 04: First Signal Creates Generation 1 ===

def test_04_first_signal_creates_generation_1():
    async def _test():
        service = SecurityIncidentService()
        unique_actor = f"usr_{uuid.uuid4().hex[:8]}"
        signal = {
            "rule_id": "RULE-A",
            "correlation_keys": {"actor_id": unique_actor},
            "severity": "HIGH",
            "signal_id": f"sig_{uuid.uuid4().hex[:8]}",
            "title": "Rapid Unauthorized Navigation",
            "explanation": "Detected 20 navigation clicks within 5 seconds.",
        }

        t0 = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        inc, ev_link, is_new = await service.correlate_signal(signal, arrival_time=t0)

        assert is_new is True
        assert inc.generation == 1
        assert inc.correlation_status == CorrelationStatus.OPEN
        assert inc.status == SecurityIncidentStatus.TRIAGE
        assert inc.severity == SecurityIncidentSeverity.HIGH
        assert inc.version == 1
        assert inc.preceding_incident_id is None
        assert ev_link.evidence_reference_id == signal["signal_id"]

    run_async(_test)


# === Test 05: Repeated Signal Within Rolling 3600s Attaches to Same Generation ===

def test_05_repeated_signal_within_3600s_same_generation():
    async def _test():
        service = SecurityIncidentService()
        unique_actor = f"usr_{uuid.uuid4().hex[:8]}"

        t0 = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        sig1 = {
            "rule_id": "RULE-B",
            "correlation_keys": {"actor_id": unique_actor},
            "severity": "MEDIUM",
            "signal_id": f"sig1_{uuid.uuid4().hex[:8]}",
        }
        sig2 = {
            "rule_id": "RULE-B",
            "correlation_keys": {"actor_id": unique_actor},
            "severity": "HIGH",  # Should trigger severity upgrade
            "signal_id": f"sig2_{uuid.uuid4().hex[:8]}",
        }

        inc1, link1, is_new1 = await service.correlate_signal(sig1, arrival_time=t0)
        assert is_new1 is True
        assert inc1.generation == 1
        assert inc1.severity == SecurityIncidentSeverity.MEDIUM

        # Signal 2 arrives 20 minutes later (1200 seconds <= 3600 seconds)
        t1 = t0 + timedelta(seconds=1200)
        inc2, link2, is_new2 = await service.correlate_signal(sig2, arrival_time=t1)

        assert is_new2 is False
        assert inc2.id == inc1.id
        assert inc2.generation == 1
        assert inc2.correlation_status == CorrelationStatus.OPEN
        assert inc2.severity == SecurityIncidentSeverity.HIGH  # Upgraded
        assert link2.evidence_reference_id == sig2["signal_id"]

    run_async(_test)


# === Test 06: Signal After >3600s Inactivity Creates Next Generation ===

def test_06_signal_after_inactivity_creates_next_generation():
    async def _test():
        conn = await asyncpg.connect(DB_URL)
        service = SecurityIncidentService()
        unique_actor = f"usr_{uuid.uuid4().hex[:8]}"

        t0 = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        sig1 = {
            "rule_id": "RULE-C",
            "correlation_keys": {"actor_id": unique_actor},
            "severity": "MEDIUM",
            "signal_id": f"sig1_{uuid.uuid4().hex[:8]}",
        }

        try:
            inc1, _, is_new1 = await service.correlate_signal(sig1, arrival_time=t0)
            assert is_new1 is True
            assert inc1.generation == 1

            # Signal 2 arrives 3601 seconds later (> 3600s rollover)
            t1 = t0 + timedelta(seconds=3601)
            sig2 = {
                "rule_id": "RULE-C",
                "correlation_keys": {"actor_id": unique_actor},
                "severity": "CRITICAL",
                "signal_id": f"sig2_{uuid.uuid4().hex[:8]}",
            }
            inc2, _, is_new2 = await service.correlate_signal(sig2, arrival_time=t1)

            assert is_new2 is True
            assert inc2.generation == 2
            assert inc2.correlation_status == CorrelationStatus.OPEN
            assert inc2.preceding_incident_id == inc1.id

            # Verify Generation 1 is CLOSED
            gen1_status = await conn.fetchval(
                "SELECT correlation_status FROM security_incidents WHERE id = $1;", inc1.id
            )
            assert gen1_status == "CLOSED"
        finally:
            await conn.close()

    run_async(_test)


# === Test 07: Generation Lineage Preservation ===

def test_07_generation_lineage_preservation():
    async def _test():
        conn = await asyncpg.connect(DB_URL)
        service = SecurityIncidentService()
        unique_actor = f"usr_{uuid.uuid4().hex[:8]}"
        threat_key = generate_threat_vector_key("RULE-D", {"actor_id": unique_actor})

        t0 = datetime(2026, 9, 16, 10, 0, 0, tzinfo=timezone.utc)
        try:
            # Gen 1 at T=10:00
            inc1, _, _ = await service.correlate_signal(
                {"rule_id": "RULE-D", "correlation_keys": {"actor_id": unique_actor}}, arrival_time=t0
            )
            # Gen 2 at T=11:30 (>3600s)
            inc2, _, _ = await service.correlate_signal(
                {"rule_id": "RULE-D", "correlation_keys": {"actor_id": unique_actor}}, arrival_time=t0 + timedelta(minutes=90)
            )
            # Gen 3 at T=13:00 (>3600s)
            inc3, _, _ = await service.correlate_signal(
                {"rule_id": "RULE-D", "correlation_keys": {"actor_id": unique_actor}}, arrival_time=t0 + timedelta(minutes=180)
            )

            assert inc1.generation == 1
            assert inc1.preceding_incident_id is None

            assert inc2.generation == 2
            assert inc2.preceding_incident_id == inc1.id

            assert inc3.generation == 3
            assert inc3.preceding_incident_id == inc2.id

            # Database check: exactly 3 rows, exactly 1 OPEN
            open_count = await conn.fetchval(
                "SELECT count(*) FROM security_incidents WHERE threat_vector_key = $1 AND correlation_status = 'OPEN';",
                threat_key,
            )
            assert open_count == 1
        finally:
            await conn.close()

    run_async(_test)


# === Test 08: No Generation Reuse ===

def test_08_no_generation_reuse():
    async def _test():
        conn = await asyncpg.connect(DB_URL)
        service = SecurityIncidentService()
        unique_actor = f"usr_{uuid.uuid4().hex[:8]}"

        t0 = datetime(2026, 9, 16, 10, 0, 0, tzinfo=timezone.utc)
        try:
            inc1, _, _ = await service.correlate_signal(
                {"rule_id": "RULE-E", "correlation_keys": {"actor_id": unique_actor}}, arrival_time=t0
            )
            # Close Gen 1 manually
            await conn.execute("UPDATE security_incidents SET correlation_status = 'CLOSED' WHERE id = $1;", inc1.id)

            # Next signal must be Gen 2, never reusing Gen 1
            inc2, _, _ = await service.correlate_signal(
                {"rule_id": "RULE-E", "correlation_keys": {"actor_id": unique_actor}}, arrival_time=t0 + timedelta(minutes=5)
            )
            assert inc2.generation == 2
            assert inc2.id != inc1.id

            # Close Gen 2
            await conn.execute("UPDATE security_incidents SET correlation_status = 'CLOSED' WHERE id = $1;", inc2.id)

            # Next signal must be Gen 3
            inc3, _, _ = await service.correlate_signal(
                {"rule_id": "RULE-E", "correlation_keys": {"actor_id": unique_actor}}, arrival_time=t0 + timedelta(minutes=10)
            )
            assert inc3.generation == 3
        finally:
            await conn.close()

    run_async(_test)


# === Test 09: OPEN Generation Uniqueness ===

def test_09_open_generation_uniqueness():
    async def _test():
        conn = await asyncpg.connect(DB_URL)
        unique_actor = f"usr_{uuid.uuid4().hex[:8]}"
        threat_key = generate_threat_vector_key("RULE-F", {"actor_id": unique_actor})

        try:
            service = SecurityIncidentService()
            await service.correlate_signal(
                {"rule_id": "RULE-F", "correlation_keys": {"actor_id": unique_actor}}
            )

            # Attempting manual direct insert of a second OPEN row for same threat key must fail at database level
            with pytest.raises(asyncpg.UniqueViolationError) as exc_info:
                async with conn.transaction():
                    await conn.execute(
                        """
                        INSERT INTO security_incidents (
                            id, incident_number, threat_vector_key, generation, correlation_status,
                            title, description, incident_type, rule_id, canonical_rule_id,
                            exam_id, dimensions_json, first_signal_at, latest_signal_at
                        ) VALUES (
                            $1, 'INC-TEST-CONFLICT', $2, 2, 'OPEN',
                            'Conflict', 'Conflict desc', 'RULE-F', 'RULE-F', 'RULE-F',
                            'GLOBAL', '{}', NOW(), NOW()
                        );
                        """,
                        str(uuid.uuid4()), threat_key
                    )
            assert "uq_active_correlation_token" in str(exc_info.value)
        finally:
            await conn.close()

    run_async(_test)


# === Test 10: Concurrent First-Generation Creation Race ===

def test_10_concurrent_first_generation_creation():
    """Prove that two concurrent workers receiving the initial signal for vector K race safely via advisory lock."""
    async def _test():
        conn = await asyncpg.connect(DB_URL)
        unique_actor = f"usr_{uuid.uuid4().hex[:8]}"

        sig1 = {
            "rule_id": "RULE-A",
            "correlation_keys": {"actor_id": unique_actor},
            "signal_id": f"race_sig_1_{uuid.uuid4().hex[:6]}",
        }
        sig2 = {
            "rule_id": "RULE-A",
            "correlation_keys": {"actor_id": unique_actor},
            "signal_id": f"race_sig_2_{uuid.uuid4().hex[:6]}",
        }

        try:
            # Run two concurrent tasks with independent sessions
            async def _worker(sig):
                async with AsyncSessionLocal() as session:
                    async with session.begin():
                        svc = SecurityIncidentService(db=session)
                        return await svc.correlate_signal(sig)

            results = await asyncio.gather(_worker(sig1), _worker(sig2))
            res1, res2 = results

            inc1, link1, is_new1 = res1
            inc2, link2, is_new2 = res2

            # Exactly one worker created the incident, the other attached
            assert (is_new1 is True and is_new2 is False) or (is_new1 is False and is_new2 is True)
            assert inc1.id == inc2.id
            assert inc1.generation == 1

            # Both evidence links exist
            links = await conn.fetch(
                "SELECT evidence_reference_id FROM incident_evidence_links WHERE incident_id = $1;", inc1.id
            )
            link_refs = {row["evidence_reference_id"] for row in links}
            assert sig1["signal_id"] in link_refs
            assert sig2["signal_id"] in link_refs
        finally:
            await conn.close()

    run_async(_test)


# === Test 11: Concurrent Generation Rollover Race ===

def test_11_concurrent_generation_rollover():
    """Prove that two concurrent workers arriving after >3600s race safely during rollover."""
    async def _test():
        conn = await asyncpg.connect(DB_URL)
        unique_actor = f"usr_{uuid.uuid4().hex[:8]}"
        threat_key = generate_threat_vector_key("RULE-B", {"actor_id": unique_actor})

        t0 = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        svc = SecurityIncidentService()

        try:
            # Initial Gen 1
            inc1, _, _ = await svc.correlate_signal(
                {"rule_id": "RULE-B", "correlation_keys": {"actor_id": unique_actor}}, arrival_time=t0
            )
            assert inc1.generation == 1

            # Both arrive at T0 + 4000s (>3600s) concurrently
            t_rollover = t0 + timedelta(seconds=4000)
            sig1 = {"rule_id": "RULE-B", "correlation_keys": {"actor_id": unique_actor}, "signal_id": f"roll_1_{uuid.uuid4().hex[:6]}"}
            sig2 = {"rule_id": "RULE-B", "correlation_keys": {"actor_id": unique_actor}, "signal_id": f"roll_2_{uuid.uuid4().hex[:6]}"}

            async def _worker(sig):
                async with AsyncSessionLocal() as session:
                    async with session.begin():
                        s = SecurityIncidentService(db=session)
                        return await s.correlate_signal(sig, arrival_time=t_rollover)

            results = await asyncio.gather(_worker(sig1), _worker(sig2))
            res1, res2 = results

            inc_a, _, is_new_a = res1
            inc_b, _, is_new_b = res2

            # Exactly one worker rolled over to Gen 2, the second attached to Gen 2
            assert (is_new_a is True and is_new_b is False) or (is_new_a is False and is_new_b is True)
            assert inc_a.generation == 2
            assert inc_b.generation == 2
            assert inc_a.id == inc_b.id

            # Exactly one OPEN generation exists in DB
            open_gens = await conn.fetch(
                "SELECT id, generation FROM security_incidents WHERE threat_vector_key = $1 AND correlation_status = 'OPEN';",
                threat_key,
            )
            assert len(open_gens) == 1
            assert open_gens[0]["generation"] == 2
        finally:
            await conn.close()

    run_async(_test)


# === Test 12: Zero Signal Loss During Concurrent Rollover Race ===

def test_12_zero_signal_loss_during_rollover_race():
    """Five concurrent workers submit signals during rollover. Prove all 5 signals attached with zero loss."""
    async def _test():
        conn = await asyncpg.connect(DB_URL)
        unique_actor = f"usr_{uuid.uuid4().hex[:8]}"
        threat_key = generate_threat_vector_key("RULE-C", {"actor_id": unique_actor})

        t0 = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        svc = SecurityIncidentService()

        try:
            # Gen 1 at T=0
            inc1, _, _ = await svc.correlate_signal(
                {"rule_id": "RULE-C", "correlation_keys": {"actor_id": unique_actor}}, arrival_time=t0
            )

            # 5 signals arrive at T0 + 5000s concurrently
            t_rollover = t0 + timedelta(seconds=5000)
            signals = [
                {"rule_id": "RULE-C", "correlation_keys": {"actor_id": unique_actor}, "signal_id": f"burst_sig_{i}_{uuid.uuid4().hex[:6]}"}
                for i in range(5)
            ]

            async def _worker(sig):
                async with AsyncSessionLocal() as session:
                    async with session.begin():
                        s = SecurityIncidentService(db=session)
                        return await s.correlate_signal(sig, arrival_time=t_rollover)

            results = await asyncio.gather(*[_worker(s) for s in signals])

            # Total evidence links across all generations for this threat vector must be exactly 6 (1 initial + 5 burst)
            links = await conn.fetch(
                """
                SELECT el.evidence_reference_id
                FROM incident_evidence_links el
                JOIN security_incidents si ON el.incident_id = si.id
                WHERE si.threat_vector_key = $1;
                """,
                threat_key,
            )
            assert len(links) == 6
        finally:
            await conn.close()

    run_async(_test)


# === Test 13: Human Reopen Does NOT Reopen Correlation ===

def test_13_human_reopen_does_not_reopen_correlation():
    """Rev-06 Invariant: Reopening an incident updates human lifecycle to INVESTIGATING but leaves correlation CLOSED."""
    async def _test():
        conn = await asyncpg.connect(DB_URL)
        officer_id = await _ensure_officer(conn)
        svc = SecurityIncidentService()
        unique_actor = f"usr_{uuid.uuid4().hex[:8]}"

        try:
            # 1. Create incident Gen 1
            inc1, _, _ = await svc.correlate_signal(
                {"rule_id": "RULE-D", "correlation_keys": {"actor_id": unique_actor}}
            )

            # 2. Transition TRIAGE -> INVESTIGATING
            inc_inv = await svc.transition_status(
                incident_id=inc1.id,
                new_status=SecurityIncidentStatus.INVESTIGATING,
                expected_version=inc1.version,
                actor_id=officer_id,
                actor_role=UserRoleEnum.SECURITY_OFFICER,
            )

            # 3. Transition INVESTIGATING -> RESOLVED (Closes correlation_status)
            inc_res = await svc.transition_status(
                incident_id=inc1.id,
                new_status=SecurityIncidentStatus.RESOLVED,
                expected_version=inc_inv.version,
                actor_id=officer_id,
                actor_role=UserRoleEnum.SECURITY_OFFICER,
                resolution_summary="False trigger caused by network retry.",
                resolution_category="NETWORK_ANOMALY",
            )
            assert inc_res.status == SecurityIncidentStatus.RESOLVED
            assert inc_res.correlation_status == CorrelationStatus.CLOSED

            # 4. Action REOPEN: Transition RESOLVED -> INVESTIGATING
            inc_reopened = await svc.transition_status(
                incident_id=inc1.id,
                new_status=SecurityIncidentStatus.INVESTIGATING,
                expected_version=inc_res.version,
                actor_id=officer_id,
                actor_role=UserRoleEnum.SECURITY_OFFICER,
                justification="New forensic correlation discovered on target node.",
            )

            assert inc_reopened.status == SecurityIncidentStatus.INVESTIGATING
            # CRITICAL CHECK: correlation_status MUST REMAIN CLOSED
            assert inc_reopened.correlation_status == CorrelationStatus.CLOSED

            # 5. When a new signal arrives, it must initiate Generation 2
            inc_next, _, is_new_next = await svc.correlate_signal(
                {"rule_id": "RULE-D", "correlation_keys": {"actor_id": unique_actor}}
            )
            assert is_new_next is True
            assert inc_next.generation == 2
            assert inc_next.id != inc1.id
        finally:
            await conn.close()

    run_async(_test)


# === Test 14: Lifecycle Transition Validation ===

def test_14_lifecycle_transition_validation():
    """Verify state machine transition constraints and role authorization."""
    async def _test():
        conn = await asyncpg.connect(DB_URL)
        officer_id = await _ensure_officer(conn)
        svc = SecurityIncidentService()
        unique_actor = f"usr_{uuid.uuid4().hex[:8]}"

        try:
            inc, _, _ = await svc.correlate_signal(
                {"rule_id": "RULE-E", "correlation_keys": {"actor_id": unique_actor}}
            )

            # 1. Illegal jump: TRIAGE directly to RESOLVED without investigation
            with pytest.raises(InvalidStateTransitionError):
                await svc.transition_status(
                    incident_id=inc.id,
                    new_status=SecurityIncidentStatus.RESOLVED,
                    expected_version=inc.version,
                    actor_id=officer_id,
                    actor_role=UserRoleEnum.SECURITY_OFFICER,
                    resolution_summary="Premature resolution",
                    resolution_category="ERROR",
                )

            # 2. FALSE_POSITIVE requires >= 20 characters justification
            with pytest.raises(InvalidStateTransitionError):
                await svc.transition_status(
                    incident_id=inc.id,
                    new_status=SecurityIncidentStatus.FALSE_POSITIVE,
                    expected_version=inc.version,
                    actor_id=officer_id,
                    actor_role=UserRoleEnum.SECURITY_OFFICER,
                    justification="Too short",
                )

            # 3. Unauthorized role (AUDITOR cannot transition incidents)
            with pytest.raises(UnauthorizedActionError):
                await svc.assign_incident(
                    incident_id=inc.id,
                    assigned_to=officer_id,
                    expected_version=inc.version,
                    actor_id="auditor_1",
                    actor_role=UserRoleEnum.AUDITOR,
                )
        finally:
            await conn.close()

    run_async(_test)


# === Test 15: OCC Conflict Behavior ===

def test_15_occ_conflict_behavior():
    """Verify OCC atomic update rejects stale version with OptimisticLockError."""
    async def _test():
        conn = await asyncpg.connect(DB_URL)
        officer_id = await _ensure_officer(conn)
        svc = SecurityIncidentService()
        unique_actor = f"usr_{uuid.uuid4().hex[:8]}"

        try:
            inc, _, _ = await svc.correlate_signal(
                {"rule_id": "RULE-F", "correlation_keys": {"actor_id": unique_actor}}
            )
            assert inc.version == 1

            # Stale version 999 must raise OptimisticLockError
            with pytest.raises(OptimisticLockError):
                await svc.transition_status(
                    incident_id=inc.id,
                    new_status=SecurityIncidentStatus.INVESTIGATING,
                    expected_version=999,
                    actor_id=officer_id,
                    actor_role=UserRoleEnum.SECURITY_OFFICER,
                )

            # Correct version increments to 2
            updated_inc = await svc.transition_status(
                incident_id=inc.id,
                new_status=SecurityIncidentStatus.INVESTIGATING,
                expected_version=1,
                actor_id=officer_id,
                actor_role=UserRoleEnum.SECURITY_OFFICER,
            )
            assert updated_inc.version == 2
        finally:
            await conn.close()

    run_async(_test)


# === Test 16: Database Failure and Transaction Rollback Isolation ===

def test_16_database_failure_and_rollback_isolation():
    """Verify that a failure during correlation rolls back cleanly and auto-releases the advisory lock."""
    async def _test():
        conn = await asyncpg.connect(DB_URL)
        unique_actor = f"usr_{uuid.uuid4().hex[:8]}"
        threat_key = generate_threat_vector_key("RULE-G", {"actor_id": unique_actor})

        try:
            # Simulate a failure inside the transaction
            with pytest.raises(RuntimeError):
                async with AsyncSessionLocal() as session:
                    async with session.begin():
                        svc = SecurityIncidentService(db=session)
                        await svc.correlate_signal(
                            {"rule_id": "RULE-G", "correlation_keys": {"actor_id": unique_actor}}
                        )
                        raise RuntimeError("Simulated mid-transaction crash!")

            # Verify zero rows inserted
            count = await conn.fetchval(
                "SELECT count(*) FROM security_incidents WHERE threat_vector_key = $1;", threat_key
            )
            assert count == 0

            # Verify advisory lock was released immediately: can acquire without blocking
            lock_val = await conn.fetchval(
                "SELECT pg_advisory_xact_lock(('x' || substr($1, 1, 16))::bit(64)::bigint);", threat_key
            )
            assert lock_val is None
        finally:
            await conn.close()

    run_async(_test)


# === Test 17: MITIGATED Not Valid Persistent State & CONTAINED Is Observational ===

def test_17_mitigated_not_valid_persistent_state_and_contained_is_observational():
    """
    Prove:
      1. 'MITIGATED' is NOT a valid persistent SecurityIncidentStatus enum value.
      2. Exactly the 7 Rev-06 persistent states exist:
         TRIAGE, INVESTIGATING, CONTAINED, RESOLVED, CLOSED, FALSE_POSITIVE, DUPLICATE.
      3. 'CONTAINED' is the observational 5D milestone (does not alter correlation_status).
    """
    # 1. Verify MITIGATED is rejected by enum
    assert "MITIGATED" not in SecurityIncidentStatus.__members__
    with pytest.raises(ValueError):
        SecurityIncidentStatus("MITIGATED")

    # 2. Verify exact 7 persistent states
    expected_states = {
        "TRIAGE",
        "INVESTIGATING",
        "CONTAINED",
        "RESOLVED",
        "CLOSED",
        "FALSE_POSITIVE",
        "DUPLICATE",
    }
    actual_states = {s.value for s in SecurityIncidentStatus}
    assert actual_states == expected_states, f"State mismatch: {actual_states} != {expected_states}"

    async def _test():
        conn = await asyncpg.connect(DB_URL)
        officer_id = await _ensure_officer(conn)
        svc = SecurityIncidentService()
        unique_actor = f"usr_{uuid.uuid4().hex[:8]}"

        try:
            inc, _, _ = await svc.correlate_signal(
                {"rule_id": "RULE-OBS", "correlation_keys": {"actor_id": unique_actor}}
            )
            assert inc.status == SecurityIncidentStatus.TRIAGE

            # Move TRIAGE -> INVESTIGATING
            inc = await svc.transition_status(
                incident_id=inc.id,
                new_status=SecurityIncidentStatus.INVESTIGATING,
                expected_version=inc.version,
                actor_id=officer_id,
                actor_role=UserRoleEnum.SECURITY_OFFICER,
            )
            assert inc.status == SecurityIncidentStatus.INVESTIGATING

            # Move INVESTIGATING -> CONTAINED (Observational milestone with metadata)
            containment_meta = {
                "containment_reference_id": f"cont_{uuid.uuid4().hex[:8]}",
                "containment_mechanism": "SESSION_INVALIDATION",
                "authorization_principal": officer_id,
                "containment_timestamp": datetime.now(timezone.utc),
                "audit_event_reference": f"aud_{uuid.uuid4().hex[:8]}",
            }
            inc = await svc.transition_status(
                incident_id=inc.id,
                new_status=SecurityIncidentStatus.CONTAINED,
                expected_version=inc.version,
                actor_id=officer_id,
                actor_role=UserRoleEnum.SECURITY_OFFICER,
                containment_data=containment_meta,
            )
            assert inc.status == SecurityIncidentStatus.CONTAINED
            # Observational: correlation_status remains OPEN
            assert inc.correlation_status == CorrelationStatus.OPEN
            assert inc.containment_reference_id == containment_meta["containment_reference_id"]
            assert inc.containment_mechanism == "SESSION_INVALIDATION"
            assert inc.authorization_principal == officer_id

            # Move CONTAINED -> RESOLVED
            inc = await svc.transition_status(
                incident_id=inc.id,
                new_status=SecurityIncidentStatus.RESOLVED,
                expected_version=inc.version,
                actor_id=officer_id,
                actor_role=UserRoleEnum.SECURITY_OFFICER,
                resolution_summary="Remediation verified by security officer",
                resolution_category="FALSE_ALARM_OR_RESOLVED",
            )
            assert inc.status == SecurityIncidentStatus.RESOLVED
            assert inc.correlation_status == CorrelationStatus.CLOSED
        finally:
            await conn.close()

    run_async(_test)


# === Test 18: Authoritative Lifecycle Audit Events Emitted ===

def test_18_authoritative_lifecycle_audit_events_emitted():
    """
    Prove all 8 Rev-06 authoritative audit events are emitted to audit_logs:
      - INCIDENT_CREATED
      - INCIDENT_EVIDENCE_ATTACHED
      - INCIDENT_ASSIGNED
      - INCIDENT_COMMENT_ADDED
      - INCIDENT_STATUS_CHANGED
      - INCIDENT_CLOSED
      - INCIDENT_REOPENED (preserves correlation_status = CLOSED)
      - INCIDENT_CORRELATION_WINDOW_CLOSED
    """
    async def _test():
        conn = await asyncpg.connect(DB_URL)
        officer_id = await _ensure_officer(conn)
        admin_id = await _ensure_superadmin(conn)
        svc = SecurityIncidentService()
        unique_actor = f"usr_{uuid.uuid4().hex[:8]}"
        base_time = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)

        try:
            # 1. INCIDENT_CREATED & INCIDENT_EVIDENCE_ATTACHED
            inc, _, is_new = await svc.correlate_signal(
                {"rule_id": "RULE-AUDIT", "correlation_keys": {"actor_id": unique_actor}},
                arrival_time=base_time,
            )
            assert is_new is True

            # Check audit logs for CREATED and EVIDENCE_ATTACHED
            created_events = await conn.fetch(
                "SELECT event_type, resource_id, event_metadata FROM audit_logs WHERE resource_id = $1 AND event_type = 'INCIDENT_CREATED';",
                inc.id,
            )
            assert len(created_events) >= 1

            evidence_events = await conn.fetch(
                "SELECT event_type, resource_id, event_metadata FROM audit_logs WHERE resource_id = $1 AND event_type = 'INCIDENT_EVIDENCE_ATTACHED';",
                inc.id,
            )
            assert len(evidence_events) >= 1

            # 2. INCIDENT_ASSIGNED
            inc = await svc.assign_incident(
                incident_id=inc.id,
                assigned_to=officer_id,
                expected_version=inc.version,
                actor_id=admin_id,
                actor_role=UserRoleEnum.SUPER_ADMIN,
            )
            assigned_events = await conn.fetch(
                "SELECT event_type, resource_id, event_metadata FROM audit_logs WHERE resource_id = $1 AND event_type = 'INCIDENT_ASSIGNED';",
                inc.id,
            )
            assert len(assigned_events) >= 1

            # 3. INCIDENT_COMMENT_ADDED
            comment = await svc.add_comment(
                incident_id=inc.id,
                comment_text="Investigating initial alert signal details.",
                author_id=officer_id,
                author_role=UserRoleEnum.SECURITY_OFFICER,
            )
            comment_events = await conn.fetch(
                "SELECT event_type, resource_id, event_metadata FROM audit_logs WHERE resource_id = $1 AND event_type = 'INCIDENT_COMMENT_ADDED';",
                inc.id,
            )
            assert len(comment_events) >= 1

            # 4. INCIDENT_STATUS_CHANGED: TRIAGE -> INVESTIGATING
            inc = await svc.transition_status(
                incident_id=inc.id,
                new_status=SecurityIncidentStatus.INVESTIGATING,
                expected_version=inc.version,
                actor_id=officer_id,
                actor_role=UserRoleEnum.SECURITY_OFFICER,
            )
            status_events = await conn.fetch(
                "SELECT event_type, resource_id, event_metadata FROM audit_logs WHERE resource_id = $1 AND event_type = 'INCIDENT_STATUS_CHANGED';",
                inc.id,
            )
            assert len(status_events) >= 1

            # Transition INVESTIGATING -> RESOLVED
            inc = await svc.transition_status(
                incident_id=inc.id,
                new_status=SecurityIncidentStatus.RESOLVED,
                expected_version=inc.version,
                actor_id=officer_id,
                actor_role=UserRoleEnum.SECURITY_OFFICER,
                resolution_summary="Root cause analyzed and mitigated externally.",
                resolution_category="RESOLVED",
            )

            # 5. INCIDENT_CLOSED: RESOLVED -> CLOSED
            inc = await svc.transition_status(
                incident_id=inc.id,
                new_status=SecurityIncidentStatus.CLOSED,
                expected_version=inc.version,
                actor_id=admin_id,
                actor_role=UserRoleEnum.SUPER_ADMIN,
            )
            closed_events = await conn.fetch(
                "SELECT event_type, resource_id, event_metadata FROM audit_logs WHERE resource_id = $1 AND event_type = 'INCIDENT_CLOSED';",
                inc.id,
            )
            assert len(closed_events) >= 1

            # 6. INCIDENT_REOPENED: CLOSED -> INVESTIGATING
            inc = await svc.transition_status(
                incident_id=inc.id,
                new_status=SecurityIncidentStatus.INVESTIGATING,
                expected_version=inc.version,
                actor_id=admin_id,
                actor_role=UserRoleEnum.SUPER_ADMIN,
                justification="New forensics evidence requires reopening this case.",
            )
            reopened_events = await conn.fetch(
                "SELECT event_type, resource_id, event_metadata FROM audit_logs WHERE resource_id = $1 AND event_type = 'INCIDENT_REOPENED';",
                inc.id,
            )
            assert len(reopened_events) >= 1
            # Proves REOPEN preserves correlation_status = CLOSED
            assert inc.correlation_status == CorrelationStatus.CLOSED

            # 7. INCIDENT_CORRELATION_WINDOW_CLOSED (via inactivity rollover)
            unique_actor_2 = f"usr_{uuid.uuid4().hex[:8]}"
            inc2, _, _ = await svc.correlate_signal(
                {"rule_id": "RULE-ROLLOVER-AUDIT", "correlation_keys": {"actor_id": unique_actor_2}},
                arrival_time=base_time,
            )
            rollover_time = base_time + timedelta(seconds=3601)
            inc2_gen2, _, is_new2 = await svc.correlate_signal(
                {"rule_id": "RULE-ROLLOVER-AUDIT", "correlation_keys": {"actor_id": unique_actor_2}},
                arrival_time=rollover_time,
            )
            assert is_new2 is True
            window_closed_events = await conn.fetch(
                "SELECT event_type, resource_id, event_metadata FROM audit_logs WHERE resource_id = $1 AND event_type = 'INCIDENT_CORRELATION_WINDOW_CLOSED';",
                inc2.id,
            )
            assert len(window_closed_events) >= 1
        finally:
            await conn.close()

    run_async(_test)
