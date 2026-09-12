"""
B-SEA Phase 3C — Concurrency Correctness Tests

These tests verify both:
  A. PERFORMANCE/AVAILABILITY — no 500 errors, no database locked errors
  B. SECURITY/CORRECTNESS — threshold cannot be bypassed, no duplicate sessions

Concurrency is simulated via Python threading against the synchronous
TestClient (which runs the async app in a blocking portal).

TEST COVERAGE:
  1. Threshold approval — concurrent duplicate approval attempts cannot bypass threshold
  2. Candidate session — concurrent session creation enforces one-active-session invariant
  3. Audit chain — concurrent events preserve hash-chain integrity

ENVIRONMENT NOTE:
  Tests run against SQLite (PostgreSQL unavailable — Docker not installed on this host).
  SQLite partial unique index on active sessions + UniqueConstraint on ReleaseApproval
  enforce correctness at the DB level for single-process concurrency.
  See docs/BSEA_PHASE3C_POSTGRESQL_VALIDATION.md for full PostgreSQL runtime status.
"""
import concurrent.futures
import threading
import time
import pytest
from fastapi.testclient import TestClient

from app.main import app

BASE_URL = "/api/v1"
ADMIN_CREDS = {"username": "admin", "password": "BSeaDemo@2026"}


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def admin_token(client):
    res = client.post(f"{BASE_URL}/auth/login", json=ADMIN_CREDS)
    data = res.json()
    assert res.status_code == 200, f"Admin login failed: {data}"
    return data["access_token"]


@pytest.fixture(scope="module")
def fresh_exam_id(client, admin_token):
    """Create a fresh exam with required_approvals=3 to use in concurrency tests."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    res = client.post(f"{BASE_URL}/exams/", headers=headers, json={
        "title": "Concurrency Test Exam",
        "exam_type": "CBT",
        "security_mode": "HIGH",
        "required_approvals": 3,
        "duration_minutes": 180,
    })
    assert res.status_code == 200, f"Could not create test exam: {res.text}"
    return res.json()["id"]


@pytest.fixture(scope="module")
def existing_exam_id(client, admin_token):
    """Use the first available exam for read-only / audit tests."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    res = client.get(f"{BASE_URL}/exams/", headers=headers)
    assert res.status_code == 200
    exams = res.json()
    assert len(exams) > 0, "No exams available for testing"
    return exams[-1]["id"]


# ── Test 1: Concurrent Duplicate Approvals — No Bypass ───────────────────────

def test_concurrent_duplicate_approvals_no_bypass(client, admin_token, fresh_exam_id):
    """
    SECURITY + CORRECTNESS TEST:
    The same admin submits N concurrent approval requests.

    Invariants:
      - Only ONE approval must be accepted (duplicate blocked by DB UniqueConstraint).
      - The exam must NOT reach THRESHOLD_APPROVED from a single admin's duplicates.
      - No 500 errors — IntegrityError from DB must return 400 or 409.

    REAL: Tests application lock (with_for_update on Exam row) + DB UniqueConstraint.
    PARTIAL on SQLite: with_for_update() is a no-op; UniqueConstraint enforces.
    FULLY ENFORCED on PostgreSQL: row-level lock prevents concurrent race.
    """
    headers = {"Authorization": f"Bearer {admin_token}"}
    exam_id = fresh_exam_id
    CONCURRENCY = 10
    results = []
    lock = threading.Lock()

    def submit():
        r = client.post(f"{BASE_URL}/release/{exam_id}/approve", headers=headers)
        with lock:
            results.append(r.status_code)

    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        futures = [executor.submit(submit) for _ in range(CONCURRENCY)]
        concurrent.futures.wait(futures)

    successes = results.count(200)
    errors_500 = results.count(500)
    conflicts = sum(1 for c in results if c in (400, 409, 403))

    print(f"\nConcurrent approval results (exam={exam_id[:8]}): {results}")
    print(f"  Successes: {successes}, Conflicts: {conflicts}, 500s: {errors_500}")

    # CORRECTNESS: at most 1 success — same admin cannot approve twice
    assert successes <= 1, (
        f"DUPLICATE APPROVAL BYPASS: {successes} approvals accepted from same admin. "
        "The DB UniqueConstraint or application lock failed."
    )
    # AVAILABILITY: DB constraint violations must not propagate as 500
    assert errors_500 == 0, (
        f"{errors_500} unhandled 500 errors from duplicate approval. "
        "IntegrityError must be caught and returned as 400/409."
    )


def test_threshold_not_bypassed_by_single_admin(client, admin_token, fresh_exam_id):
    """
    SECURITY TEST: Verify that the exam with required_approvals=3 was NOT
    promoted to THRESHOLD_APPROVED by a single admin's concurrent submissions.
    """
    headers = {"Authorization": f"Bearer {admin_token}"}
    res = client.get(f"{BASE_URL}/release/{fresh_exam_id}/status", headers=headers)
    assert res.status_code == 200
    data = res.json()

    required = data.get("required_approvals", 3)
    received = data.get("received_approvals", 0)
    exam_status = data.get("exam_status")

    print(f"\nThreshold state after concurrent test: {received}/{required}, status={exam_status}")

    # SECURITY INVARIANT: One admin cannot satisfy threshold > 1
    assert received <= 1, (
        f"THRESHOLD BYPASS: {received} approvals recorded for threshold={required}. "
        "A single admin cannot submit multiple valid approvals."
    )
    assert exam_status != "THRESHOLD_APPROVED", (
        f"THRESHOLD_APPROVED reached with only {received}/{required} from a single admin."
    )


# ── Test 2: Concurrent Session Creation ───────────────────────────────────────

def test_concurrent_session_creation_one_active_session(client, existing_exam_id):
    """
    CORRECTNESS + SECURITY TEST:
    Many concurrent login attempts for the SAME candidate on the SAME exam.

    Invariants:
      - At most ONE ACTIVE session created per candidate per exam (enforced by
        the partial unique index uix_active_session_candidate_exam at DB level).
      - All other concurrent attempts return 409 Conflict.
      - No 500 errors from unhandled IntegrityError on the unique index.

    REAL: Tests uix_active_session_candidate_exam (partial unique index) + app check.
    FULL ENFORCEMENT on PostgreSQL: DB-level constraint fires at INSERT time.
    """
    CANDIDATE_CREDS = {
        "registration_number": "BSEA-2026-DEMO-001",
        "password": "BSeaDemo@2026",
        "exam_id": existing_exam_id,
    }
    CONCURRENCY = 15
    results = []
    lock = threading.Lock()

    def attempt_login():
        r = client.post(f"{BASE_URL}/candidate/auth/login", json=CANDIDATE_CREDS)
        with lock:
            results.append(r.status_code)

    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        futures = [executor.submit(attempt_login) for _ in range(CONCURRENCY)]
        concurrent.futures.wait(futures)

    successes_200 = results.count(200)
    conflicts_409 = results.count(409)
    rate_limited = results.count(429)
    errors_500 = results.count(500)

    print(f"\nConcurrent session creation results: {results}")
    print(
        f"  200 OK: {successes_200}, 409 Conflict: {conflicts_409}, "
        f"429 Rate-Limited: {rate_limited}, 500 Error: {errors_500}"
    )

    # AVAILABILITY: No unhandled integrity errors
    assert errors_500 == 0, (
        f"{errors_500} unhandled 500 errors during concurrent session creation. "
        "Unique index violations must return 409, not 500."
    )
    # CORRECTNESS: At most one new session created
    # Could be 0 if candidate already has ACTIVE session from a prior run
    assert successes_200 <= 1, (
        f"DUPLICATE SESSION: {successes_200} concurrent logins succeeded for the same candidate."
    )


# ── Test 3: Audit Chain Integrity Under Concurrent Load ───────────────────────

def test_concurrent_audit_events_chain_integrity(client, admin_token, existing_exam_id):
    """
    CORRECTNESS TEST: Concurrent audit event generation preserves hash-chain integrity.

    Generates CONCURRENCY concurrent reads (each triggers audit logging) then
    verifies the chain is still valid using /api/v1/audit/verify.

    NOTE (Prototype Limitation):
      The audit worker uses an in-memory asyncio.Queue. Events may be reordered
      relative to their submission time, but the chain hash sequence must remain
      contiguous. Events lost on crash (ungraceful shutdown) are a known limitation.
    """
    headers = {"Authorization": f"Bearer {admin_token}"}
    CONCURRENCY = 20

    def trigger_event():
        r = client.get(f"{BASE_URL}/exams/{existing_exam_id}", headers=headers)
        return r.status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        futures = [executor.submit(trigger_event) for _ in range(CONCURRENCY)]
        event_results = [f.result() for f in concurrent.futures.as_completed(futures)]

    server_errors = sum(1 for r in event_results if r >= 500)
    assert server_errors == 0, f"{server_errors} server errors during concurrent event generation"

    # Wait for the background audit worker to drain
    time.sleep(2)

    # Verify hash chain
    res = client.get(f"{BASE_URL}/audit/verify", headers=headers)
    assert res.status_code == 200, f"Audit chain verify endpoint failed: {res.status_code} — {res.text}"
    data = res.json()
    assert data.get("valid") is True, (
        f"AUDIT CHAIN INTEGRITY VIOLATION after concurrent writes: {data}"
    )
    entries = data.get("entries_checked", data.get("total_entries", "?"))
    print(f"\nAudit chain verified: {entries} entries checked, chain={data.get('chain_head', '')[:16]}...")
