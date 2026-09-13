"""
B-SEA Phase 3D Step 5A — Candidate Session Concurrency Race Regression Test

Verifies:
1. When concurrent candidate login attempts for the same candidate race against PostgreSQL,
   the partial unique constraint `uix_active_session_candidate_exam` authoritative check fires.
2. The application catches the specific IntegrityError, rolls back the transaction,
   and returns HTTP 409 Conflict (zero HTTP 500 errors).
3. Exactly ONE active session is created in PostgreSQL.
4. Zero duplicate active sessions exist.
"""
import concurrent.futures
import threading
import asyncio
import asyncpg
import pytest
from fastapi.testclient import TestClient
from app.main import app

BASE_URL = "/api/v1"
PG_DSN = "postgresql://postgres:root@localhost:5432/bsea"


def run_pg_query(fn):
    async def _runner():
        conn = await asyncpg.connect(PG_DSN)
        try:
            return await fn(conn)
        finally:
            await conn.close()
    return asyncio.run(_runner())


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def released_exam_id(client):
    """Retrieve the released exam ID."""
    async def _get(conn):
        return await conn.fetchval("SELECT id FROM exams WHERE status = 'RELEASED' LIMIT 1")
    exam_id = run_pg_query(_get)
    assert exam_id is not None, "No released exam found in PostgreSQL"
    return exam_id


def test_concurrent_candidate_login_race_returns_409(client, released_exam_id):
    """
    REGRESSION TEST FOR FINDING #3:
    Concurrent candidate login attempts for the same candidate race:
       Worker 1 -> INSERT ACTIVE session -> Success (200 OK)
       Worker 2 -> INSERT ACTIVE session -> UniqueViolationError on uix_active_session_candidate_exam
       API -> caught IntegrityError -> rollback -> HTTP 409 Conflict

    Invariants Verified:
       - Exactly one 200 OK response
       - Competing requests receive 409 Conflict
       - Zero 500 Internal Server Errors
       - Exactly one ACTIVE session exists in PostgreSQL
       - Zero duplicate ACTIVE sessions exist in PostgreSQL
    """
    candidate_reg = "BSEA-TEST-004950"
    
    # Pre-test cleanup: ensure candidate has 0 sessions
    async def _setup(conn):
        c_id = await conn.fetchval("SELECT id FROM candidates WHERE registration_number = $1", candidate_reg)
        assert c_id is not None, f"Candidate {candidate_reg} not found"
        await conn.execute("DELETE FROM candidate_sessions WHERE candidate_id = $1", c_id)
        return c_id

    candidate_id = run_pg_query(_setup)

    payload = {
        "registration_number": candidate_reg,
        "password": "BSeaTest@2026",
        "exam_id": released_exam_id,
    }

    CONCURRENCY = 8
    results = []
    response_bodies = []
    lock = threading.Lock()

    def attempt_login():
        r = client.post(f"{BASE_URL}/candidate/auth/login", json=payload)
        with lock:
            results.append(r.status_code)
            try:
                response_bodies.append(r.json())
            except Exception:
                response_bodies.append({"raw": r.text})

    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        futures = [executor.submit(attempt_login) for _ in range(CONCURRENCY)]
        concurrent.futures.wait(futures)

    success_200 = results.count(200)
    conflict_409 = results.count(409)
    error_500 = results.count(500)
    rate_limited_429 = results.count(429)

    print(f"\nConcurrent Race Status Codes: {results}")
    print(f"  200 OK: {success_200}, 409 Conflict: {conflict_409}, 429 RateLimit: {rate_limited_429}, 500 Error: {error_500}")

    # 1. Zero 500 errors — unhandled IntegrityError must NOT escape as 500
    assert error_500 == 0, (
        f"DEFECT REGRESSION: {error_500} unhandled HTTP 500 errors occurred! "
        f"Unique constraint violations must be converted to 409 Conflict."
    )

    # 2. Exactly one login succeeded
    assert success_200 == 1, (
        f"Expected exactly 1 successful login, got {success_200}"
    )

    # 3. Competing requests received 409 Conflict
    assert conflict_409 >= 1, (
        f"Expected competing requests to receive 409 Conflict, got {conflict_409}"
    )

    # 4. Verify 409 response structure
    conflict_bodies = [b for b in response_bodies if b.get("detail") == "An active session already exists for this candidate."]
    assert len(conflict_bodies) == conflict_409, "409 responses must contain expected detail message"

    # 5. Authoritative PostgreSQL Verification
    async def _verify_and_cleanup(conn):
        active_cnt = await conn.fetchval(
            "SELECT count(*) FROM candidate_sessions WHERE candidate_id = $1 AND status = 'ACTIVE'",
            candidate_id
        )
        dups = await conn.fetch("""
            SELECT candidate_id, exam_id, count(*)
            FROM candidate_sessions
            WHERE status = 'ACTIVE'
            GROUP BY candidate_id, exam_id
            HAVING count(*) > 1
        """)
        # Cleanup
        await conn.execute("DELETE FROM candidate_sessions WHERE candidate_id = $1", candidate_id)
        return active_cnt, dups

    active_count, duplicates = run_pg_query(_verify_and_cleanup)
    assert active_count == 1, f"Expected exactly 1 ACTIVE session in PostgreSQL, found {active_count}"
    assert len(duplicates) == 0, f"PARTIAL UNIQUE INDEX VIOLATION: {duplicates}"
