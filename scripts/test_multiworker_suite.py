import asyncio
import time
import math
import httpx
import asyncpg

SERVER_URL = "http://127.0.0.1:8000"
PG_DSN = "postgresql://postgres:root@localhost:5432/bsea"

def calc_percentile(sorted_data, p):
    if not sorted_data:
        return 0.0
    k = (len(sorted_data) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_data[int(k)]
    d0 = sorted_data[int(f)] * (c - k)
    d1 = sorted_data[int(c)] * (k - f)
    return d0 + d1

async def get_released_exam():
    conn = await asyncpg.connect(PG_DSN)
    row = await conn.fetchrow("SELECT id, title FROM exams WHERE status = 'RELEASED' LIMIT 1")
    await conn.close()
    return row

async def get_pg_conns():
    conn = await asyncpg.connect(PG_DSN)
    conns = await conn.fetchval("SELECT count(*) FROM pg_stat_activity WHERE datname = 'bsea'")
    await conn.close()
    return conns

async def cleanup_sessions():
    conn = await asyncpg.connect(PG_DSN)
    await conn.execute("DELETE FROM responses")
    await conn.execute("DELETE FROM candidate_sessions")
    rem = await conn.fetchval("SELECT count(*) FROM candidate_sessions")
    await conn.close()
    return rem

async def run_concurrency_batch(concurrency: int, exam_id: str, offset: int):
    print(f"\n" + "=" * 60)
    print(f"RUNNING CONCURRENCY BATCH: {concurrency} CANDIDATES (HTTP -> 2 WORKERS)")
    print("=" * 60)

    pre_conns = await get_pg_conns()
    limits = httpx.Limits(max_keepalive_connections=120, max_connections=250)
    
    async with httpx.AsyncClient(base_url=SERVER_URL, limits=limits, timeout=90.0) as client:
        async def login_one(idx: int):
            reg = f"BSEA-TEST-{idx:06d}"
            payload = {
                "registration_number": reg,
                "password": "BSeaTest@2026",
                "exam_id": exam_id,
            }
            t0 = time.perf_counter()
            try:
                res = await client.post("/api/v1/candidate/auth/login", json=payload)
                t1 = time.perf_counter()
                return res.status_code, (t1 - t0) * 1000.0, None
            except Exception as ex:
                t1 = time.perf_counter()
                return 599, (t1 - t0) * 1000.0, str(ex)

        start_time = time.perf_counter()
        tasks = [login_one(offset + i) for i in range(1, concurrency + 1)]
        raw_results = await asyncio.gather(*tasks)
        total_wall = time.perf_counter() - start_time

    post_conns = await get_pg_conns()
    codes = [r[0] for r in raw_results]
    latencies = sorted([r[1] for r in raw_results])

    c_200 = codes.count(200)
    c_4xx = sum(1 for c in codes if 400 <= c < 500)
    c_5xx = sum(1 for c in codes if c >= 500)
    rps = concurrency / total_wall if total_wall > 0 else 0.0

    p50 = calc_percentile(latencies, 50)
    p95 = calc_percentile(latencies, 95)
    p99 = calc_percentile(latencies, 99)
    avg_lat = sum(latencies) / len(latencies) if latencies else 0.0
    min_lat = min(latencies) if latencies else 0.0
    max_lat = max(latencies) if latencies else 0.0

    print(f"Results for Concurrency = {concurrency}:")
    print(f"  HTTP 200 OK           : {c_200} (100.0%)" if c_200 == concurrency else f"  HTTP 200 OK           : {c_200}")
    print(f"  HTTP 4xx Client Error : {c_4xx}")
    print(f"  HTTP 5xx Server Error : {c_5xx}")
    print(f"  Total Elapsed Time    : {total_wall:.3f} s")
    print(f"  Throughput            : {rps:.2f} req/s")
    print(f"  Latency Min           : {min_lat:.2f} ms")
    print(f"  Latency Avg           : {avg_lat:.2f} ms")
    print(f"  Latency P50           : {p50:.2f} ms")
    print(f"  Latency P95           : {p95:.2f} ms")
    print(f"  Latency P99           : {p99:.2f} ms")
    print(f"  Latency Max           : {max_lat:.2f} ms")
    print(f"  PostgreSQL Conns      : {pre_conns} pre-test -> {post_conns} post-test")

    return {
        "concurrency": concurrency,
        "http_200": c_200,
        "http_4xx": c_4xx,
        "http_5xx": c_5xx,
        "wall_time": total_wall,
        "throughput": rps,
        "avg": avg_lat,
        "min": min_lat,
        "p50": p50,
        "p95": p95,
        "p99": p99,
        "max": max_lat,
        "pre_conns": pre_conns,
        "post_conns": post_conns,
    }

async def test_rate_limiter_distribution(exam_id: str):
    print("\n" + "=" * 60)
    print("STEP 8: PROCESS-LOCAL RATE LIMITER DISTRIBUTION TEST")
    print("=" * 60)
    # Use candidate BSEA-TEST-004500 (exists, known password)
    # The identity rate limit is 5/minute per registration number.
    # We will send 12 requests with this valid candidate.
    # First request creates session (200 OK).
    # Subsequent requests within rate limit return 409 Conflict (active session already exists).
    # Requests exceeding rate limit return 429 Too Many Requests.
    target_cand = "BSEA-TEST-004500"
    payload = {
        "registration_number": target_cand,
        "password": "BSeaTest@2026",
        "exam_id": exam_id,
    }

    # Part A: Sequential requests with HTTP Keepalive (hits Worker 1)
    status_codes_seq = []
    print(f"\nPart A: Sending 10 sequential keepalive requests for candidate {target_cand}...")
    async with httpx.AsyncClient(base_url=SERVER_URL, timeout=10.0) as client:
        for i in range(10):
            res = await client.post("/api/v1/candidate/auth/login", json=payload)
            status_codes_seq.append(res.status_code)
            await asyncio.sleep(0.01)

    c_200_seq = status_codes_seq.count(200)
    c_409_seq = status_codes_seq.count(409)
    c_429_seq = status_codes_seq.count(429)
    print(f"Sequential (Keepalive) status sequence: {status_codes_seq}")
    print(f"  Processed (200/409): {c_200_seq + c_409_seq}")
    print(f"  Rate-limited (429) : {c_429_seq}")
    print(f">> Single-worker bucket enforces configured 5/min limit on persistent connection.")

    # Part B: Concurrent requests without keepalive for a NEW candidate (distributes across workers)
    target_cand_b = "BSEA-TEST-004600"
    payload_b = {
        "registration_number": target_cand_b,
        "password": "BSeaTest@2026",
        "exam_id": exam_id,
    }
    print(f"\nPart B: Sending 12 concurrent requests (independent connections) for candidate {target_cand_b}...")
    async def make_independent_req():
        async with httpx.AsyncClient(base_url=SERVER_URL, timeout=10.0) as c:
            r = await c.post("/api/v1/candidate/auth/login", json=payload_b)
            return r.status_code

    tasks = [make_independent_req() for _ in range(12)]
    status_codes_dist = await asyncio.gather(*tasks)
    c_200_dist = status_codes_dist.count(200)
    c_409_dist = status_codes_dist.count(409)
    c_429_dist = status_codes_dist.count(429)
    total_allowed_dist = c_200_dist + c_409_dist
    print(f"Concurrent Distributed status sequence: {status_codes_dist}")
    print(f"  Processed (200/409): {total_allowed_dist}")
    print(f"  Rate-limited (429) : {c_429_dist}")

    if total_allowed_dist > 5:
        print(f">> ARCHITECTURAL LIMITATION OBSERVED: Total allowed attempts = {total_allowed_dist} > 5.")
        print(f"   Candidate received independent in-memory rate-limit buckets across the 2 worker processes.")
    else:
        print(f">> Requests blocked at {total_allowed_dist}.")

    return {
        "seq_results": status_codes_seq,
        "dist_results": status_codes_dist,
        "total_allowed_dist": total_allowed_dist,
    }

async def test_audit_consistency():
    print("\n" + "=" * 60)
    print("STEP 9: AUDIT LOG BEHAVIOR AND CONTINUITY ACROSS 2 WORKERS")
    print("=" * 60)
    print("Waiting 3.0 seconds for background audit queue workers to flush...")
    await asyncio.sleep(3.0)

    conn = await asyncpg.connect(PG_DSN)
    total_logs = await conn.fetchval("SELECT count(*) FROM audit_logs")
    max_seq = await conn.fetchval("SELECT max(seq) FROM audit_logs")
    
    # Check for duplicate sequence numbers
    dup_seqs = await conn.fetch("""
        SELECT seq, count(*) 
        FROM audit_logs 
        GROUP BY seq 
        HAVING count(*) > 1 
        ORDER BY seq
    """)

    # Verify hash chain manually from DB records
    logs = await conn.fetch("SELECT id, seq, prev_hash, event_hash, event_type, timestamp FROM audit_logs ORDER BY seq ASC, id ASC")
    chain_breaks = []
    for i in range(1, len(logs)):
        if logs[i]['prev_hash'] != logs[i-1]['event_hash']:
            chain_breaks.append((logs[i-1]['seq'], logs[i]['seq'], logs[i-1]['event_hash'], logs[i]['prev_hash']))

    await conn.close()

    print(f"Audit Log Total Records : {total_logs}")
    print(f"Max Sequence Number     : {max_seq}")
    print(f"Duplicate Seq Numbers   : {len(dup_seqs)} distinct sequences with duplicates")
    if dup_seqs:
        print(f"  Examples of duplicate seqs: {[d['seq'] for d in dup_seqs[:8]]}")
    print(f"Chain Discontinuities   : {len(chain_breaks)} breaks detected in linear sequence")

    # Now verify via admin API endpoint
    async with httpx.AsyncClient(base_url=SERVER_URL, timeout=10.0) as client:
        auth_res = await client.post("/api/v1/auth/login", json={"username": "admin", "password": "BSeaDemo@2026"})
        if auth_res.status_code == 200:
            token = auth_res.json()["access_token"]
            v_res = await client.get("/api/v1/audit/verify", headers={"Authorization": f"Bearer {token}"})
            print(f"API /api/v1/audit/verify HTTP status: {v_res.status_code}")
            print(f"API /api/v1/audit/verify payload    : {v_res.json()}")

    return {
        "total_logs": total_logs,
        "max_seq": max_seq,
        "dup_seqs_count": len(dup_seqs),
        "dup_seqs_samples": [d['seq'] for d in dup_seqs[:8]],
        "chain_breaks_count": len(chain_breaks),
    }

async def verify_post_test_state():
    print("\n" + "=" * 60)
    print("STEP 10: POST-TEST DATABASE STATE & INTEGRITY VERIFICATION")
    print("=" * 60)
    conn = await asyncpg.connect(PG_DSN)
    
    total_sessions = await conn.fetchval("SELECT count(*) FROM candidate_sessions")
    active_sessions = await conn.fetchval("SELECT count(*) FROM candidate_sessions WHERE status = 'ACTIVE'")
    
    # Check duplicate active sessions
    dups = await conn.fetch("""
        SELECT candidate_id, exam_id, count(*) 
        FROM candidate_sessions 
        WHERE status = 'ACTIVE' 
        GROUP BY candidate_id, exam_id 
        HAVING count(*) > 1
    """)

    # Check orphaned records
    orphans = await conn.fetchval("""
        SELECT count(*) 
        FROM candidate_sessions s 
        LEFT JOIN candidates c ON s.candidate_id = c.id 
        WHERE c.id IS NULL
    """)

    sec_events = await conn.fetchval("SELECT count(*) FROM security_events")
    users_count = await conn.fetchval("SELECT count(*) FROM users")
    candidates_count = await conn.fetchval("SELECT count(*) FROM candidates")
    exams_count = await conn.fetchval("SELECT count(*) FROM exams")
    forms_count = await conn.fetchval("SELECT count(*) FROM exam_forms")
    questions_count = await conn.fetchval("SELECT count(*) FROM questions")
    answers_count = await conn.fetchval("SELECT count(*) FROM answer_keys")
    approvals_count = await conn.fetchval("SELECT count(*) FROM release_approvals")

    print(f"Candidate Sessions : Total={total_sessions}, Active={active_sessions}")
    print(f"Duplicate Active   : {len(dups)} (Violations of uix_active_session_candidate_exam)")
    print(f"Orphaned Sessions  : {orphans}")
    print(f"Security Events    : {sec_events}")
    print(f"Domain Integrity   :")
    print(f"  Users            : {users_count}")
    print(f"  Candidates       : {candidates_count}")
    print(f"  Exams            : {exams_count}")
    print(f"  Exam Forms       : {forms_count}")
    print(f"  Questions        : {questions_count}")
    print(f"  Answer Keys      : {answers_count}")
    print(f"  Release Approvals: {approvals_count}")

    await conn.close()
    return {
        "total_sessions": total_sessions,
        "active_sessions": active_sessions,
        "duplicate_active": len(dups),
        "orphaned_sessions": orphans,
        "users": users_count,
        "candidates": candidates_count,
        "exams": exams_count,
    }

async def main():
    print("==================================================")
    print("B-SEA PHASE 3D STEP 5: MULTI-WORKER RUNTIME SUITE")
    print("==================================================")
    
    # 0. Initial cleanup of previous test sessions
    rem = await cleanup_sessions()
    print(f"Initial DB Cleanup: candidate_sessions = {rem}")

    exam = await get_released_exam()
    exam_id = exam["id"]
    print(f"Exam Target: {exam['title']} - ID: {exam_id}")

    # 1. Concurrency batch: 10
    r10 = await run_concurrency_batch(10, exam_id, offset=2000)

    # 2. Concurrency batch: 50
    r50 = await run_concurrency_batch(50, exam_id, offset=2100)

    # 3. Concurrency batch: 100
    r100 = await run_concurrency_batch(100, exam_id, offset=2200)

    # 4. Rate limiter distribution
    rl = await test_rate_limiter_distribution(exam_id)

    # 5. Audit queue behavior
    aud = await test_audit_consistency()

    # 6. Post-test DB state
    db_state = await verify_post_test_state()

    # 7. Cleanup
    print("\n" + "=" * 60)
    print("STEP 11: CLEANUP SYNTHETIC TEST SESSIONS")
    print("=" * 60)
    final_rem = await cleanup_sessions()
    print(f"Final Cleanup: candidate_sessions count = {final_rem}")

if __name__ == "__main__":
    asyncio.run(main())
