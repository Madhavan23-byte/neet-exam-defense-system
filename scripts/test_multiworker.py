import asyncio
import time
import math
import httpx
import asyncpg

SERVER_URL = "http://127.0.0.1:8000"

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

async def get_exam_id():
    conn = await asyncpg.connect("postgresql://postgres:root@localhost:5432/bsea")
    exam_id = await conn.fetchval("SELECT id FROM exams WHERE status = 'RELEASED' LIMIT 1")
    await conn.close()
    return exam_id

async def run_multiworker_concurrency(concurrency: int, exam_id: str, offset: int = 0):
    print(f"\n==================================================")
    print(f"MULTI-WORKER TEST: {concurrency} CONCURRENT CANDIDATES (HTTP -> 2 WORKERS)")
    print(f"==================================================")

    # Use HTTP client against real running server on port 8000
    limits = httpx.Limits(max_keepalive_connections=100, max_connections=200)
    async with httpx.AsyncClient(base_url=SERVER_URL, limits=limits, timeout=60.0) as client:
        async def login_task(idx: int):
            reg_num = f"BSEA-TEST-{idx:06d}"
            payload = {
                "registration_number": reg_num,
                "password": "BSeaTest@2026",
                "exam_id": exam_id,
            }
            t0 = time.perf_counter()
            try:
                res = await client.post("/api/v1/candidate/auth/login", json=payload)
                t1 = time.perf_counter()
                return res.status_code, (t1 - t0) * 1000.0, None
            except Exception as e:
                t1 = time.perf_counter()
                return 599, (t1 - t0) * 1000.0, str(e)

        start_wall = time.perf_counter()
        tasks = [login_task(offset + i) for i in range(1, concurrency + 1)]
        raw_results = await asyncio.gather(*tasks)
        total_wall = time.perf_counter() - start_wall

    results = [r[0] for r in raw_results]
    latencies = sorted([r[1] for r in raw_results])

    count_200 = results.count(200)
    count_4xx = sum(1 for c in results if 400 <= c < 500)
    count_5xx = sum(1 for c in results if c >= 500)
    rps = concurrency / total_wall if total_wall > 0 else 0.0

    p50 = calc_percentile(latencies, 50)
    p95 = calc_percentile(latencies, 95)
    p99 = calc_percentile(latencies, 99)
    avg_lat = sum(latencies) / len(latencies) if latencies else 0.0
    max_lat = max(latencies) if latencies else 0.0

    print(f"Total Requests   : {concurrency}")
    print(f"200 OK           : {count_200}")
    print(f"4xx Client Error : {count_4xx}")
    print(f"5xx Server Error : {count_5xx}")
    print(f"Total Wall Time  : {total_wall:.3f}s")
    print(f"Throughput       : {rps:.2f} req/s")
    print(f"Latency P50      : {p50:.2f}ms")
    print(f"Latency P95      : {p95:.2f}ms")
    print(f"Latency P99      : {p99:.2f}ms")
    print(f"Latency Avg      : {avg_lat:.2f}ms")
    print(f"Latency Max      : {max_lat:.2f}ms")

    return {
        "concurrency": concurrency,
        "total": concurrency,
        "success": count_200,
        "4xx": count_4xx,
        "5xx": count_5xx,
        "wall_time": total_wall,
        "rps": rps,
        "avg": avg_lat,
        "p50": p50,
        "p95": p95,
        "p99": p99,
        "max": max_lat,
    }

async def test_process_local_rate_limiting(exam_id: str):
    print(f"\n==================================================")
    print("TESTING PROCESS-LOCAL RATE LIMITER (2 WORKERS)")
    print("==================================================")
    # The identity rate limit is 5/minute for a single candidate identity.
    # Send 12 rapid sequential or concurrent requests with the SAME candidate registration_number.
    target_candidate = "BSEA-2026-DEMO-001"
    payload = {
        "registration_number": target_candidate,
        "password": "WrongPassword123!", # We want to test rate limit triggers regardless of credential correctness
        "exam_id": exam_id,
    }

    status_codes = []
    async with httpx.AsyncClient(base_url=SERVER_URL, timeout=10.0) as client:
        # First check if candidate login with wrong password gives 401 or 429
        for i in range(12):
            res = await client.post("/api/v1/candidate/auth/login", json=payload)
            status_codes.append(res.status_code)
            # small sleep to allow round-robin between workers
            await asyncio.sleep(0.05)

    count_401 = status_codes.count(401)
    count_429 = status_codes.count(429)
    print(f"12 Requests with SAME candidate identity:")
    print(f"Status codes sequence: {status_codes}")
    print(f"  401 Unauthorized (attempt processed): {count_401}")
    print(f"  429 Rate-Limited (identity blocked)  : {count_429}")

    if count_401 > 5:
        print(">> FINDING: More than 5 requests were processed before blocking.")
        print("   This confirms MemoryStorage is process-local across the 2 Uvicorn workers,")
        print("   allowing each worker to maintain an independent in-memory rate-limit counter.")
    else:
        print(">> FINDING: All requests beyond 5 were rejected with 429.")

async def test_audit_event_consistency():
    print(f"\n==================================================")
    print("TESTING AUDIT TRAIL CONSISTENCY ACROSS 2 WORKERS")
    print("==================================================")
    # Wait 2 seconds for worker background queues to flush to PostgreSQL
    await asyncio.sleep(2.0)
    
    # Login as admin to verify audit chain
    async with httpx.AsyncClient(base_url=SERVER_URL, timeout=10.0) as client:
        login_res = await client.post("/api/v1/auth/login", json={"username": "admin", "password": "BSeaDemo@2026"})
        if login_res.status_code != 200:
            print(f"Admin login failed: {login_res.status_code}")
            return
        token = login_res.json()["access_token"]
        
        verify_res = await client.get("/api/v1/audit/verify", headers={"Authorization": f"Bearer {token}"})
        print(f"Audit verification endpoint response: {verify_res.status_code}")
        if verify_res.status_code == 200:
            data = verify_res.json()
            print(f"  Valid Hash Chain: {data.get('valid')}")
            print(f"  Entries Checked : {data.get('entries_checked')}")
            print(f"  Chain Head Hash : {data.get('chain_head')}")
        else:
            print(f"  Error: {verify_res.text}")

async def verify_post_test_db():
    conn = await asyncpg.connect("postgresql://postgres:root@localhost:5432/bsea")
    session_count = await conn.fetchval("SELECT count(*) FROM candidate_sessions")
    active_count = await conn.fetchval("SELECT count(*) FROM candidate_sessions WHERE status = 'ACTIVE'")
    
    dups = await conn.fetch("""
        SELECT candidate_id, exam_id, count(*) 
        FROM candidate_sessions 
        WHERE status = 'ACTIVE' 
        GROUP BY candidate_id, exam_id 
        HAVING count(*) > 1
    """)
    orphans = await conn.fetchval("""
        SELECT count(*) 
        FROM candidate_sessions s 
        LEFT JOIN candidates c ON s.candidate_id = c.id 
        WHERE c.id IS NULL
    """)
    
    # Check PostgreSQL connection count
    pg_conns = await conn.fetchval("SELECT count(*) FROM pg_stat_activity WHERE datname = 'bsea'")
    await conn.close()
    return session_count, active_count, len(dups), orphans, pg_conns

async def cleanup_test_sessions():
    conn = await asyncpg.connect("postgresql://postgres:root@localhost:5432/bsea")
    await conn.execute("DELETE FROM responses")
    await conn.execute("DELETE FROM candidate_sessions")
    remaining_sessions = await conn.fetchval("SELECT count(*) FROM candidate_sessions")
    await conn.close()
    print(f"\nCleanup: Removed test candidate_sessions. Remaining sessions = {remaining_sessions}")

async def main():
    await cleanup_test_sessions()

    exam_id = await get_exam_id()
    print(f"Targeting released exam: {exam_id}")

    # 1. Concurrency test at 10
    m10 = await run_multiworker_concurrency(10, exam_id, offset=1000)
    s, a, d, o, c = await verify_post_test_db()
    print(f"DB State after 10: Sessions={s}, Active={a}, Dups={d}, Orphans={o}, PG Conns={c}")

    # 2. Concurrency test at 50
    m50 = await run_multiworker_concurrency(50, exam_id, offset=1100)
    s, a, d, o, c = await verify_post_test_db()
    print(f"DB State after 50: Sessions={s}, Active={a}, Dups={d}, Orphans={o}, PG Conns={c}")

    # 3. Concurrency test at 100
    m100 = await run_multiworker_concurrency(100, exam_id, offset=1200)
    s, a, d, o, c = await verify_post_test_db()
    print(f"DB State after 100: Sessions={s}, Active={a}, Dups={d}, Orphans={o}, PG Conns={c}")

    # 4. Rate limiting test across workers
    await test_process_local_rate_limiting(exam_id)

    # 5. Audit queue test
    await test_audit_event_consistency()

    # 6. Final DB verification and cleanup
    s, a, d, o, c = await verify_post_test_db()
    print(f"\nFinal DB State: Total Sessions={s}, Active={a}, Duplicate Active={d}, Orphans={o}, PG Conns={c}")
    assert d == 0, f"PARTIAL UNIQUE CONSTRAINT VIOLATION: {d} duplicates!"

    await cleanup_test_sessions()

if __name__ == "__main__":
    asyncio.run(main())
