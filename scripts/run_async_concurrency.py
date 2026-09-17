import asyncio
import time
import math
import httpx
import asyncpg

from app.main import app

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

async def run_async_concurrency_level(concurrency: int, exam_id: str, offset: int = 0):
    print(f"\n==================================================")
    print(f"TESTING CONCURRENCY LEVEL: {concurrency} CONCURRENT CANDIDATES (ASYNC)")
    print(f"==================================================")

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver", timeout=60.0) as client:
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

async def get_exam_id():
    conn = await asyncpg.connect("postgresql://postgres:root@localhost:5432/bsea")
    exam_id = await conn.fetchval("SELECT id FROM exams WHERE status = 'RELEASED' LIMIT 1")
    await conn.close()
    return exam_id

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
    await conn.close()
    return session_count, active_count, len(dups), orphans

async def cleanup_test_sessions():
    conn = await asyncpg.connect("postgresql://postgres:root@localhost:5432/bsea")
    await conn.execute("DELETE FROM responses")
    await conn.execute("DELETE FROM candidate_sessions")
    remaining_sessions = await conn.fetchval("SELECT count(*) FROM candidate_sessions")
    await conn.close()
    print(f"\nCleanup: Removed test candidate_sessions. Remaining sessions = {remaining_sessions}")

async def main():
    # First clean up any leftover sessions
    await cleanup_test_sessions()

    exam_id = await get_exam_id()
    print(f"Targeting released exam: {exam_id}")

    m10 = await run_async_concurrency_level(10, exam_id, offset=0)
    s_cnt, a_cnt, d_cnt, o_cnt = await verify_post_test_db()
    print(f"DB State after 10: Total Sessions={s_cnt}, Active={a_cnt}, Duplicates={d_cnt}, Orphans={o_cnt}")

    m50 = await run_async_concurrency_level(50, exam_id, offset=100)
    s_cnt, a_cnt, d_cnt, o_cnt = await verify_post_test_db()
    print(f"DB State after 50: Total Sessions={s_cnt}, Active={a_cnt}, Duplicates={d_cnt}, Orphans={o_cnt}")

    m100 = await run_async_concurrency_level(100, exam_id, offset=500)
    s_cnt, a_cnt, d_cnt, o_cnt = await verify_post_test_db()
    print(f"DB State after 100: Total Sessions={s_cnt}, Active={a_cnt}, Duplicates={d_cnt}, Orphans={o_cnt}")

    print(f"\nFinal DB State: Total Sessions={s_cnt}, Active={a_cnt}, Duplicate Active Per Cand={d_cnt}, Orphans={o_cnt}")
    assert d_cnt == 0, f"PARTIAL UNIQUE CONSTRAINT VIOLATION: {d_cnt} duplicate active sessions!"

    # Clean up test sessions after verification per Step 4E
    await cleanup_test_sessions()

if __name__ == "__main__":
    asyncio.run(main())
