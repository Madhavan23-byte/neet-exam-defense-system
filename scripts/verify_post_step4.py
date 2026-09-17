import asyncio
import asyncpg

async def verify():
    conn = await asyncpg.connect("postgresql://postgres:root@localhost:5432/bsea")
    print("==================================================")
    print("PHASE 3D STEP 4E: POST-TEST DATABASE VERIFICATION")
    print("==================================================")

    # 1. Candidate sessions count
    sess_count = await conn.fetchval("SELECT count(*) FROM candidate_sessions")
    active_sess = await conn.fetchval("SELECT count(*) FROM candidate_sessions WHERE status = 'ACTIVE'")
    print(f"1. Candidate Sessions:")
    print(f"   - Total candidate_sessions : {sess_count}")
    print(f"   - Active candidate_sessions: {active_sess}")

    # 2. Duplicate active sessions check
    dups = await conn.fetch("""
        SELECT candidate_id, exam_id, count(*) 
        FROM candidate_sessions 
        WHERE status = 'ACTIVE' 
        GROUP BY candidate_id, exam_id 
        HAVING count(*) > 1
    """)
    print(f"2. Duplicate Active Sessions: {len(dups)}")

    # 3. Orphaned sessions check
    orphans = await conn.fetchval("""
        SELECT count(*) 
        FROM candidate_sessions s 
        LEFT JOIN candidates c ON s.candidate_id = c.id 
        WHERE c.id IS NULL
    """)
    print(f"3. Orphaned Sessions: {orphans}")

    # 4. Threshold approval records consistency
    approvals = await conn.fetch("""
        SELECT exam_id, count(*) as count, bool_and(is_valid) as all_valid
        FROM release_approvals
        GROUP BY exam_id
    """)
    print(f"4. Threshold Approval Records:")
    for a in approvals:
        print(f"   - Exam {a['exam_id'][:8]}...: {a['count']} approvals, all_valid={a['all_valid']}")

    # 5. Security & Audit events
    sec_events = await conn.fetchval("SELECT count(*) FROM security_events")
    audit_events = await conn.fetchval("SELECT count(*) FROM audit_logs")
    print(f"5. Security & Audit Event Logs:")
    print(f"   - Security Events : {sec_events}")
    print(f"   - Audit Log Events: {audit_events}")

    # Verify audit hash chain if audit_logs has entries
    if audit_events > 1:
        logs = await conn.fetch("SELECT id, seq, prev_hash, event_hash FROM audit_logs ORDER BY seq ASC")
        chain_broken = False
        for i in range(1, len(logs)):
            if logs[i]['prev_hash'] != logs[i-1]['event_hash']:
                chain_broken = True
                print(f"   ! Audit chain break detected between seq {logs[i-1]['seq']} and {logs[i]['seq']}")
        if not chain_broken:
            print("   - Audit Hash Chain: 100% VALID and intact.")

    # 6. Overall database integrity
    cand_count = await conn.fetchval("SELECT count(*) FROM candidates")
    user_count = await conn.fetchval("SELECT count(*) FROM users")
    exam_count = await conn.fetchval("SELECT count(*) FROM exams")
    print(f"6. Domain Integrity:")
    print(f"   - Users      : {user_count}")
    print(f"   - Candidates : {cand_count}")
    print(f"   - Exams      : {exam_count}")

    await conn.close()

if __name__ == '__main__':
    asyncio.run(verify())
