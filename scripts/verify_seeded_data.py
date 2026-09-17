import asyncio
import asyncpg

async def verify():
    conn = await asyncpg.connect("postgresql://postgres:root@localhost:5432/bsea")
    print("==================================================")
    print("B-SEA POSTGRESQL 16 SEEDED DATA VERIFICATION")
    print("==================================================")
    
    tables = [
        "organizations", "users", "candidates", "exams", "centres",
        "exam_blueprints", "exam_forms", "incidents", "questions",
        "release_approvals", "answer_keys", "candidate_sessions",
        "question_reviews", "responses", "results", "security_events", "audit_logs"
    ]
    
    print("\n1. Table Row Counts:")
    counts = {}
    for table in tables:
        count = await conn.fetchval(f"SELECT count(*) FROM {table}")
        counts[table] = count
        print(f"  - {table:<22}: {count:>6} rows")
        
    print("\n2. User Count by Role:")
    user_roles = await conn.fetch("SELECT role, count(*) FROM users GROUP BY role ORDER BY count(*) DESC, role")
    for r in user_roles:
        print(f"  - {r['role']:<20}: {r['count']:>6}")
        
    print("\n3. Candidate Verification:")
    cand_count = counts["candidates"]
    unique_reg = await conn.fetchval("SELECT count(DISTINCT registration_number) FROM candidates")
    print(f"  - Total candidates         : {cand_count}")
    print(f"  - Unique registration nums : {unique_reg}")
    print(f"  - Candidate user_id nulls  : {await conn.fetchval('SELECT count(*) FROM candidates WHERE user_id IS NULL')}")
    print(f"  - Candidate org_id nulls   : {await conn.fetchval('SELECT count(*) FROM candidates WHERE org_id IS NULL')}")
    
    # Check sample registration numbers
    sample_first = await conn.fetchval("SELECT registration_number FROM candidates ORDER BY registration_number ASC LIMIT 1")
    sample_last = await conn.fetchval("SELECT registration_number FROM candidates ORDER BY registration_number DESC LIMIT 1")
    print(f"  - Sample range             : {sample_first} ... {sample_last}")

    print("\n4. Active Sessions Check:")
    active_sessions = await conn.fetchval("SELECT count(*) FROM candidate_sessions WHERE status = 'ACTIVE'")
    total_sessions = counts["candidate_sessions"]
    print(f"  - Total sessions           : {total_sessions}")
    print(f"  - Active sessions          : {active_sessions}")

    print("\n5. Exam & Forms Verification:")
    exam = await conn.fetchrow("SELECT id, title, status, required_approvals FROM exams LIMIT 1")
    if exam:
        print(f"  - Exam Title               : {exam['title']}")
        print(f"  - Exam Status              : {exam['status']}")
        print(f"  - Required Approvals       : {exam['required_approvals']}")
    forms = await conn.fetch("SELECT form_label, status, json_array_length(question_ids) AS q_count FROM exam_forms ORDER BY form_label")
    print(f"  - Forms count              : {len(forms)}")
    for f in forms:
        print(f"    * Form {f['form_label']}: status={f['status']}, questions={f['q_count']}")

    print("\n6. Centres Verification:")
    centres = await conn.fetch("SELECT centre_code, name, status, device_count FROM centres")
    for c in centres:
        print(f"  - Centre {c['centre_code']}: {c['name']} (status={c['status']}, capacity={c['device_count']})")

    print("\n7. Foreign Key Integrity Check:")
    # Check candidates FK to users and orgs
    orphaned_cand_users = await conn.fetchval("SELECT count(*) FROM candidates c LEFT JOIN users u ON c.user_id = u.id WHERE u.id IS NULL")
    orphaned_cand_orgs = await conn.fetchval("SELECT count(*) FROM candidates c LEFT JOIN organizations o ON c.org_id = o.id WHERE o.id IS NULL")
    # Check questions FK to exams
    orphaned_questions = await conn.fetchval("SELECT count(*) FROM questions q LEFT JOIN exams e ON q.exam_id = e.id WHERE e.id IS NULL")
    # Check forms FK to exams
    orphaned_forms = await conn.fetchval("SELECT count(*) FROM exam_forms f LEFT JOIN exams e ON f.exam_id = e.id WHERE e.id IS NULL")
    print(f"  - Orphaned candidate users : {orphaned_cand_users}")
    print(f"  - Orphaned candidate orgs  : {orphaned_cand_orgs}")
    print(f"  - Orphaned questions       : {orphaned_questions}")
    print(f"  - Orphaned forms           : {orphaned_forms}")

    print("\n8. Database Disk Size:")
    db_size = await conn.fetchval("SELECT pg_size_pretty(pg_database_size('bsea'))")
    print(f"  - Total database size      : {db_size}")

    await conn.close()

if __name__ == '__main__':
    asyncio.run(verify())
