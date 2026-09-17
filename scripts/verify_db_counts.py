import asyncio
import os
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text

os.environ['DATABASE_URL'] = 'postgresql+asyncpg://postgres:root@localhost:5432/bsea'

async def verify_db():
    engine = create_async_engine(os.environ['DATABASE_URL'])
    tables = [
        'users', 'candidates', 'exams', 'exam_blueprints', 'exam_forms',
        'questions', 'answer_keys', 'release_approvals', 'candidate_sessions',
        'responses', 'results', 'incidents', 'security_events', 'audit_logs'
    ]
    print('--- DATABASE TABLE COUNTS ---')
    async with engine.connect() as conn:
        for t in tables:
            try:
                res = await conn.execute(text(f'SELECT count(*) FROM {t}'))
                count = res.scalar()
                print(f'{t}: {count}')
            except Exception as e:
                print(f'{t}: ERROR ({e})')
                
        # Check active candidate sessions
        res = await conn.execute(text("SELECT count(*) FROM candidate_sessions WHERE status = 'ACTIVE'"))
        active_count = res.scalar()
        print(f'Active candidate sessions: {active_count}')
        
        # Check duplicate active sessions (should be 0)
        res = await conn.execute(text("SELECT candidate_id, exam_id, count(*) FROM candidate_sessions WHERE status = 'ACTIVE' GROUP BY candidate_id, exam_id HAVING count(*) > 1"))
        dupes = res.fetchall()
        print(f'Duplicate active sessions: {len(dupes)}')
        
        # Check orphan candidate_sessions
        res = await conn.execute(text("SELECT count(*) FROM candidate_sessions cs LEFT JOIN candidates c ON cs.candidate_id = c.id WHERE c.id IS NULL"))
        orphan_candidates = res.scalar()
        print(f'Orphan candidate_sessions (no candidate): {orphan_candidates}')
        
        res = await conn.execute(text("SELECT count(*) FROM candidate_sessions cs LEFT JOIN exams e ON cs.exam_id = e.id WHERE e.id IS NULL"))
        orphan_exams = res.scalar()
        print(f'Orphan candidate_sessions (no exam): {orphan_exams}')
        
        # Check orphan responses
        res = await conn.execute(text("SELECT count(*) FROM responses r LEFT JOIN candidate_sessions cs ON r.session_id = cs.id WHERE cs.id IS NULL"))
        orphan_responses = res.scalar()
        print(f'Orphan responses (no session): {orphan_responses}')
        
        # Check orphan results
        res = await conn.execute(text("SELECT count(*) FROM results r LEFT JOIN candidate_sessions cs ON r.session_id = cs.id WHERE cs.id IS NULL"))
        orphan_results = res.scalar()
        print(f'Orphan results (no session): {orphan_results}')

    await engine.dispose()

if __name__ == '__main__':
    asyncio.run(verify_db())
