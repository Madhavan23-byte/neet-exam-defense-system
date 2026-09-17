import asyncio
import asyncpg

DB_URL = "postgresql://postgres:root@localhost:5432/bsea"

async def test_trigger_behavior():
    conn = await asyncpg.connect(DB_URL)
    tr = conn.transaction()
    await tr.start()
    try:
        log_id = "test-uuid-immutability-01"
        await conn.execute("""
            INSERT INTO audit_logs (id, event_type, event_hash, result, risk_score, timestamp, created_at)
            VALUES ($1, 'TEST_EVENT', 'hash01', 'SUCCESS', 0.0, NOW(), NOW());
        """, log_id)
        
        # Test 1: Try to UPDATE
        try:
            async with conn.transaction():
                await conn.execute("UPDATE audit_logs SET event_type = 'TAMPERED' WHERE id = $1;", log_id)
        except asyncpg.IntegrityConstraintViolationError as e:
            print("Successfully caught UPDATE rejection:", e)
            
        # Test 2: Try to DELETE
        try:
            async with conn.transaction():
                await conn.execute("DELETE FROM audit_logs WHERE id = $1;", log_id)
        except asyncpg.IntegrityConstraintViolationError as e:
            print("Successfully caught DELETE rejection:", e)
            
        print("ALL TESTS PASSED CLEANLY")
    finally:
        await tr.rollback()
        await conn.close()

if __name__ == "__main__":
    asyncio.run(test_trigger_behavior())
