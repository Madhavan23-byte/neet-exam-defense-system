import asyncio
import asyncpg

async def check():
    conn = await asyncpg.connect("postgresql://postgres:root@localhost:5432/bsea")
    cols = await conn.fetch("""
        SELECT column_name, data_type, is_nullable, column_default
        FROM information_schema.columns
        WHERE table_name = 'audit_logs'
        ORDER BY ordinal_position;
    """)
    print("Columns of audit_logs:")
    for c in cols:
        print(f"  {c['column_name']}: {c['data_type']}, nullable={c['is_nullable']}, default={c['column_default']}")
        
    count = await conn.fetchval("SELECT count(*) FROM audit_logs;")
    print(f"Current audit_logs count: {count}")
    await conn.close()

if __name__ == "__main__":
    asyncio.run(check())
