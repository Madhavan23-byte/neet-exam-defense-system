import asyncio
import asyncpg

async def verify():
    conn = await asyncpg.connect("postgresql://postgres:root@localhost:5432/bsea")
    print("=== TABLES ===")
    tables = await conn.fetch("""
        SELECT table_name FROM information_schema.tables 
        WHERE table_schema = 'public' AND table_name LIKE 'audit_%'
        ORDER BY table_name;
    """)
    for t in tables:
        print("Table:", t["table_name"])

    print("\n=== TRIGGERS ===")
    triggers = await conn.fetch("""
        SELECT event_object_table, trigger_name, event_manipulation, action_statement
        FROM information_schema.triggers
        WHERE event_object_schema = 'public' AND event_object_table LIKE 'audit_%'
        ORDER BY event_object_table, trigger_name;
    """)
    for trg in triggers:
        print(f"Trigger: {trg['trigger_name']} on {trg['event_object_table']} ({trg['event_manipulation']})")

    print("\n=== AUDIT_LOGS ROW COUNT & INTEGRITY ===")
    count = await conn.fetchval("SELECT count(*) FROM audit_logs;")
    created_at_nulls = await conn.fetchval("SELECT count(*) FROM audit_logs WHERE created_at IS NULL;")
    print(f"Total audit_logs: {count}, created_at IS NULL: {created_at_nulls}")

    await conn.close()

if __name__ == "__main__":
    asyncio.run(verify())
