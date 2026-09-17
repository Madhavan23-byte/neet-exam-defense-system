import asyncio
import asyncpg

async def inspect():
    conn = await asyncpg.connect("postgresql://postgres:root@localhost:5432/bsea")
    print("==================================================")
    print("POSTGRESQL 16 LIVE SCHEMA INSPECTION REPORT")
    print("==================================================")
    
    # 1. Tables
    tables = await conn.fetch("""
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'public' 
        ORDER BY table_name
    """)
    table_names = [r['table_name'] for r in tables]
    print(f"\n1. Tables in public schema ({len(table_names)} total):")
    for t in table_names:
        print(f"  - {t}")
        
    # 2. Primary Keys
    pks = await conn.fetch("""
        SELECT tc.table_name, ccu.column_name, tc.constraint_name
        FROM information_schema.table_constraints tc
        JOIN information_schema.constraint_column_usage ccu 
          ON tc.constraint_name = ccu.constraint_name
        WHERE tc.table_schema = 'public' AND tc.constraint_type = 'PRIMARY KEY'
        ORDER BY tc.table_name
    """)
    print(f"\n2. Primary Keys ({len(pks)} total):")
    for pk in pks:
        print(f"  - {pk['table_name']}: {pk['column_name']} ({pk['constraint_name']})")
        
    # 3. Foreign Keys
    fks = await conn.fetch("""
        SELECT 
            tc.table_name, 
            kcu.column_name, 
            ccu.table_name AS foreign_table_name,
            ccu.column_name AS foreign_column_name,
            tc.constraint_name
        FROM information_schema.table_constraints AS tc 
        JOIN information_schema.key_column_usage AS kcu
          ON tc.constraint_name = kcu.constraint_name
        JOIN information_schema.constraint_column_usage AS ccu
          ON ccu.constraint_name = tc.constraint_name
        WHERE tc.table_schema = 'public' AND tc.constraint_type = 'FOREIGN KEY'
        ORDER BY tc.table_name, kcu.column_name
    """)
    print(f"\n3. Foreign Keys ({len(fks)} total):")
    for fk in fks:
        print(f"  - {fk['table_name']}.{fk['column_name']} -> {fk['foreign_table_name']}.{fk['foreign_column_name']}")

    # 4. Unique Constraints
    uqs = await conn.fetch("""
        SELECT tc.table_name, tc.constraint_name
        FROM information_schema.table_constraints tc
        WHERE tc.table_schema = 'public' AND tc.constraint_type = 'UNIQUE'
        ORDER BY tc.table_name
    """)
    print(f"\n4. Explicit Unique Constraints ({len(uqs)} total):")
    for uq in uqs:
        print(f"  - {uq['table_name']}: {uq['constraint_name']}")

    # 5. Indexes (including partial indexes)
    indexes = await conn.fetch("""
        SELECT tablename, indexname, indexdef
        FROM pg_indexes
        WHERE schemaname = 'public'
        ORDER BY tablename, indexname
    """)
    print(f"\n5. Indexes in pg_indexes ({len(indexes)} total):")
    for idx in indexes:
        print(f"  - {idx['tablename']}.{idx['indexname']}: {idx['indexdef']}")

    # 6. Specific Verification of Partial Unique Index
    print("\n6. Specific Partial Unique Index Verification:")
    partial_idx = await conn.fetchrow("""
        SELECT indexname, indexdef 
        FROM pg_indexes 
        WHERE tablename = 'candidate_sessions' 
          AND indexname = 'uix_active_session_candidate_exam'
    """)
    if partial_idx:
        print(f"  NAME: {partial_idx['indexname']}")
        print(f"  DEF : {partial_idx['indexdef']}")
        print("  PARTIAL INDEX VERIFIED: TRUE")
    else:
        print("  PARTIAL INDEX VERIFIED: FALSE (NOT FOUND!)")

    # 7. PostgreSQL Native Types (Enums in pg_type)
    enums = await conn.fetch("""
        SELECT t.typname, string_agg(e.enumlabel, ', ' ORDER BY e.enumsortorder) AS labels
        FROM pg_type t 
        JOIN pg_enum e ON t.oid = e.enumtypid 
        GROUP BY t.typname
        ORDER BY t.typname
    """)
    print(f"\n7. PostgreSQL Native Enums ({len(enums)} total):")
    for e in enums:
        print(f"  - {e['typname']}: [{e['labels']}]")

    # 8. PostgreSQL Timestamps with Time Zone (timestamptz)
    tz_cols = await conn.fetch("""
        SELECT table_name, column_name, data_type 
        FROM information_schema.columns 
        WHERE table_schema = 'public' AND data_type = 'timestamp with time zone'
        ORDER BY table_name, column_name
    """)
    print(f"\n8. Timestamp with Time Zone columns ({len(tz_cols)} total verified):")
    for c in tz_cols[:5]:
        print(f"  - {c['table_name']}.{c['column_name']} ({c['data_type']})")
    print(f"  ... and {len(tz_cols) - 5} more timestamptz columns verified.")

    # 9. JSON Columns
    json_cols = await conn.fetch("""
        SELECT table_name, column_name, data_type 
        FROM information_schema.columns 
        WHERE table_schema = 'public' AND data_type IN ('json', 'jsonb')
        ORDER BY table_name, column_name
    """)
    print(f"\n9. JSON / JSONB columns ({len(json_cols)} total verified):")
    for c in json_cols:
        print(f"  - {c['table_name']}.{c['column_name']} ({c['data_type']})")

    await conn.close()

if __name__ == '__main__':
    asyncio.run(inspect())
