import asyncio
import asyncpg
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
import sys
import os

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:root@localhost:5432/bsea")

async def test_direct_asyncpg():
    print("--- 1. Testing Direct asyncpg Connection ---")
    raw_url = DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")
    conn = await asyncpg.connect(raw_url)
    version = await conn.fetchval("SELECT version()")
    print(f"Direct asyncpg connection successful!")
    print(f"Version: {version}")
    
    tables = await conn.fetch("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")
    print(f"Existing public tables: {[t['table_name'] for t in tables]}")
    await conn.close()

async def test_sqlalchemy_engine():
    print("\n--- 2. Testing SQLAlchemy Async Engine ---")
    engine = create_async_engine(DATABASE_URL, echo=False)
    async with engine.connect() as conn:
        result = await conn.execute(text("SELECT 1 AS alive, current_database() AS db, current_user AS usr, version() AS ver"))
        row = result.mappings().one()
        print(f"SQLAlchemy async engine connection successful!")
        print(f"Database: {row['db']}")
        print(f"User: {row['usr']}")
        print(f"Status: alive={row['alive']}")
    await engine.dispose()

async def main():
    try:
        await test_direct_asyncpg()
        await test_sqlalchemy_engine()
        print("\nAll connection verifications PASSED!")
    except Exception as e:
        print(f"\nConnection FAILED: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
