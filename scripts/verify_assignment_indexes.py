import asyncio
import sys
from sqlalchemy import text
from app.core.database import engine

async def main():
    async with engine.connect() as conn:
        res = await conn.execute(text("""
            SELECT indexname, indexdef 
            FROM pg_indexes 
            WHERE tablename = 'question_assignments'
            ORDER BY indexname;
        """))
        rows = res.fetchall()
        print("INDEX COUNT:", len(rows))
        for row in rows:
            print(f"- {row[0]}: {row[1]}")

        # check alembic version
        ver = await conn.execute(text("SELECT version_num FROM alembic_version;"))
        v = ver.scalar()
        print("ALEMBIC VERSION:", v)

if __name__ == "__main__":
    asyncio.run(main())
