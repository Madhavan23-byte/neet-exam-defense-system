import asyncio
import sys
from sqlalchemy import text

# Import the actual B-SEA application modules
from app.core.config import get_settings
from app.core.database import engine, get_db, _is_sqlite

async def verify_backend_pg_integration():
    settings = get_settings()
    print("==================================================")
    print("B-SEA BACKEND POSTGRESQL INTEGRATION VERIFICATION")
    print("==================================================")
    print(f"Active DATABASE_URL     : {settings.database_url}")
    print(f"Is SQLite active?       : {_is_sqlite}")
    print(f"Dialect name            : {engine.dialect.name}")
    print(f"Driver name             : {engine.dialect.driver}")
    print(f"Pool class              : {engine.pool.__class__.__name__}")
    print(f"Pool size               : {getattr(engine.pool, '_pool_size', 'N/A')}")
    print(f"Max overflow            : {getattr(engine.pool, '_max_overflow', 'N/A')}")
    print("--------------------------------------------------")

    if _is_sqlite:
        raise RuntimeError("Expected PostgreSQL to be active, but SQLite was detected!")

    print("Connecting via backend get_db() session generator...")
    async for session in get_db():
        result = await session.execute(
            text("SELECT current_database() AS db, current_user AS usr, version() AS ver, 1 AS health_check")
        )
        row = result.mappings().one()
        print(f"Connected to Database   : {row['db']}")
        print(f"Connected as User       : {row['usr']}")
        print(f"PostgreSQL Version      : {row['ver']}")
        print(f"Health Check Value      : {row['health_check']}")
        print("--------------------------------------------------")
        print("Backend PostgreSQL session verified successfully via get_db()!")
        break

    await engine.dispose()

if __name__ == "__main__":
    asyncio.run(verify_backend_pg_integration())
