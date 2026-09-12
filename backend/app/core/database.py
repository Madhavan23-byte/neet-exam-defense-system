"""
B-SEA Database Configuration
SQLAlchemy async engine supporting both SQLite (development) and PostgreSQL (production).

Connection Pool Notes (Phase 3C):
──────────────────────────────────
Pool sizing is fully environment-driven via DB_POOL_SIZE / DB_MAX_OVERFLOW / DB_POOL_TIMEOUT.

IMPORTANT PRODUCTION CONSIDERATION:
  Total potential DB connections ≈ API_INSTANCES × (pool_size + max_overflow)
  e.g. 4 instances × (20 + 40) = 240 connections to PostgreSQL.

  PostgreSQL max_connections must accommodate this, and PgBouncer (transaction mode)
  should be placed in front of PostgreSQL when running multiple API instances to
  prevent connection exhaustion.

  The defaults in Settings (pool_size=10, max_overflow=20) are local benchmark values.
  Adjust DB_POOL_SIZE and DB_MAX_OVERFLOW based on:
    - measured peak concurrent requests per instance
    - available PostgreSQL max_connections
    - number of API replica instances deployed

SQLite:
  SQLite does not support connection pooling in the same way.
  We use NullPool for SQLite (each operation gets its own connection) to avoid
  "database is locked" errors from pool-level connection reuse.
  SQLite is suitable for development/testing ONLY.

PostgreSQL:
  Full async connection pooling via asyncpg.
  pool_recycle evicts connections older than db_pool_recycle seconds to prevent
  stale TCP connections being returned from the pool.
"""
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool

from app.core.config import get_settings

settings = get_settings()

_is_sqlite = settings.database_url.startswith("sqlite")

# SQLite uses NullPool to avoid file-level locking from stale pooled connections.
# PostgreSQL uses the full async pool configured by DB_POOL_SIZE / DB_MAX_OVERFLOW.
_engine_kwargs = {}
if _is_sqlite:
    _engine_kwargs["connect_args"] = {"check_same_thread": False}
    _engine_kwargs["poolclass"] = NullPool
else:
    _engine_kwargs["pool_size"] = settings.db_pool_size
    _engine_kwargs["max_overflow"] = settings.db_max_overflow
    _engine_kwargs["pool_timeout"] = settings.db_pool_timeout
    _engine_kwargs["pool_recycle"] = settings.db_pool_recycle
    _engine_kwargs["pool_pre_ping"] = True  # Health-check connections before use

engine = create_async_engine(
    settings.database_url,
    echo=False,  # Set True for SQL debugging — never in production
    **_engine_kwargs,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""
    pass


async def get_db() -> AsyncSession:
    """FastAPI dependency: provides an async database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def create_tables() -> None:
    """Create all database tables. Used during startup (dev/test only).
    Production should use Alembic migrations instead."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
