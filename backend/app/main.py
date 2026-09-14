import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.core.database import engine, Base
from app.api.v1.router import api_router
from app.crypto.kms_interface import get_kms
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler
from app.core.dependencies import limiter

from app.core.logging import setup_logging
from app.core.telemetry_middleware import BSEAHttpTelemetryMiddleware

settings = get_settings()
setup_logging(
    environment=settings.environment,
    level=getattr(settings, "log_level", "INFO"),
    app_version=settings.app_version,
)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize KMS
    logger.info("Initializing MockKMS (Prototype Mode)")
    kms = get_kms()

    # Create tables
    logger.info("Initializing Database schema")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Start Audit Worker
    from app.modules.audit.service import audit_worker, flush_audit_queue
    worker_task = asyncio.create_task(audit_worker())
    logger.info("Audit worker started")

    yield

    # Shutdown
    logger.info("Shutting down application. Flushing audit queue...")
    await flush_audit_queue()
    await worker_task
    logger.info("Audit worker stopped")
    try:
        from app.core.redis_client import close_redis
        await close_redis()
    except Exception as e:
        logger.warning("Error closing Redis on shutdown: %s", e)
    await engine.dispose()

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    openapi_url="/api/v1/openapi.json",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Observability & telemetry middleware (Phase 3C-5B)
app.add_middleware(BSEAHttpTelemetryMiddleware)

# Set up CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact frontend domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from app.api.v1.health import router as health_router
app.include_router(health_router)
app.include_router(api_router, prefix="/api/v1")

@app.get("/health")
async def health_check():
    return {"status": "ok", "version": settings.app_version}

