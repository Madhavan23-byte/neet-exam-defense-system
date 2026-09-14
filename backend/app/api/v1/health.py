"""
B-SEA — Health and Readiness Check Endpoints (Phase 3C-1)
Provides liveness and readiness probes for orchestrators (ECS, Docker Compose, Kubernetes, ALB).
"""
from __future__ import annotations

import logging
from typing import Dict, Any, Optional
from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.core.config import get_settings
from app.core.database import engine
from app.core.redis_client import check_redis_health
from app.crypto.kms_interface import get_kms

logger = logging.getLogger("bsea.health")
settings = get_settings()

router = APIRouter(tags=["Health"])


@router.get("/health/live", status_code=status.HTTP_200_OK)
async def liveness_probe():
    """
    Liveness probe: Determines if the process and event loop are responsive.
    Does NOT perform external dependency checks.
    """
    return {
        "status": "alive",
        "app": settings.app_name,
        "version": settings.app_version,
    }


@router.get("/health/ready")
async def readiness_probe():
    """
    Readiness probe: Determines whether the instance is ready to receive traffic.
    Checks:
    - PostgreSQL database connectivity
    - Redis connectivity
    - Cryptographic provider (MockKMS in local, AWS KMS in cloud)
    """
    checks: Dict[str, Any] = {
        "database": "unknown",
        "redis": "unknown",
        "crypto": "unknown",
    }
    healthy = True

    # 1. Database check
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as e:
        logger.warning("Readiness probe: database check failed: %s", e)
        checks["database"] = f"error: {str(e)}"
        healthy = False

    # 2. Redis check
    try:
        redis_alive = await check_redis_health()
        if redis_alive:
            checks["redis"] = "ok"
        else:
            checks["redis"] = "error: unreachable"
            # In production or local production-parity, Redis is required for shared rate limiting
            healthy = False
    except Exception as e:
        logger.warning("Readiness probe: redis check failed: %s", e)
        checks["redis"] = f"error: {str(e)}"
        healthy = False

    # 3. Cryptographic provider check
    try:
        kms = get_kms()
        if kms is not None:
            p_name = getattr(kms, "provider_name", "MockKMS")
            if p_name == "AWS-KMS":
                # Verify AWS-KMS readiness safely without exposing sensitive AWS details
                if hasattr(kms, "readiness_check") and not kms.readiness_check():
                    checks["crypto"] = "degraded (AWS-KMS)"
                    healthy = False
                else:
                    checks["crypto"] = "ok (AWS-KMS)"
            else:
                checks["crypto"] = "ok (MockKMS)"
        else:
            checks["crypto"] = "error: provider uninitialized"
            healthy = False
    except Exception as e:
        logger.warning("Readiness probe: crypto check failed: %s", e)
        # Never expose KMS identifiers or sensitive AWS errors publicly
        checks["crypto"] = "error: cryptographic provider unavailable"
        healthy = False

    status_code = status.HTTP_200_OK if healthy else status.HTTP_503_SERVICE_UNAVAILABLE
    response_payload = {
        "status": "ready" if healthy else "not_ready",
        "environment": settings.environment,
        "mode": "LOCAL" if settings.environment != "production" else "CLOUD",
        "checks": checks,
    }
    return JSONResponse(status_code=status_code, content=response_payload)


from fastapi import Header, Response
from app.core.metrics import metrics_registry


@router.get("/metrics")
async def get_prometheus_metrics(
    x_bsea_metrics_key: Optional[str] = Header(None, alias="X-BSEA-Metrics-Key"),
):
    """
    Phase 3C-5B: Production-safe Prometheus metrics endpoint.
    Requires internal scraper authentication via X-BSEA-Metrics-Key header.
    Never exposes question content, answer keys, candidate data, or secrets.
    """
    expected_key = getattr(settings, "metrics_scraper_key", "bsea-metrics-scraper-secret-local")
    if not x_bsea_metrics_key or x_bsea_metrics_key != expected_key:
        logger.warning(
            "Unauthorized metrics scrape attempt",
            extra={"action": "METRICS_SCRAPE", "result": "DENIED", "error_code": "FORBIDDEN"},
        )
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": "Forbidden: Invalid or missing metrics authorization"},
        )

    content = metrics_registry.generate_prometheus_text()
    return Response(
        content=content,
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )
