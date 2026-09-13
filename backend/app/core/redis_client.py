"""
B-SEA — Centralized Redis Connection Manager (Phase 3C-1)
Provides an asynchronous Redis client with connection pooling, retries,
health checks, and safe URL logging.
"""
from __future__ import annotations

import logging
import re
from typing import Optional
import redis.asyncio as aioredis
from redis.asyncio.retry import Retry
from redis.backoff import ExponentialBackoff

from app.core.config import get_settings

logger = logging.getLogger("bsea.redis")
settings = get_settings()

_pool: Optional[aioredis.ConnectionPool] = None
_client: Optional[aioredis.Redis] = None


def mask_redis_url(url: str) -> str:
    """Mask password in Redis URL for safe logging."""
    if not url:
        return ""
    if "://" in url and "@" in url:
        prefix, rest = url.split("://", 1)
        auth, host = rest.split("@", 1)
        if ":" in auth:
            user, _ = auth.split(":", 1)
            return f"{prefix}://{user}:***@{host}"
        return f"{prefix}://***@{host}"
    return url


def get_redis_pool() -> aioredis.ConnectionPool:
    """
    Initialize or return the centralized Redis connection pool.
    Configured with connection timeouts, socket timeouts, and exponential backoff retry.
    """
    global _pool
    if _pool is None:
        safe_url = mask_redis_url(settings.redis_url)
        logger.info("Initializing Redis connection pool: %s", safe_url)

        # Exponential backoff retry policy (3 retries, base 0.1s, max 2.0s)
        retry_policy = Retry(ExponentialBackoff(cap=2.0, base=0.1), retries=3)

        _pool = aioredis.ConnectionPool.from_url(
            settings.redis_url,
            max_connections=50,
            socket_connect_timeout=3.0,
            socket_timeout=3.0,
            retry=retry_policy,
            retry_on_timeout=True,
            health_check_interval=30,
        )
    return _pool


def get_redis_client() -> aioredis.Redis:
    """
    Get or initialize the global async Redis client singleton.
    """
    global _client
    if _client is None:
        pool = get_redis_pool()
        _client = aioredis.Redis(connection_pool=pool)
    return _client


def set_redis_client_override(client: Optional[aioredis.Redis]) -> None:
    """
    Override client for testing or failure simulation.
    """
    global _client
    _client = client


async def close_redis() -> None:
    """
    Gracefully disconnect Redis client and close connection pool.
    """
    global _client, _pool
    if _client is not None:
        try:
            await _client.aclose()
        except Exception as e:
            logger.warning("Error closing Redis client: %s", e)
        _client = None

    if _pool is not None:
        try:
            await _pool.disconnect()
        except Exception as e:
            logger.warning("Error disconnecting Redis pool: %s", e)
        _pool = None
    logger.info("Redis connection pool closed")


async def check_redis_health() -> bool:
    """
    Perform a health ping to Redis.
    Returns True if healthy, False if unreachable or failing.
    """
    client = get_redis_client()
    try:
        res = await client.ping()
        return bool(res)
    except Exception as e:
        logger.warning("Redis health ping failed: %s", e)
        return False
