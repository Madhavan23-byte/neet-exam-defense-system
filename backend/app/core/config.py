"""
B-SEA Backend Configuration
Centralized settings management using Pydantic Settings.
All secrets must come from environment variables — never hardcoded.
"""
from functools import lru_cache
from typing import List
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ───────────────────────────────────────────────────────────
    app_name: str = "B-SEA"
    app_version: str = "1.0.0"
    environment: str = Field(default="development")
    log_level: str = Field(default="INFO")
    debug: bool = Field(default=False)

    # ── Database ──────────────────────────────────────────────────────────────
    # Default: SQLite for local development without Docker.
    # For PostgreSQL: set DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/bsea_dev
    # For Alembic sync migrations: set SYNC_DATABASE_URL=postgresql+psycopg2://...
    database_url: str = Field(
        default="sqlite+aiosqlite:///./bsea_demo.db",
        alias="DATABASE_URL",
    )
    sync_database_url: str = Field(
        default="sqlite:///./bsea_demo.db",
        alias="SYNC_DATABASE_URL",
    )

    # ── Connection Pool ───────────────────────────────────────────────────────
    # IMPORTANT PRODUCTION CONSIDERATION:
    # Total potential database connections ≈ API_INSTANCES × (pool_size + max_overflow)
    # Example: 4 API instances × (20 + 40) = 240 connections maximum.
    # PostgreSQL's max_connections must exceed this, and PgBouncer should be used
    # in transaction-mode pooling to multiplex connections at scale.
    # These local benchmark defaults are NOT production-final values.
    db_pool_size: int = Field(default=10, alias="DB_POOL_SIZE")
    db_max_overflow: int = Field(default=20, alias="DB_MAX_OVERFLOW")
    db_pool_timeout: int = Field(default=30, alias="DB_POOL_TIMEOUT")
    # pool_recycle prevents stale connections (important for PostgreSQL TCP keep-alive)
    db_pool_recycle: int = Field(default=1800, alias="DB_POOL_RECYCLE")  # 30 minutes

    # ── Redis ─────────────────────────────────────────────────────────────────
    redis_url: str = Field(
        default="redis://:bsea_redis_password_change_me@localhost:6379/0"
    )
    redis_session_ttl: int = 7200  # 2 hours (exam session lifetime)
    redis_rate_limit_ttl: int = 60

    # ── MinIO / Object Storage ────────────────────────────────────────────────
    minio_endpoint: str = Field(default="localhost:9000")
    minio_access_key: str = Field(default="bsea_minio_access_key")
    minio_secret_key: str = Field(default="bsea_minio_secret")
    minio_secure: bool = Field(default=False)
    minio_bucket_questions: str = "bsea-questions"
    minio_bucket_configs: str = "bsea-configs"
    minio_bucket_audit: str = "bsea-audit"

    # ── JWT / Authentication ──────────────────────────────────────────────────
    secret_key: str = Field(
        default="CHANGE_ME_IN_PRODUCTION_MINIMUM_64_CHARACTERS_LONG_SECRET_KEY_abc123"
    )
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    mfa_issuer: str = "B-SEA Secure Examination"

    # ── MockKMS (Prototype Cryptographic Keys) ────────────────────────────────
    # SECURITY NOTE: These are PROTOTYPE keys only.
    # Production MUST use Cloud KMS / HSM. Never commit real keys.
    mock_kms_master_key: str = Field(
        default="bsea_kms_master_key_change_me_xx"
    )
    mock_kms_signing_key: str = Field(
        default="bsea_ed25519_seed_32_bytes_chng"
    )

    # ── CORS ─────────────────────────────────────────────────────────────────
    cors_origins: str = Field(
        default="http://localhost:5173,http://localhost:3000"
    )

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",")]

    # ── Rate Limiting ─────────────────────────────────────────────────────────
    benchmark_mode: bool = Field(default=False, alias="BSEA_BENCHMARK_MODE")
    
    @property
    def rate_limit_ip_login(self) -> str:
        return "10000/minute" if self.benchmark_mode else "500/minute"

    @property
    def rate_limit_identity_login(self) -> str:
        return "10000/minute" if self.benchmark_mode else "5/minute"

    @property
    def rate_limit_api(self) -> str:
        return "100000/minute" if self.benchmark_mode else "20/minute"

    @property
    def rate_limit_candidate(self) -> str:
        return "200000/minute" if self.benchmark_mode else "200/minute"

    # ── Threshold Authorization ───────────────────────────────────────────────
    # Number of release authorities required to approve exam release
    default_release_threshold: int = 3
    release_approval_expiry_hours: int = 24

    # ── Exam Security ─────────────────────────────────────────────────────────
    min_centre_readiness_pct: float = 90.0
    session_heartbeat_interval_sec: int = 30
    session_heartbeat_max_miss: int = 3  # Miss 3 heartbeats → flag
    max_tab_switches_before_flag: int = 5
    max_mfa_attempts: int = 5

    # ── Anomaly Detection ─────────────────────────────────────────────────────
    anomaly_brute_force_threshold: int = 5
    anomaly_bulk_question_threshold: int = 20
    anomaly_failed_mfa_threshold: int = 3


@lru_cache()
def get_settings() -> Settings:
    """
    Returns cached settings singleton.
    Use dependency injection: Depends(get_settings)
    """
    return Settings()
