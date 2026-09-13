# ── Stage 1: Builder ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies required for compiling C extensions (asyncpg, argon2, cryptography)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# Create isolated build environment and install dependencies
COPY requirements.txt .
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# ── Stage 2: Production Runtime ──────────────────────────────────────────────
FROM python:3.12-slim AS runtime

WORKDIR /app

# Security: Create non-root system group and user
RUN groupadd -r -g 10001 bsea && \
    useradd -r -u 10001 -g bsea -s /sbin/nologin -d /app bsea

# Install minimal runtime dependencies only (libpq for PostgreSQL, curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder --chown=bsea:bsea /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Environment configuration
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOST=0.0.0.0 \
    PORT=8000 \
    GUNICORN_WORKERS=4 \
    GUNICORN_TIMEOUT=60 \
    GUNICORN_GRACEFUL_TIMEOUT=30

# Copy application source code (explicitly excluding any secrets or local environments via .dockerignore)
COPY --chown=bsea:bsea app/ /app/app/
COPY --chown=bsea:bsea alembic/ /app/alembic/
COPY --chown=bsea:bsea alembic.ini /app/alembic.ini

# Drop root privileges
USER bsea

EXPOSE 8000

# Health check using the lightweight liveness probe
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8000}/health/live || exit 1

# Standard graceful shutdown signal for Gunicorn
STOPSIGNAL SIGQUIT

# Production process: Gunicorn process supervisor multiplexing Uvicorn async workers
CMD ["sh", "-c", "exec gunicorn app.main:app -w ${GUNICORN_WORKERS:-4} -k uvicorn.workers.UvicornWorker -b ${HOST:-0.0.0.0}:${PORT:-8000} --access-logfile - --error-logfile - --graceful-timeout ${GUNICORN_GRACEFUL_TIMEOUT:-30} --timeout ${GUNICORN_TIMEOUT:-60}"]
