# B-SEA Phase 3C-1: Cloud Foundation Architecture & Implementation

## 1. Executive Summary & Objective

Phase 3C-1 establishes the **Cloud Foundation** for the Bharat Secure Examination Architecture (B-SEA). It prepares the system for horizontally scalable, multi-instance cloud deployments (ECS/EKS) while preserving strict local development parity and uncompromising cryptographic security invariants.

**Baseline Frozen Commit**: `8398d042096581f6cd2d2987cc2dfa87a758b62f`
**Approved Architecture Reference**: `BSEA-ARCH-P3C-REV-03`
**Status**: IMPLEMENTED & VALIDATED

---

## 2. Implementation Scope Matrix

| Capability / Component | Classification | Current Status | Notes |
|---|---|---|---|
| **Multi-Stage Backend Dockerization** | `IMPLEMENTED NOW` | **Complete** | Python 3.12-slim, non-root user `bsea:bsea`, Gunicorn + Uvicorn workers |
| **Async CPU-Bound Argon2id** | `IMPLEMENTED NOW` | **Complete** | Offloaded via `asyncio.to_thread`, zero event loop blockage |
| **Centralized Async Redis Manager** | `IMPLEMENTED NOW` | **Complete** | Connection pooling, retry backoff, ping health probe, credential masking |
| **Distributed Rate Limiting (`slowapi`)** | `IMPLEMENTED NOW` | **Complete** | Redis-backed storage with memory fallback for test isolation |
| **Differentiated Redis Failure Policy** | `IMPLEMENTED NOW` | **Complete** | Security-sensitive: fail-closed (503); Candidate: graceful degradation |
| **Candidate Delivery Resiliency** | `IMPLEMENTED NOW` | **Complete** | PostgreSQL-authoritative grants, direct ACID autosave, non-fatal telemetry |
| **Health & Readiness Endpoints** | `IMPLEMENTED NOW` | **Complete** | `GET /health/live` (lightweight), `GET /health/ready` (environment-aware) |
| **Frontend Production Packaging** | `IMPLEMENTED NOW` | **Complete** | Vite multi-stage build, Nginx 1.27-alpine, SPA fallback, security headers |
| **Local Production-Parity Compose** | `IMPLEMENTED NOW` | **Complete** | Frontend (Nginx), Backend (multi-worker), PostgreSQL, Redis, MinIO |
| **Configuration Tier Separation** | `IMPLEMENTED NOW` | **Complete** | Development, Testing, Local Production-Parity, AWS Staging |
| **AWS Terraform Infrastructure** | `FUTURE / PHASE 3C-2+` | *Deferred* | VPC, private subnets, ECS Fargate, ALB, RDS PostgreSQL 16, RDS Proxy, ElastiCache |
| **Native AWS KMS Ed25519 Signing** | `FUTURE / PHASE 3C-3` | *Deferred* | `AWSKMSProvider` with KeySpec `ECC_NIST_EDWARDS25519` |
| **WAF & Cloud Security Hardening** | `FUTURE / PHASE 3C-4` | *Deferred* | AWS WAF rate-limiting, IP reputation, shield protection |
| **Cloud Load & Scalability Testing** | `FUTURE / PHASE 3C-5` | *Deferred* | Distributed Locust / k6 load simulation on cloud infrastructure |

---

## 3. Backend Production Docker Architecture

### 3.1 Multi-Stage Build Pipeline
The backend container is structured across two distinct stages in `backend/Dockerfile`:

1. **Stage 1 (`builder`)**:
   - Base: `python:3.12-slim`
   - Role: Compiles C-extensions (such as `psycopg2`, `asyncpg`, `argon2-cffi`, `cryptography`) using `build-essential` and system headers.
   - Outputs: Wheel cache and pre-compiled virtual environment.
2. **Stage 2 (`runtime`)**:
   - Base: `python:3.12-slim`
   - Role: Copies only the runtime virtualenv and application source code. Excludes compilers, debugging tools, development dependencies, `.env` files, and secrets.
   - User: Dedicated unprivileged system user `bsea` (UID 10001, GID 10001).
   - Signals: `STOPSIGNAL SIGTERM` for clean process teardown.

### 3.2 Process Management: Gunicorn + Uvicorn Workers
In production, execution is delegated to Gunicorn managing asynchronous Uvicorn workers:
```
Gunicorn Master (Process Supervisor, Signal Handling)
  ├── Uvicorn Worker 1 (Asyncio Event Loop + FastAPI App)
  ├── Uvicorn Worker 2 (Asyncio Event Loop + FastAPI App)
  └── Uvicorn Worker N (Asyncio Event Loop + FastAPI App)
```
- **Configurability**:
  - `GUNICORN_WORKERS`: Configurable via environment variable (default: 4).
  - `HOST`: Configurable bind address (default: `0.0.0.0`).
  - `PORT`: Configurable bind port (default: `8000`).
  - `TIMEOUT`: Graceful timeout handling (default: 120s).

---

## 4. CPU-Bound Argon2id Offloading

### 4.1 Problem Statement (Phase 3A Baseline)
Argon2id is a memory-hard, CPU-intensive hashing algorithm (64MB memory cost, time cost 3, parallelism 4). When executed synchronously within FastAPI async route handlers, password verification halts the Python asyncio event loop for 80–250ms per operation, degrading throughput for concurrent candidate examination requests.

### 4.2 Implementation
In `backend/app/core/security.py`, password hashing and verification are wrapped in `asyncio.to_thread`:
```python
async def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against Argon2 hash in worker thread to prevent event loop blocking."""
    return await asyncio.to_thread(pwd_context.verify, plain_password, hashed_password)

async def hash_password(password: str) -> str:
    """Generate Argon2 password hash in worker thread."""
    return await asyncio.to_thread(pwd_context.hash, password)
```
**Invariants Preserved**:
- Argon2 parameters remain unchanged (no security reduction for speed).
- MFA, RBAC, and candidate credential validation semantics remain identical.
- Async event loop remains fully responsive during concurrent authentication bursts.

---

## 5. Centralized Redis Connection Manager

### 5.1 Architecture & Resilience
The centralized Redis connection manager is located at `backend/app/core/redis_client.py`.

Key Capabilities:
- **Asynchronous Client**: Built on `redis.asyncio.Redis` using `ConnectionPool`.
- **Configurable Connection Limits**: `max_connections` (default: 50), `socket_connect_timeout` (2.0s), `socket_timeout` (2.0s).
- **Exponential Backoff Retry**: Automatic retry policy for transient network hiccups via `Retry(ExponentialBackoff(), 3)`.
- **Health Verification**: `ping()` method validates round-trip connectivity.
- **Graceful Teardown**: `close_redis()` gracefully flushes and disconnects during application shutdown.
- **Credential Masking**: `mask_redis_url()` ensures connection strings containing passwords (e.g., `redis://:secret@host:6379/0`) are masked in logs as `redis://:****@host:6379/0`.

---

## 6. Distributed Rate Limiting & Differentiated Failure Policy

### 6.1 slowapi Redis Integration
Rate limiting is transitioned from process-local memory to Redis-backed distributed state using `slowapi`. When multiple Gunicorn workers or container replicas run concurrently, rate-limit state is synchronized across all instances via Redis keys.

For test environments and isolated CI runs, `get_rate_limit_storage_uri()` defaults to `memory://` when `TESTING=1` or `ENVIRONMENT=testing`.

### 6.2 Endpoint-Specific Rate Limits
Rate limits are tuned specifically by endpoint sensitivity:

| Endpoint Category | Endpoints | Default Limit | Policy Rationale |
|---|---|---|---|
| **Security-Sensitive: Auth Login** | `POST /api/v1/auth/login` | `10/minute` | Brute-force & credential stuffing defense |
| **Security-Sensitive: MFA** | `POST /api/v1/auth/mfa/verify` | `5/minute` | Strict token exhaustion defense |
| **Security-Sensitive: Break-Glass** | `POST /api/v1/break-glass/requests` | `5/minute` | Emergency access throttling & spam prevention |
| **Security-Sensitive: Reviewer Access**| Reviewer operations | `30/minute` | High-security audit operations |
| **Availability-Sensitive: Questions** | `POST /api/v1/candidates/questions/{id}/access` | `120/minute` | High-frequency candidate navigation |
| **Availability-Sensitive: Autosave** | `POST /api/v1/candidates/responses/autosave` | `300/minute` | Rapid keystroke & answer state synchronization |
| **Availability-Sensitive: Heartbeat**| `POST /api/v1/candidates/sessions/{id}/heartbeat`| `60/minute` | Periodic candidate telemetry & liveness tracking |

### 6.3 Differentiated Failure Behavior (`BSEALimiter`)
The custom `BSEALimiter` in `backend/app/core/dependencies.py` implements the Phase 3C resilience policy:

1. **Security-Sensitive Endpoints (Fail-Closed)**:
   - If Redis becomes unavailable, the system **REFUSES** to fall back to uncoordinated local memory.
   - Access is denied with `HTTP 503 Service Unavailable` (`"Distributed rate limiting service unavailable. Access denied for security."`).
   - Prevents distributed brute-force attacks during infrastructure degradation.
2. **Candidate Examination Endpoints (Graceful Degradation)**:
   - If Redis rate-limit checks fail, candidate requests **PROCEED** to the underlying business logic.
   - Question access authorization is strictly validated against the authoritative PostgreSQL database via `QuestionAccessGrant`.
   - Security is never weakened because authorization is cryptographically enforced by PostgreSQL and KMS, not rate limits.
3. **Autosave Reliability**:
   - Autosave writes directly to PostgreSQL using ACID transactions. Redis failure has zero impact on candidate response persistence.
4. **Heartbeat Non-Fatal Liveness**:
   - Heartbeat Redis errors do not terminate active candidate exam sessions.

---

## 7. Health & Readiness Probes

Located in `backend/app/api/v1/health.py`:

### 7.1 Liveness Probe (`GET /health/live`)
- **Purpose**: Kubernetes / ECS container liveness check. Confirms the Python process and asyncio event loop are responsive.
- **Cost**: Microsecond execution. Zero downstream dependency checks (no DB, no Redis, no KMS).
- **Response**: `200 OK` `{"status": "alive"}`.

### 7.2 Readiness Probe (`GET /health/ready`)
- **Purpose**: Load balancer / ALB readiness check. Determines whether the container should receive candidate and administrative traffic.
- **Environment-Aware Checks**:
  1. **PostgreSQL**: Executes `SELECT 1` via `AsyncSession`.
  2. **Redis**: Executes `client.ping()` via async connection manager.
  3. **Cryptographic Key Provider**:
     - Local/Testing: Confirms `MockKMS` is initialized and healthy.
     - Cloud (Future Phase 3C-3): Confirms AWS KMS connectivity.
- **Response**:
  - Healthy: `200 OK` with status dictionary and UTC timestamp.
  - Unhealthy: `503 Service Unavailable` with specific error details.

---

## 8. Frontend Production Packaging

### 8.1 Multi-Stage Packaging
Located in `frontend/Dockerfile`:
- **Stage 1 (`builder`)**: Node 20-alpine runs `npm ci` and `npm run build` using Vite. Output: Optimized, tree-shaken static assets in `/app/dist`.
- **Stage 2 (`runtime`)**: Nginx 1.27-alpine serves static assets. Runs as unprivileged `nginx` user.

### 8.2 Production Nginx Configuration
Located in `frontend/nginx.conf`:
- **SPA Routing**: `try_files $uri $uri/ /index.html;` ensures React Router handles deep navigation.
- **Security Headers**:
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Permissions-Policy: geolocation=(), camera=(), microphone=()`
- **Asset Caching**: Static assets (`/assets/`) served with `Cache-Control "public, max-age=31536000, immutable"`.
- **API Proxy**: Upstream proxying to FastAPI backend `/api/` with proper header forwarding (`X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Proto`).
- **Secret Cleanliness**: Verified zero inclusion of database URLs, JWT signing keys, KMS secrets, or AWS credentials in compiled bundles.

---

## 9. Local Production-Parity Docker Compose

`docker-compose.yml` orchestrates full local production parity:
```
                ┌─────────────────────────┐
                │   Browser Client        │
                └────────────┬────────────┘
                             │ Port 80
                             ▼
                ┌─────────────────────────┐
                │   Frontend (Nginx)      │
                │   - Static Asset Cache  │
                │   - SPA Routing         │
                └────────────┬────────────┘
                             │ /api/ (Internal Network)
                             ▼
                ┌─────────────────────────┐
                │   Backend (FastAPI)     │
                │   - Gunicorn (4 Workers)│
                │   - Async Argon2id      │
                │   - MockKMS             │
                └──────┬────────────┬─────┘
                       │            │
          Internal Port│5432        │Internal Port 6379
                       ▼            ▼
        ┌─────────────────┐      ┌─────────────────┐
        │  PostgreSQL 16  │      │  Redis 7-Alpine │
        │  (Authoritative)│      │  (Rate Limiting)│
        └─────────────────┘      └─────────────────┘
```
- All inter-container communication uses isolated internal Docker networks.
- Service dependencies gated by container health checks (`condition: service_healthy`).

---

## 10. Configuration Hierarchy & Tier Separation

Documented in `.env.example`:
1. **Tier 1: Development (`ENVIRONMENT=development`)**:
   - SQLite or local Postgres, in-memory rate limiting, MockKMS.
2. **Tier 2: Testing (`ENVIRONMENT=testing`, `TESTING=1`)**:
   - Isolated ephemeral DB, NullPool connections, in-memory rate limiting, MockKMS.
3. **Tier 3: Local Production-Parity (`ENVIRONMENT=production`)**:
   - Docker Compose, multi-worker backend, PostgreSQL 16 container, Redis 7 container, MockKMS.
4. **Tier 4: AWS Staging/Production (`FUTURE / PHASE 3C-2+`)**:
   - AWS ECS Fargate, Amazon RDS PostgreSQL 16 with AWS RDS Proxy, Amazon ElastiCache Redis, native AWS KMS Ed25519.

---

## 11. Known Limitations & Phase 3C-2 Handoff

### Known Limitations (By Design in Phase 3C-1)
1. **Multi-Worker Audit Hash Chain**:
   - The current cryptographic audit trail uses an in-process memory queue (`audit_queue`) with a background worker thread. When running multiple Gunicorn workers, hash chaining remains process-local.
   - *The distributed audit ingestion architecture (e.g., Redis Streams / sequence-based queuing) remains PROPOSED / FUTURE IMPLEMENTATION and is NOT an implementation requirement for Phase 3C-2.*
2. **MockKMS Active Locally**:
   - Native AWS KMS asymmetric Ed25519 signing (`ECC_NIST_EDWARDS25519`) will be implemented in Phase 3C-3. MockKMS remains the cryptographic engine in Phase 3C-1.
3. **Container Testing on Development Host**:
   - Dockerfiles and Docker Compose manifests were statically/configuration validated. Full container runtime validation remains pending in a Docker-enabled Linux/CI environment.

### Phase 3C-2 Handoff Requirements
- Implement Terraform modules for VPC, ECS Fargate cluster, ALB, AWS RDS PostgreSQL 16, AWS RDS Proxy, and ElastiCache Redis.
- Configure secure AWS SSM Parameter Store / Secrets Manager references for environment configuration.
- Wire ALB target groups to `/health/live` and `/health/ready`.
