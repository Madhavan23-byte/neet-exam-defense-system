# B-SEA Phase 3A: Performance, Scalability & Production Readiness Baseline

## Executive Summary
This document outlines the performance baseline for the Bharat Secure Examination Architecture (B-SEA) Reference Implementation. The objective of this phase was to measure the actual performance characteristics and identify bottlenecks without trading examination security for raw performance claims.

Two testing modes were utilized:
1. **Mode 1 — Security-Realistic Baseline**: Ran tests against the current application respecting the production-like `slowapi` rate limits.
2. **Mode 2 — Controlled Infrastructure Stress Test**: Relaxed rate limits via `BSEA_BENCHMARK_MODE=true` to stress the underlying infrastructure and database.

## Test Methodology
- **Tooling**: A custom Python `httpx` async benchmarking tool was used (`backend/tests/performance/load_test.py`).
- **Load Profiles**: Synthetic concurrent users (100 and 500) executing a realistic candidate flow:
  1. Login (`POST /candidate/auth/login`)
  2. Question Retrieval (`GET /candidate/session/question/0`)
  3. Response Autosave (`POST /candidate/session/response`)
  4. Security Event Logging (`POST /candidate/session/event`)

## Results: Mode 1 (Security-Realistic)
Testing 100 concurrent candidates against the default rate limits.

**Metrics:**
- **Status Codes**: 90% blocked by Rate Limiting (HTTP 429).
- **RPS (Legitimate)**: Limited by `10/minute` limit on the authentication endpoint. Only a fraction of requests penetrate the rate limiter.
- **Errors**: ~10% resulted in `HTTP 500` due to SQLite concurrency limitations (see bottlenecks).
- **Latencies**:
  - `login`: Avg 15,421ms | P50 15,067ms | P99 35,468ms
  - `get_question`: Avg 3,845ms
  - `autosave`: Avg ~5ms
  - `log_event`: Avg ~7ms

**Observation:** The strict IP-based rate limiting of `slowapi` successfully blocked concurrent spikes but did not prevent backend DB locking for the requests that were permitted in burst.

## Results: Mode 2 (Infrastructure Stress Test)
Testing 50 concurrent candidates with relaxed rate limits (`BSEA_BENCHMARK_MODE=true`).

**Metrics:**
- **Status Codes**: 60% resulted in `HTTP 500` Internal Server Errors; 42% resulted in Timeouts.
- **RPS**: Effectively 0 due to backend halting under load.
- **Errors**: `sqlite3.OperationalError: database is locked`.

## Bottleneck Analysis

### 1. Database Locking under Concurrency (SQLite `aiosqlite`)
The primary failure mode in both Mode 1 and Mode 2 was `sqlite3.OperationalError: database is locked`. 
- **Cause**: SQLite uses file-level locking during `INSERT` transactions. When multiple concurrent users attempt to initiate a session (writing to `candidate_sessions`), the SQLite write lock prevents concurrent access. Under high stress, these transactions time out, leading to 500 Internal Server errors.
- **Impact**: Limits concurrent logins and autosaves to <10 requests/sec.
- **Production Gap**: SQLite is not viable for production. Migration to HA PostgreSQL is strictly required for concurrent write scaling.

### 2. Synchronous Password Hashing Blocks Event Loop
- **Cause**: The application uses Argon2 password hashing (`verify_password`). This is a CPU-bound operation designed to be slow. By executing it synchronously on the main thread in FastAPI, it completely blocks the `asyncio` event loop.
- **Impact**: Average login latencies skyrocketed to over 15 seconds under minor load (100 users). Other non-blocking endpoints queue up behind the hashing operation, causing timeouts.
- **Recommendation**: Offload CPU-bound cryptographic operations (like Argon2 hashing) to a thread pool (`run_in_executor`) to prevent event-loop starvation.

### 3. Cryptographic Hash-Chain Serialization
- **Cause**: The `AuditService` relies on a global `asyncio.Lock()` to ensure that the cryptographic hash chain does not fork or branch during concurrent audit log writes.
- **Impact**: While it preserves the strict sequential cryptographic integrity required by the architecture, it serializes all writes. This creates a severe choke point when 50+ candidates trigger security events simultaneously (e.g., `TAB_SWITCH`).
- **Recommendation**: To preserve the sequential hash chain at high scale, the audit logging mechanism must be refactored into a high-throughput Append-Only message queue (e.g., Kafka or Redis Streams) processed by a dedicated sequential worker, rather than inline synchronous locking.

### 4. In-Memory Rate Limiting
- **Cause**: The current `slowapi` implementation uses in-memory state.
- **Impact**: While functional on a single node, it cannot scale horizontally across a cluster of API servers, as rate limit buckets would not be shared. 
- **Recommendation**: Transition the `slowapi` backend to Redis (as provisioned in the configuration) before production deployment.

## Conclusion
The reference implementation successfully enforces security controls but fundamentally lacks the infrastructure scaling to support examination-scale traffic (e.g., 50,000+ candidates). The benchmarks prove that **database locks** and **synchronous cryptography blocking the event loop** are the primary architectural bottlenecks. No further horizontal scaling can be achieved until SQLite is replaced and the cryptographic hash-chain lock is moved to an asynchronous worker queue.
