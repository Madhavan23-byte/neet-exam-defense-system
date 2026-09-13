# B-SEA Phase 3D — Final PostgreSQL Runtime Validation Report

## 1. Executive Summary
Phase 3D establishes the empirical baseline for the Bharat Secure Examination Architecture (B-SEA) running against a live PostgreSQL 16.15 database engine. Previous development phases relied on SQLite in-memory or file-based mock execution. Step 6 concludes Phase 3D by validating complete schema migration from a clean database state, deterministic synthetic seeding across 5,001 candidates, full execution of the 21-test security regression suite, single-worker and two-worker concurrent session lifecycle validation, and rigorous measurement of connection pool, rate limiting, and audit trail behavior.

Under tested concurrency scenarios up to 100 simultaneous candidate logins, PostgreSQL 16.15 successfully enforced all domain relational integrity constraints, foreign keys, and the authoritative partial unique index `uix_active_session_candidate_exam`. The candidate session collision defect identified in Step 5 was confirmed resolved in Step 5A, with concurrent login races consistently translating database unique violations into graceful HTTP 409 Conflict responses with 0 unhandled ASGI exceptions and 0 duplicate active sessions.

Two known process-local architectural limitations were confirmed and characterized:
1. Process-local in-memory rate limiting via SlowAPI `MemoryStorage` and module dictionaries isolates counters per worker process.
2. In-memory uncoordinated audit queues (`asyncio.Queue`) produce sequence collisions and hash-chain branching when multiple workers concurrently write to PostgreSQL.

Both limitations are documented as planned architectural hardening items for Phase 4 (Redis distributed rate limiting and durable transactional outbox / centralized audit sequencing).

---

## 2. Environment
The validation environment was verified as a real PostgreSQL 16.15 installation with native Python 3.14 asynchronous drivers:

| Component | Verified Specification |
| :--- | :--- |
| **Database Engine** | PostgreSQL 16.15, compiled by Visual C++ build 1944, 64-bit |
| **Database Host & Port** | `localhost:5432` (Database: `bsea`) |
| **Operating System** | Microsoft Windows 11 Enterprise (Build 26100) |
| **Python Runtime** | Python 3.14.5 |
| **FastAPI Framework** | FastAPI 0.141.1 |
| **ORM / Core** | SQLAlchemy 2.0.52 |
| **PostgreSQL Driver** | asyncpg 0.31.0 |
| **Database Migration Tool** | Alembic 1.13.3 |
| **Database Connection URL** | `postgresql+asyncpg://postgres:***@localhost:5432/bsea` |
| **Connection Pool Implementation** | `AsyncAdaptedQueuePool` |
| **Configured DB_POOL_SIZE** | 10 connections |
| **Configured DB_MAX_OVERFLOW** | 20 connections |
| **Configured DB_POOL_TIMEOUT** | 30 seconds |
| **Configured DB_POOL_RECYCLE** | 1800 seconds (30 minutes) |
| **SQLite Fallback Status** | Intact in code configuration; verified **inactive** during validation |

---

## 3. Migration Validation
Greenfield baseline migration reversibility was verified against a completely wiped PostgreSQL database:
1. **Downgrade Execution**:
   `alembic downgrade base` executed cleanly, dropping all domain tables, indexes, constraints, and custom PostgreSQL ENUM types.
2. **Upgrade Execution**:
   `alembic upgrade head` executed cleanly from revision `base` to `99c8ce339dd4` (`baseline_schema_v1`).
3. **Verified Schema Artifacts**:
   - **Domain Tables (17)**: `organizations`, `users`, `candidates`, `exams`, `centres`, `exam_blueprints`, `exam_forms`, `questions`, `question_reviews`, `answer_keys`, `release_approvals`, `candidate_sessions`, `responses`, `results`, `incidents`, `security_events`, `audit_logs`.
   - **PostgreSQL Native ENUM Types (10)**: `auditresult`, `centrestatus`, `examstatus`, `formstatus`, `incidentseverity`, `incidentstatus`, `questionstatus`, `securitymode`, `sessionstatus`, `userroleenum`.
   - **Partial Unique Index**: `uix_active_session_candidate_exam` verified:
     ```sql
     CREATE UNIQUE INDEX uix_active_session_candidate_exam 
     ON public.candidate_sessions USING btree (candidate_id, exam_id) 
     WHERE (status = 'ACTIVE'::sessionstatus);
     ```
   - **Timestamp with Time Zone**: 31 columns verified using `TIMESTAMP WITH TIME ZONE`.
   - **JSON / JSONB Columns**: 7 columns verified using `JSONB` / `JSON`.
   - **Migration Errors**: 0 errors.

---

## 4. Seed / Data Integrity
The deterministic synthetic seeding script (`backend/app/scripts/seed_demo.py`) was executed against the migrated PostgreSQL database:

| Domain Entity | Seed Count | Integrity & Constraint Verification |
| :--- | :--- | :--- |
| **Organizations** | 1 | Code `BSEA-DEMO`, unique short name verified |
| **Administrative & Staff Users** | 13 | All 11 `UserRoleEnum` roles represented |
| **Candidate User Accounts** | 5,001 | 100% 1-to-1 foreign key linkage to candidate profiles |
| **Candidates** | 5,001 | Registration numbers `BSEA-2026-DEMO-001` + `BSEA-TEST-000001`..`005000` |
| **Exams** | 1 | *"B-SEA Global Security Certification 2026"*, status `RELEASED` |
| **Exam Blueprints** | 1 | JSONB blueprint configuration with SHA-256 integrity hash |
| **Centres** | 1 | Centre code `ND-CBT-001`, active capacity 500 |
| **Exam Forms** | 4 | Forms `A`, `B`, `C`, `D` with randomized question permutations |
| **Questions** | 8 | AES-256-GCM encrypted ciphertext payloads with integrity hashes |
| **Answer Keys** | 8 | Encrypted answer payloads isolated from question delivery endpoints |
| **Release Approvals** | 3 | Quorum threshold met (3 distinct `RELEASE_AUTHORITY` signatures) |
| **Security Events** | 5 | Baseline synthetic security event records |
| **Candidate Sessions** | 0 | Fresh baseline; 0 pre-existing sessions |
| **Orphaned Records** | 0 | 0 orphaned users, 0 orphaned candidates, 0 foreign-key mismatches |
| **Database Storage Footprint** | ~14 MB | Initial seed on PostgreSQL 16.15 disk storage |

---

## 5. Security Regression Results
The complete security attack regression suite (`backend/tests/security/test_attacks.py`) was executed against live PostgreSQL 16.15:

- **Total Security Tests**: 21
- **Passed**: 21 (100.0%)
- **Skipped**: 0
- **Failed**: 0
- **Errors**: 0

### Attack Scenarios Validated
1. `test_candidate_cannot_access_admin_api`: Candidates blocked with HTTP 403 on administrative endpoints.
2. `test_candidate_cannot_access_questions_direct`: Direct question retrieval without active session blocked with HTTP 401/403.
3. `test_setter_cannot_access_audit_logs`: Question setters blocked with HTTP 403 on auditor endpoints.
4. `test_setter_cannot_approve_questions`: Question setters cannot self-approve questions (separation of duties).
5. `test_setter_cannot_access_others_questions`: Multi-tenant / tenant-author isolation verified.
6. `test_candidate_cannot_access_others_session`: Session token impersonation blocked with HTTP 401.
7. `test_bulk_extraction_rate_limit`: Rapid question scraping triggers HTTP 429 rate limiting.
8. `test_candidate_question_delivery_hides_answer_key`: Question delivery payloads verified to contain 0 plaintext answer key data.
9. `test_early_exam_release_blocked`: Unreleased exam question delivery blocked with HTTP 403.
10. `test_single_admin_cannot_release`: 1 approval on a 3-approval threshold exam fails to transition status to `RELEASED`.
11. `test_tampered_question_detected`: Ciphertext tampering detected via SHA-256 integrity hash verification failure.
12. `test_audit_chain_verification`: Audit log chain verification endpoint confirms unbroken SHA-256 hash progression.
13. `test_invalid_session_token_rejected`: Cryptographically invalid session tokens rejected with HTTP 401.
14. `test_cbt_security_event_reporting`: Security event telemetry endpoint accepts and persists client violation telemetry.
15. `test_centre_isolation`: Test centre isolation logic verified.
16. `test_candidate_cannot_access_other_forms`: Cross-form question leakage blocked.
17. `test_admin_cannot_see_plaintext_questions`: Administrators cannot read question ciphertext without setter/key permissions.
18. `test_api_does_not_leak_secrets`: Server error responses verified to contain 0 stack traces or database credential leaks.
19. `test_api_requires_auth_for_protected_routes`: Unauthenticated requests to protected routes rejected with HTTP 401.
20. `test_candidate_login_identity_rate_limit`: Candidate identity login rate limiting enforces 5 attempts/minute limit.
21. `test_admin_login_identity_rate_limit`: Administrative login rate limiting enforces identity-based brute force protection.

---

## 6. PostgreSQL Concurrency Results
PostgreSQL concurrency correctness was evaluated using both thread-pool execution and asynchronous gather execution against live PostgreSQL:

| Test Scenario | Concurrency | HTTP Status Breakdown | DB Errors | Duplicate Sessions | Unhandled 500s | Result |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Concurrent Duplicate Approvals** | 10 | 1× 200 OK, 9× 400 Bad Request | 0 | N/A | 0 | **PASSED** |
| **Threshold Bypass Prevention** | 10 | 1× 200 OK, 9× 400 Bad Request | 0 | N/A | 0 | **PASSED** |
| **Concurrent Session Creation** | 15 | 0× 200 OK, 5× 409 Conflict, 10× 429 RateLimit | 0 | 0 | 0 | **PASSED** |
| **Step 5A Session Race Regression** | 8 | 1× 200 OK, 4× 409 Conflict, 3× 429 RateLimit | 0 | 0 | 0 | **PASSED** |
| **Concurrent Audit Events (Single Worker)** | 20 | 20× 200 OK | 0 | N/A | 0 | **PASSED** (40/40 valid) |

---

## 7. Multi-Worker Results
FastAPI was launched using Uvicorn with exactly 2 worker processes (`--workers 2`, PIDs `5648` and `7032` under parent PID `18448`):

| Concurrency Level | HTTP 200 OK | HTTP 4xx | HTTP 5xx | Elapsed Time | Throughput | Latency (P50) | Latency (P95) | Latency (Max) | DB Connections |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **10 Concurrent Users** | 10 (100%) | 0 | 0 | 0.641 s | 15.60 req/s | 586.13 ms | 595.32 ms | 595.87 ms | 3 $\rightarrow$ 13 |
| **50 Concurrent Users** | 50 (100%) | 0 | 0 | 2.143 s | 23.33 req/s | 1,748.83 ms | 2,125.53 ms | 2,134.36 ms | 13 $\rightarrow$ 21 |
| **100 Concurrent Users**| 100 (100%)| 0 | 0 | 3.790 s | 26.39 req/s | 2,572.36 ms | 3,695.78 ms | 3,735.90 ms | 21 $\rightarrow$ 21 |

- **Worker Restarts / Crashes**: 0
- **PostgreSQL Locking Errors**: 0
- **Total Concurrent Logins Processed**: 160 successful logins across batches
- **Peak Database Connections**: 21 (comfortably within configured pool boundaries)

---

## 8. Rate Limiting Results
Rate limiter behavior was evaluated across single-worker and multi-worker execution:

1. **Persistent Connection (Single Worker Bucket)**:
   Sequential candidate login requests over a persistent HTTP keepalive connection yielded:
   `[200, 409, 409, 409, 409, 429, 429, 429, 429, 429]`
   - Processed: Exactly 5 attempts (1 successful login + 4 active session collision rejections).
   - Rate-Limited: All subsequent attempts rejected with `HTTP 429 Too Many Requests`.
2. **Distributed Concurrent Requests (Multi-Worker Execution)**:
   Concurrent candidate login requests dispatched across independent TCP connections yielded:
   `[409, 409, 409, 409, 200, 409, 409, 429, 429, 409, 409, 409]`
   - Processed: 10 attempts processed before global saturation (5 attempts per worker process).
   - Rate-Limited: Requests exceeding individual worker buckets rejected with `HTTP 429`.
   - **Architectural Observation**: Confirmed process-local limitation of in-memory SlowAPI and local dictionaries. Global rate limiting requires a shared cache (Redis).
   - **Zero 500 Errors**: All competing collision attempts returned HTTP 409 Conflict without unhandled exceptions.

---

## 9. Session Uniqueness Results
Direct SQL verification was executed after multi-worker concurrency tests:
```sql
SELECT candidate_id, exam_id, COUNT(*)
FROM candidate_sessions
WHERE status = 'ACTIVE'
GROUP BY candidate_id, exam_id
HAVING COUNT(*) > 1;
```
- **Duplicate ACTIVE Sessions**: **0 rows**
- **Orphaned Sessions (`candidate_sessions` without valid candidate)**: **0 rows**
- **Enforcement Mechanism**: The PostgreSQL partial unique index `uix_active_session_candidate_exam` authoritatively prevented duplicate active session creation under concurrent multi-worker load.
- **Application Error Translation**: Step 5A fix in `candidates.py` ensured that simultaneous insertion collisions trigger clean transaction rollbacks and HTTP 409 Conflict responses.

---

## 10. Threshold Approval Results
Quorum release approval mechanics were verified:
1. **Single Approval Insufficiency**: An exam with `required_approvals = 3` cannot be released by 1 or 2 approvals; status remains `THRESHOLD_PENDING`.
2. **Duplicate Prevention**: Re-submitting an approval from the same release authority is rejected with HTTP 400 (`Authority has already approved this release`), enforced by unique constraint `uq_exam_authority_approval`.
3. **Concurrent Quorum Enforcement**: Row-level locking (`SELECT ... FOR UPDATE`) prevents concurrent duplicate submissions from incrementing the approval count.
4. **Authorized State Transition**: Status transitions to `RELEASED` if and only if 3 distinct authorized release authority signatures are recorded.

---

## 11. Question / Answer-Key Security
API-level security controls governing question delivery and answer key isolation were validated:
1. **Answer Key Protection**: Answer keys are stored in a dedicated `answer_keys` table and are never serialized or referenced by `/api/v1/candidate/*` endpoints.
2. **Ciphertext Delivery**: Question content is stored encrypted with exam-specific master keys and decrypted only during active candidate session windows.
3. **Payload Integrity**: Question payloads include SHA-256 HMAC integrity hashes. Modifying a single byte of ciphertext triggers integrity verification failure and rejects delivery.
4. **Pre-Release Containment**: Candidates attempting to access questions before formal exam release receive HTTP 403 Forbidden.

---

## 12. Audit Validation
Tamper-evident audit logging was evaluated under single-worker and multi-worker modes:
1. **Single-Worker Execution**:
   - Sequential audit logging through the local `asyncio.Queue` maintained linear sequence progression (`seq = 1, 2, 3...`) and unbroken SHA-256 hash chains (`prev_hash` $\rightarrow$ `event_hash`).
   - `GET /api/v1/audit/verify` verified 40/40 entries intact (`valid: true`).
2. **Multi-Worker Execution (Known Architectural Limitation)**:
   - When 2 workers processed audit events concurrently, independent `audit_worker` tasks read `MAX(seq)` without cross-process serialization.
   - Resulted in duplicate sequence numbers (e.g. sequences `165, 212, 214`) and 4 hash-chain breaks.
   - `GET /api/v1/audit/verify` accurately identified the first discontinuity at seq 165 (`valid: false, message: "CHAIN INTEGRITY VIOLATION DETECTED"`).
   - This empirically confirms that an in-memory queue cannot maintain linear tamper-evidence across multiple application workers without centralized sequencing.

---

## 13. Connection Pool Validation
PostgreSQL connection pool behavior was monitored during 10, 50, and 100 concurrent candidate login benchmarks:
- **Baseline Idle Connections**: 3 connections
- **Peak Active Connections**: 21 connections
- **Connection Saturation**: Stayed well within the configured bounds (`DB_POOL_SIZE = 10`, `DB_MAX_OVERFLOW = 20` per worker process = 60 max combined connections).
- **Timeouts / Deadlocks**: 0 connection pool timeouts, 0 PostgreSQL connection deadlocks, 0 dropped backend connections.
- **Health Checks**: `pool_pre_ping = True` successfully ensured stale connections were recycled.

---

## 14. Known Architectural Limitations
Validation confirmed two structural limitations inherent to the current single-node, in-memory reference implementation:

1. **Process-Local Rate Limiting**:
   - SlowAPI `MemoryStorage` and `_identity_login_attempts` operate inside worker process memory.
   - Quotas are enforced independently per worker rather than globally across the cluster.
2. **Process-Local Audit Queue**:
   - `_audit_queue = asyncio.Queue()` exists per worker process.
   - Reading `MAX(seq)` and `last_hash` from PostgreSQL without distributed locking allows concurrent workers to create identical sequence numbers and branched hash chains.
3. **CPU-Bound Argon2 Password Hashing**:
   - Argon2id password verification contributes >90% of login latency under high concurrency, capping single-node throughput to ~28 logins/second on a 2-worker configuration.

---

## 15. Production Gaps
The following architectural controls are required before enterprise production deployment:

1. **Distributed Rate Limiting (Redis)**: Replace SlowAPI `MemoryStorage` with a Redis-backed distributed sliding-window counter.
2. **Durable Transactional Audit Pipeline**: Replace `asyncio.Queue` with a Transactional Outbox pattern, Kafka event stream, or database-level sequence with row-level locking to ensure monotonic, unbroken hash-chain progression across arbitrary worker instances.
3. **Connection Pooling Middleware (PgBouncer)**: Deploy PgBouncer in transaction pooling mode in front of PostgreSQL to scale to thousands of concurrent CBT terminals.
4. **Hardware Security Module (HSM) / Cloud KMS**: Replace `MockKMS` prototype cryptographic keys with production Cloud KMS / PKCS#11 HSM integration.
5. **Database Row-Level Security (RLS)**: Enforce PostgreSQL tenant and centre isolation at the database engine level.

---

## 16. Final Phase 3D Status
- **PostgreSQL 16.15 Runtime**: **VERIFIED**
- **Greenfield Alembic Migrations**: **VERIFIED**
- **Domain Integrity & Deterministic Seeding**: **VERIFIED**
- **Security Attack Regression Suite**: **21/21 PASSED**
- **Concurrency & Race Condition Handling**: **VERIFIED**
- **Multi-Worker Execution (2 Workers)**: **VERIFIED**
- **Candidate Session Uniqueness**: **100% ENFORCED (0 Duplicates)**
- **Final Verdict**: **PASS WITH LIMITATIONS** (due to documented process-local rate limiting and audit queue limitations reserved for Phase 4 hardening).
