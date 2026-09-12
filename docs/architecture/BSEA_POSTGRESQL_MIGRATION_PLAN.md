# B-SEA PostgreSQL Migration Plan

## 1. Executive Summary
The B-SEA Reference Implementation relies on `SQLite` (`aiosqlite`) for rapid prototyping. However, as demonstrated in the Phase 3A Load Testing, SQLite suffers from severe locking under concurrent `INSERT` operations (returning 500 `database is locked` errors at just 50 concurrent logins). To support high-scale examination traffic, B-SEA must migrate to a High Availability (HA) PostgreSQL cluster. 

This document defines the constraints, isolation levels, and migration strategy required to swap out SQLite for PostgreSQL while preserving all security properties and threshold authorization semantics from Phase 2.

## 2. Driver & Framework
- **ORM Framework:** SQLAlchemy 2.0 (Async)
- **Database Driver:** `asyncpg`
- **Migration Tool:** Alembic
- **Connection URI Format:** `postgresql+asyncpg://user:pass@host:5432/bsea_prod`

## 3. Schema & Constraint Mapping
The B-SEA schema maps exceptionally well to PostgreSQL, leveraging SQLAlchemy's dialect-agnostic modeling.

### Identifiers & Foreign Keys
- UUIDs are natively supported via `UUID(as_uuid=True)`.
- Foreign Keys and Cascades will be strictly enforced at the database level.

### Constraints
- `UNIQUE` constraints (e.g., `Candidate.registration_number` + `exam_id`) map directly.
- `CHECK` constraints (e.g., `Exam.total_approvals >= Exam.required_approvals`) should be materialized in PostgreSQL to act as a secondary defense-in-depth against application bugs overriding threshold logic.

### Indexes
Performance-critical indexes to be defined:
- `CREATE INDEX idx_candidate_session ON candidate_sessions (session_token, status);`
- `CREATE INDEX idx_audit_resource ON audit_logs (resource_id, event_type);`
- `CREATE INDEX idx_question_exam ON questions (exam_id, is_active);`

## 4. Concurrency & Transaction Boundaries

### The Threshold Release Logic
The most sensitive concurrency invariant in B-SEA is the threshold approval logic (`ReleaseAuthority`).
- **Invariant:** An exam MUST NOT transition to `RELEASED` until `total_approvals >= required_approvals`.
- **PostgreSQL Isolation Level:** `REPEATABLE READ`. 
  - `SERIALIZABLE` is overly restrictive for the entire database.
  - Using `SELECT ... FOR UPDATE` (Row-Level Locking) during the approval increment effectively prevents dual-submission race conditions without requiring global serializability.
  - In SQLAlchemy: `db.execute(select(Exam).where(...).with_for_update())`

### Connection Pooling
- **Engine configuration:**
  - `pool_size`: 50
  - `max_overflow`: 100
  - `pool_timeout`: 30
- **External Pooling:** PgBouncer (Transaction mode) must be deployed in front of PostgreSQL to handle thousands of candidate connections without exhausting database memory.

## 5. Audit Architecture Implications
With PostgreSQL, the `asyncio.Queue` worker prototype will be replaced by a durable message broker (e.g., Apache Kafka or Redis Streams).
- **Flow:** API -> Kafka Topic -> Audit Worker -> PostgreSQL `audit_logs` table.
- **Sequencing:** Kafka guarantees exact-order delivery per partition. A single partition for audit logs ensures that `prev_hash` is computed sequentially by exactly one consumer group worker before committing to PostgreSQL.

## 6. Migration Steps
1. **Initialize Alembic:** Generate the initial baseline migration script (`alembic revision --autogenerate`).
2. **Review Migrations:** Manually inspect the generated script to ensure `UUID` and `JSON` types map to native PostgreSQL `UUID` and `JSONB`.
3. **Environment Swap:** Update `BSEA_DATABASE_URL` in CI pipelines.
4. **Integration Testing:** Rerun the entire `test_attacks.py` suite against PostgreSQL to ensure authorization boundaries are preserved.
5. **Load Testing:** Re-execute the Phase 3A benchmark in Mode 2 against PostgreSQL to verify that `database is locked` errors are eliminated and throughput scales horizontally.
