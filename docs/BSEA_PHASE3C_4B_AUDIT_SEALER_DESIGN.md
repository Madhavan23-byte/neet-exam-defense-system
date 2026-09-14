# B-SEA Phase 3C-4B: Audit Sealer & Canonical Incorporation Ordering Architecture Design (Rev-04 — Final Design)

**Status:** DESIGN FINALIZATION ONLY — IMPLEMENTATION NOT YET AUTHORIZED  
**Author:** Google DeepMind / B-SEA Engineering Team  
**Date:** September 2026  
**System:** Bharat Secure Examination Architecture (B-SEA)  
**Security Classification:** Highly Confidential / National Critical Infrastructure  
**Baseline Git Checkpoint:** `dae8631c5ccc14d7e2e85ab4c8ecbf543a7c9506` (Phase 3C-4A Database Foundation)  

---

## Revision Changelog

| Revision | Date | Summary of Changes |
| :--- | :--- | :--- |
| **Rev-01** | Sept 2026 | Initial Phase 3C-4B sealer design. Established 3-table decoupled append-only architecture, single-leader advisory lock, and 72-byte binary chain hash formula. |
| **Rev-02** | Sept 2026 | Addressed epoch contiguity schema reality, deterministic epoch identity derivation, dual-mode audit ingestion (business-atomic vs. security-isolated), and corrected RFC 8785 terminology. |
| **Rev-03** | Sept 2026 | Resolved epoch size vs. age contradiction by introducing partial epochs. Defined historical backfill mapping for 5,982 rows into Epochs 1..6. Clarified deterministic Ed25519 re-signing. |
| **Rev-04 (Final)**| Sept 2026 | **Hardened Specifications:**<br>1. **Precise `MAX_EPOCH_AGE`:** Defined age strictly from `created_at` of oldest unsealed event.<br>2. **Historical Event Hash Semantics:** Preserved legacy event hashes without recomputation; verifier dual-path.<br>3. **RFC 6962 Domain-Separated Merkle Tree:** Explicit `0x00` leaf and `0x01` parent node binary hashing.<br>4. **Canonical Epoch Manifest:** Fixed 9 schema fields; excluded retry timestamps; required exact KMS key ARN.<br>5. **Exact `prev_seal_hash`:** Defined strictly as $\text{SHA256}(\text{manifest\_bytes})$ excluding signature.<br>6. **KMS Retry & Advisory Lock Guard:** Disclaimed KMS-level idempotency; proved deterministic Ed25519 recovery under advisory lock.<br>7. **Exact Claim Boundaries:** Formalized defensible durability claims and DBA trust boundary.<br>8. **Implementation Gate:** Completed 18-point verification checklist. |

---

## 1. Executive Summary

### 1.1 Problem Statement
In high-stakes national examinations administered under the Bharat Secure Examination Architecture (B-SEA), audit trail integrity is paramount. An audit record must prove conclusively—to candidates, examination authorities, forensic auditors, and judicial review—that an event occurred exactly as recorded, was not modified, was not deleted, and has an indisputable, immutable position in the global security event sequence.

Previous prototype implementations suffered from three architectural limitations:
1. **Coupled Sequencing:** The legacy worker attempted to assign sequential identifiers (`seq`) and chain hashes (`prev_hash`) directly within raw event records (`audit_logs`), which conflicted with database immutability triggers.
2. **Commit vs. Insertion Ordering Fallacy:** Relying on insertion timestamps (`created_at`) or PostgreSQL sequence numbers to infer commit ordering is provably broken under concurrent, multi-transaction workloads.
3. **Multi-Worker Vulnerability:** The prototype relied on an in-memory Python `asyncio.Queue` and process-local sequencing, which fails under multi-process application servers (e.g., Gunicorn with multiple Uvicorn workers) and causes permanent audit loss on ungraceful worker termination.

### 1.2 Phase 3C-4B Mission & Scope
Phase 3C-4B establishes the final architectural design for the **AuditSealer**: a resilient, distributed, single-leader background daemon that consumes committed, immutable raw audit logs (`audit_logs`) and incorporates them into a canonical, strictly contiguous cryptographic chain (`audit_chain_links`), and periodically establishes signed checkpoints (`audit_epoch_seals`).

```
+-----------------------------------------------------------------------------------+
|                                 STRICT BOUNDARY                                   |
|                                                                                   |
|  THIS DOCUMENT REPRESENTS A FINAL ARCHITECTURAL DESIGN SPECIFICATION ONLY.        |
|  - DO NOT modify Python application code.                                         |
|  - DO NOT execute database schema migrations.                                     |
|  - DO NOT create or modify automated test suites.                                 |
|  - DO NOT create Git commits or execute Git pushes.                               |
|  - DO NOT implement the Phase 3C-4B codebase until explicitly authorized.         |
+-----------------------------------------------------------------------------------+
```

### 1.3 Core Architectural Principle: Sealer-Assigned Canonical Incorporation Order
The authoritative cryptographic sequence of the B-SEA audit subsystem is:
$$\mathbf{Sealer\text{-}Assigned\ Canonical\ Incorporation\ Order}\quad (\texttt{audit\_chain\_links.chain\_seq})$$

This ordering is **NOT**:
- Database commit ordering (which is invisible, microsecond-indistinguishable, and unqueryable without custom PostgreSQL engine extensions).
- Transaction start ordering (`txid` allocation order).
- Timestamp ordering (`created_at` or `timestamp`).
- UUID ordering (UUIDv4/UUIDv7 primary keys).

The audit chain represents the precise order in which the designated **AuditSealer** leader incorporates durably committed events into the append-only ledger.

### 1.4 Fundamental Ordering Hierarchy
To eliminate any ambiguity across the engineering and auditing teams, B-SEA explicitly distinguishes the following distinct orderings:

$$\mathbf{Candidate\ Selection\ Order} \ne \mathbf{Database\ Commit\ Order} \ne \mathbf{Canonical\ Audit\ Order}$$

1. **Candidate Selection Order (`ORDER BY created_at ASC, id ASC`):** A deterministic, query-level tie-breaker among currently visible, unsealed committed events. `created_at` is statement execution time, **NOT** commit time. `id` is a synthetic tie-breaker, **NOT** commit time.
2. **Database Commit Order:** The exact chronological point at which PostgreSQL flushes WAL records on `COMMIT`. This order is non-queryable in application SQL and cannot guarantee gapless sequence numbers across concurrent transactions.
3. **Canonical Audit Order (`chain_seq = 1, 2, 3...`):** The immutable, gapless cryptographic sequence assigned by the distributed AuditSealer leader upon incorporating committed events into `audit_chain_links`. **Only successful sealer incorporation establishes authoritative audit sequence.**

### 1.5 Canonical Serialization Standard
All canonical payload serializations within B-SEA are formally specified as:
> **"Deterministic key-sorted compact JSON serialization following RFC 8785 principles using Python's standard `json` implementation."**

B-SEA makes no claim of a "full standards-certified RFC 8785 engine." Determinism is achieved by sorting dictionary keys at all hierarchy levels, eliminating non-essential whitespace separators (`separators=(',', ':')`), ensuring UTF-8 encoding without ASCII escaping (`ensure_ascii=False`), and enforcing standardized UTC ISO 8601 timestamps.

### 1.6 Exact Claim Boundaries
B-SEA maintains strictly defensible claims regarding audit durability and security:
> **Approved Claim:**  
> *"Every audit event that successfully commits to `audit_logs` is eventually incorporated exactly once into the immutable canonical audit chain, assuming the sealer remains operational and the database remains available."*

**Explicit Non-Claims:**
- B-SEA does **NOT** claim that physical database commit order is proven.
- B-SEA does **NOT** claim absolute immutability against privileged PostgreSQL superusers (`postgres` with root OS access).
- B-SEA does **NOT** claim zero audit loss under total infrastructure destruction without multi-region backups.
- B-SEA does **NOT** claim "zero vulnerabilities" or "production certification" prior to full Phase 3C-4C observability and independent external audits.

---

## 2. Existing State & Repository Inspection

A comprehensive inspection of the B-SEA repository was conducted across models, services, migrations, API endpoints, background tasks, and deployment configurations:

### 2.1 Component Inventory & Current Role

| Component | File Path | Current Status & Role | Deprecation / Adaptation Strategy |
| :--- | :--- | :--- | :--- |
| **`AuditLog` Model** | `backend/app/core/models.py` | Stores raw audit events. In Phase 3C-4A, `seq` and `prev_hash` were converted to `nullable=True`. Immutability trigger is active. | **Retained.** Serves as the immutable raw event store. Ingestion endpoints write directly here, setting `seq=NULL`, `prev_hash=NULL`, and canonical `event_hash`. |
| **`AuditChainLink` Model** | `backend/app/core/models.py` | Schema created in Phase 3C-4A. `chain_seq` (UNIQUE), `audit_log_id` (UNIQUE FK), `chain_hash`. Immutability trigger active. | **Retained / Target.** Currently has ZERO writers. The Phase 3C-4B AuditSealer will be the sole writer. |
| **`AuditEpochSeal` Model** | `backend/app/core/models.py` | Schema created in Phase 3C-4A. Range constraints, `end_chain_seq` (UNIQUE), `epoch_root_hash`. Immutability trigger active. | **Retained / Target.** Currently has ZERO writers. The Phase 3C-4B Epoch Sealer will be the sole writer. |
| **`canonical.py`** | `backend/app/modules/audit/canonical.py` | Implements deterministic key-sorted compact JSON serialization following RFC 8785 principles using Python's standard `json` implementation (`compute_event_hash`). | **Retained.** Authoritative module for computing raw `audit_logs.event_hash`. Extended in 3C-4B to support canonical chain hash preimages and Merkle tree hashing. |
| **`AuditService`** | `backend/app/modules/audit/service.py` | API-facing service. Currently pushes event dicts to in-memory `_audit_queue`. | **To Be Replaced.** Refactored to support dual-mode durable writing: business-atomic writes (Mode A) and independent security failure writes (Mode B). |
| **`audit_worker`** | `backend/app/modules/audit/service.py` | Prototype background task. Reads `_audit_queue`, runs `SELECT MAX(seq)`, inserts legacy fields. | **To Be Deprecated.** Replaced entirely by the distributed, leader-elected `AuditSealer`. |
| **`_audit_queue`** | `backend/app/modules/audit/service.py` | In-memory `asyncio.Queue(maxsize=10000)`. | **To Be Eliminated.** Completely removed from canonical audit ingestion. No security-critical event will depend on in-process memory. |
| **`compute_audit_hash`** | `backend/app/crypto/kms_interface.py` | Legacy formula: `SHA-256(event_data + prev_hash)` using string concatenation. | **To Be Deprecated.** Replaced with canonical fixed-width 72-byte binary preimage formula. |
| **Audit Verification** | `backend/app/api/v1/audit.py` (`/verify`) | Verifies legacy chain sequentially using `AuditLog.seq`. | **To Be Adapted.** Refactored to verify `audit_chain_links` and `audit_epoch_seals` with dual-path support for historical rows. |
| **Application Lifespan**| `backend/app/main.py` | Spawns `audit_worker()` in `asyncio.create_task()`. | **To Be Adapted.** Will spawn the `AuditSealer` background task. |
| **Process Model** | `backend/Dockerfile` | Gunicorn with Uvicorn workers: `exec gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker`. | **Analyzed.** Demonstrates that 4 independent Python processes run simultaneously. |

### 2.2 Historical Event Hash Semantics
The repository currently contains 5,982 historical rows in `audit_logs` created during prototype testing.
- **Legacy Invariant:** Existing historical `audit_logs.event_hash` values are permanently immutable. They were generated using prototype JSON serialization and concatenation, and **cannot** be reproduced by the new `canonical.py` algorithm.
- **No Overwrite Policy:** Historical `event_hash` values will **NOT** be recomputed or overwritten.
- **Backfill Integration:** During historical backfill, the sealer incorporates these rows into `audit_chain_links` by binding `previous_chain_hash`, the **preserved legacy `event_hash`**, and `chain_seq` using the new Phase 3C-4B 72-byte chain hash primitive.
- **Dual-Path Verification:** The audit verifier will explicitly distinguish:
  1. **Historical Records ($1 \le \text{chain\_seq} \le 5982$):** Verifies canonical chain hash contiguity in `audit_chain_links` using the preserved legacy `audit_logs.event_hash`.
  2. **Live Records ($\text{chain\_seq} \ge 5983$):** Verifies both full RFC 8785-principle canonical event hashing from `audit_logs` raw payload **AND** canonical chain hash contiguity in `audit_chain_links`.

---

## 3. Approved Architecture: Three-Tier Append-Only Data Model

```
+---------------------------------------------------------------------------------------------------+
| 1. RAW AUDIT EVENT STORE: audit_logs (Application Tier)                                           |
|    - Appended directly by business endpoints or security interceptors.                            |
|    - Immutable at insertion; PostgreSQL BEFORE UPDATE OR DELETE trigger raises EXCEPTION.         |
|    - event_hash computed deterministically via key-sorted compact JSON following RFC 8785 rules.  |
|    - Unordered with respect to global sequence; sequence fields (seq, prev_hash) are NULL.       |
+---------------------------------------------------------------------------------------------------+
                                                  |
                                                  | Committed audit rows visible via MVCC
                                                  v
+---------------------------------------------------------------------------------------------------+
| 2. CANONICAL AUDIT CHAIN: audit_chain_links (AuditSealer Leader)                                  |
|    - Single logical leader elected via PostgreSQL session-scoped advisory lock.                   |
|    - Assigns strictly contiguous, monotonic chain_seq (1, 2, 3, 4...).                            |
|    - Cryptographic chain_hash binds prev_chain_hash, event_hash, and chain_seq (72-byte preimage).|
|    - 1:1 foreign key to audit_logs.id; enforced by UNIQUE constraint.                             |
|    - Immutable; PostgreSQL BEFORE UPDATE OR DELETE trigger raises EXCEPTION.                      |
+---------------------------------------------------------------------------------------------------+
                                                  |
                                                  | Fixed range [start_seq, end_seq]
                                                  v
+---------------------------------------------------------------------------------------------------+
| 3. SIGNED EPOCH SEALS: audit_epoch_seals (Epoch Sealer & AWS KMS)                                 |
|    - Aggregates contiguous, frozen chain link ranges [start_chain_seq, end_chain_seq].            |
|    - Computes Merkle root / epoch_root_hash using RFC 6962 domain separation (0x00 / 0x01).       |
|    - Signs canonical epoch manifest using AWS KMS Ed25519 (OUTSIDE database transaction).         |
|    - Persists signature, exact KMS key ARN, and sequence bounds into audit_epoch_seals.           |
|    - Immutable; PostgreSQL BEFORE UPDATE OR DELETE trigger raises EXCEPTION.                      |
+---------------------------------------------------------------------------------------------------+
```

---

## 4. Audit Ingestion Transaction Semantics: Dual-Mode Architecture

The naive assumption that all audit events must be committed inside the caller's business transaction is dangerous. In security operations, business failures and authorization rejections must be durably recorded even when the underlying business action is rolled back.

B-SEA defines two strictly separated ingestion modes:

```
MODE A: Business-Atomic Audit Events                   MODE B: Security-Critical / Denial Events
(e.g., Exam submission, Standard workflow)            (e.g., Auth failure, Forbidden attempt, Policy breach)

        Business Transaction                                      Dedicated Audit Transaction
        +----------------------------+                            +----------------------------+
        | BEGIN                      |                            | BEGIN                      |
        |   INSERT exam_submissions  |                            |   INSERT audit_logs        |
        |   INSERT audit_logs        |                            |   (SUCCESS/FAILURE/BLOCKED)|
        | COMMIT                     |                            | COMMIT                     |
        +----------------------------+                            +----------------------------+
                 |                                                              |
    Rollback erases BOTH data and audit.                           Rollback of business request
    (Accurate: action never occurred)                              CANNOT erase security record!
```

### 4.1 Mode A: Business-Atomic Audit Events
- **Context:** Standard state transitions where the audit log asserts that a business action succeeded (e.g., candidate answered question, supervisor authorized candidate workstation).
- **Semantics:** If the business operation fails or rolls back, the business effect did not happen; therefore, the audit record asserting that the action succeeded must also roll back atomically.
- **Execution:** The caller passes its active `AsyncSession` to `AuditService.log(..., session=db)`. The `audit_logs` record is inserted within the caller's active database transaction.

### 4.2 Mode B: Security-Critical & Denial Events
- **Context:** Security-relevant occurrences, authentication failures, authorization denials, rate limit triggers, suspicious IP activity, break-glass rejections, or unexpected exceptions.
- **Semantics:** **A security event accepted for durable auditing must NEVER disappear merely because the business operation rolls back or aborts with an HTTP error.**
- **Execution:** The application calls `AuditService.log_security_event(...)`. This method:
  1. Opens an **independent, isolated database session** via `AsyncSessionLocal()`.
  2. Inserts the `audit_logs` record (`result='FAILURE' | 'BLOCKED'`, canonical `event_hash`).
  3. Executes an immediate, explicit `await audit_session.commit()`.
  4. Closes the isolated session before the API endpoint raises its `HTTPException(401/403/429)` or rolls back the business transaction.
  5. Completely bypasses in-memory queues, ensuring immediate PostgreSQL WAL durability.

### 4.3 Universal Invariant
Whether an event is committed via Mode A or Mode B, once its transaction has issued a durable `COMMIT`, it becomes visible to PostgreSQL MVCC and satisfies the fundamental system invariant:
> **"Every successfully committed `audit_logs` event is eventually incorporated into the canonical hash chain."**

---

## 5. Candidate Selection Model

### 5.1 Deterministic Candidate Query
The AuditSealer discovers committed, unsealed audit events using a deterministic anti-join query:

```sql
SELECT 
    al.id, 
    al.event_hash, 
    al.created_at
FROM audit_logs al
WHERE NOT EXISTS (
    SELECT 1 
    FROM audit_chain_links acl 
    WHERE acl.audit_log_id = al.id
)
ORDER BY 
    al.created_at ASC, 
    al.id ASC
LIMIT :batch_size;
```

### 5.2 Criteria for Eligibility
An event is eligible for incorporation if and only if:
1. **Committed State:** The transaction that inserted the `audit_logs` row has issued a durable `COMMIT`. Under PostgreSQL Multi-Version Concurrency Control (MVCC) with default `READ COMMITTED` or `REPEATABLE READ` isolation, uncommitted transactions are strictly invisible to the sealer.
2. **Unlinked State:** The event `id` does not exist in `audit_chain_links.audit_log_id`.
3. **Deterministic Tie-Breaking:** If multiple events have identical `created_at` timestamps (common under high-throughput concurrent workloads), the tie is deterministically broken by `al.id ASC` (lexicographical UUID comparison).

> [!IMPORTANT]
> `al.created_at ASC, al.id ASC` is used strictly as a **deterministic candidate-selection tie-breaker** among currently visible unsealed rows. It is **NOT** a guarantee or proof of commit ordering. The canonical order is established only when `chain_seq` is assigned by the sealer.

### 5.3 Handling Long-Running and In-Flight Transactions
Consider two transactions, $T_A$ and $T_B$:
- $T_A$ begins at 10:00:00, inserts event $E_A$ (`created_at = 10:00:00`), and executes a slow query for 15 seconds.
- $T_B$ begins at 10:00:02, inserts event $E_B$ (`created_at = 10:00:02`), and commits immediately at 10:00:03.

**Sealer Behavior:**
1. **At 10:00:04 (Sealer Cycle 1):**
   - $E_A$ is uncommitted $\rightarrow$ MVCC hides $E_A$ completely from the sealer query.
   - $E_B$ is committed and unlinked $\rightarrow$ Sealer selects $E_B$, assigns `chain_seq = 100`, and commits.
2. **At 10:00:15:**
   - $T_A$ commits $E_A$.
3. **At 10:00:16 (Sealer Cycle 2):**
   - $E_B$ already exists in `audit_chain_links` $\rightarrow$ filtered out by `NOT EXISTS`.
   - $E_A$ is now committed and unlinked $\rightarrow$ Sealer selects $E_A$, assigns `chain_seq = 101`, and commits.

**Mathematical Proof of Correctness:**
- Neither event is lost.
- Sequence contiguity is preserved ($100 \rightarrow 101$).
- No gaps are created.
- In-flight transactions cannot stall the sealer or strand earlier-created events.

---

## 6. Canonical Incorporation Ordering & Sequence Allocation

### 6.1 `chain_seq` Invariant
For all rows in `audit_chain_links`:
$$\text{chain\_seq}_1 = 1$$
$$\text{chain\_seq}_k = \text{chain\_seq}_{k-1} + 1 \quad \forall k > 1$$
$$\text{Gaps} = \emptyset, \quad \text{Duplicates} = \emptyset$$

### 6.2 Evaluation of Allocation Mechanisms

| Mechanism | Description | Evaluation & Verdict |
| :--- | :--- | :--- |
| **PostgreSQL Sequence** (`CREATE SEQUENCE`) | Standard DB sequence generator. | **REJECTED.** PostgreSQL sequences are not transaction-isolated. If a transaction aborts or crashes after consuming `nextval()`, the sequence number is permanently lost, creating gaps in violation of the Contiguity Invariant. |
| **Table Lock** (`LOCK TABLE audit_chain_links IN EXCLUSIVE MODE`) | Coarse-grained table lock during incorporation. | **REJECTED.** Destroys concurrency, blocks read queries under certain lock modes, and causes query timeouts under heavy read loads. |
| **Row Lock on Head** (`SELECT ... ORDER BY chain_seq DESC LIMIT 1 FOR UPDATE`) | Queries and locks the highest existing link. | **CONDITIONALLY ACCEPTED.** Excellent for serialization inside an existing chain. However, at **Genesis** (when the table is empty), `LIMIT 1 FOR UPDATE` locks **zero rows**, leaving a race window for concurrent sealers. |
| **PostgreSQL Advisory Lock** (`pg_try_advisory_lock`) | Cluster-wide application lock in PostgreSQL memory. | **ACCEPTED.** Works across all connections, is transaction-independent, serializes sealers globally, and handles Genesis safely. |

### 6.3 Concurrency Proof of Chosen Strategy
The chosen design combines **Session-Scoped Advisory Locks** with **Chain-Head Row Locking**:
1. **Advisory Lock (Macro Layer):** Guarantees that only one process cluster-wide can enter the Sealer Execution Loop.
2. **Chain-Head Query with `FOR UPDATE` (Micro Layer):** Within the incorporation transaction, the leader locks the latest chain link:
   ```sql
   SELECT chain_seq, chain_hash 
   FROM audit_chain_links 
   ORDER BY chain_seq DESC 
   LIMIT 1 
   FOR UPDATE;
   ```
   - If rows exist: `next_seq = chain_seq + 1`, `prev_hash = chain_hash`.
   - If table is empty (Genesis): `next_seq = 1`, `prev_hash = GENESIS_CHAIN_HASH`.
3. Within the single transaction, $N$ candidates are assigned sequential numbers $[next\_seq, next\_seq + N - 1]$ and batch-inserted.
4. On `COMMIT`, all $N$ links become visible simultaneously and atomically.
5. On `ROLLBACK`, zero links are inserted; the next cycle reads the unchanged head.

---

## 7. Single-Leader / Multi-Sealer Architecture

### 7.1 Advisory Lock Key Definition
PostgreSQL advisory locks use 64-bit integer identifiers. B-SEA allocates a distinct, dedicated lock key from the application namespace:

$$\text{Lock Key} = \texttt{0x4253454100000001}\quad (\text{Hex for ASCII 'BSEA' } \parallel \text{ Subsystem ID } 1)$$
$$\text{Decimal: } 4779267104085409793$$

In SQL:
```sql
SELECT pg_try_advisory_lock(4779267104085409793);
```

### 7.2 Session-Scoped vs. Transaction-Scoped Locks
- **Transaction-Scoped (`pg_advisory_xact_lock`):** Automatically released on `COMMIT` or `ROLLBACK`. If used for the sealer leader loop, the lock would be released and reacquired every cycle, causing heavy lock-churn, race conditions between workers, and non-deterministic leader flipping.
- **Session-Scoped (`pg_try_advisory_lock` — SELECTED):** Bound to the physical PostgreSQL connection (`pg_stat_activity`). The leader process holds this lock continuously across multiple sealing cycles on a dedicated background connection.

### 7.3 Multi-Worker Lifecycle & Failover Dynamics

```
+------------------------------------+        +------------------------------------+
|       Gunicorn Worker 1            |        |       Gunicorn Worker 2            |
|  (AuditSealer Background Task)     |        |  (AuditSealer Background Task)     |
+------------------------------------+        +------------------------------------+
                  |                                              |
     1. pg_try_advisory_lock(...)                   1. pg_try_advisory_lock(...)
                  |                                              |
            [ Returns TRUE ]                               [ Returns FALSE ]
                  |                                              |
         ==> BECOMES LEADER                             ==> BECOMES STANDBY
                  |                                              |
        Loops every 500ms:                             Sleeps for 5.0 seconds.
        - Select Candidates                            Re-attempts:
        - Insert Chain Links                           pg_try_advisory_lock(...)
        - Check Epochs                                           |
                  |                                              |
     [ Worker 1 Process Dies / OOM ]                             |
                  |                                              |
     TCP Connection Closes                                       |
     PostgreSQL automatically drops                              |
     session-scoped advisory lock.                               |
                  |                                              |
                  X                                    [ Returns TRUE ]
                                                                 |
                                                        ==> PROMOTED TO LEADER
                                                        Resumes sealing gaplessly!
```

---

## 8. Transaction Boundaries & Frozen Range Invariant

A cardinal security requirement is: **AWS KMS network operations must NEVER occur inside a PostgreSQL database transaction.**

To enforce this, operations are divided into four strictly decoupled transaction scopes:

```
+-----------------------------------------------------------------------------------------------+
| TRANSACTION A: Event Creation (API Context)                                                   |
| Mode A (Business): Within caller's active transaction; commits/rolls back with business data. |
| Mode B (Security): Isolated dedicated session; commits immediately regardless of caller state.|
+-----------------------------------------------------------------------------------------------+

+-----------------------------------------------------------------------------------------------+
| TRANSACTION B: Sealer Incorporation Batch (AuditSealer Context)                               |
| BEGIN                                                                                         |
|   1. SELECT chain_seq, chain_hash FROM audit_chain_links ORDER BY chain_seq DESC LIMIT 1      |
|      FOR UPDATE;                                                                              |
|   2. SELECT al.id, al.event_hash FROM audit_logs al WHERE NOT EXISTS (...) LIMIT :batch_size; |
|   3. Compute chain_hash values in memory for items 1..N;                                      |
|   4. INSERT INTO audit_chain_links (chain_seq, audit_log_id, event_hash, prev_chain_hash,    |
|                                    chain_hash, created_at) VALUES (...);                     |
| COMMIT                                                                                        |
| [Links 1..N are now permanently sealed. All DB row locks released.]                          |
+-----------------------------------------------------------------------------------------------+

+-----------------------------------------------------------------------------------------------+
| OPERATION C: Epoch Merkle Root Computation & KMS Signature (OUTSIDE DB TRANSACTION)          |
| [NO OPEN DATABASE TRANSACTION, NO ROW LOCKS HELD]                                            |
|   1. Target range [start_chain_seq, end_chain_seq] is already COMMITTED and FROZEN in DB;      |
|   2. All links in range exist and are permanently immutable;                                  |
|   3. Compute binary Merkle Tree Root (epoch_root_hash) using RFC 6962 domain separation;      |
|   4. Build canonical epoch manifest payload following RFC 8785 principles;                    |
|   5. Invoke AWS KMS: `kms_client.sign(KeyId=..., Message=manifest_bytes, SigningAlgorithm=...)`|
|      with strict 5.0s client timeout;                                                         |
|   6. Receive signature_b64 from KMS HSM.                                                      |
+-----------------------------------------------------------------------------------------------+

+-----------------------------------------------------------------------------------------------+
| TRANSACTION D: Epoch Seal Persistence (AuditSealer Context)                                   |
| BEGIN                                                                                         |
|   1. SELECT epoch_id, end_chain_seq FROM audit_epoch_seals ORDER BY epoch_id DESC LIMIT 1     |
|      FOR UPDATE;                                                                              |
|   2. Verify start_chain_seq == (last_end_chain_seq + 1) AND target_epoch_id == last_id + 1;   |
|   3. Verify no intervening epoch seal exists;                                                 |
|   4. INSERT INTO audit_epoch_seals (epoch_id, start_chain_seq, end_chain_seq, record_count,   |
|                                    prev_seal_hash, final_chain_hash, epoch_root_hash,        |
|                                    signature_b64, kms_key_id, created_at) VALUES (...);       |
| COMMIT                                                                                        |
| [Epoch checkpoint is now permanently committed and immutable.]                                |
+-----------------------------------------------------------------------------------------------+
```

### 8.1 The Frozen Range Invariant
Why is it completely safe to execute Operation C (KMS signing) without holding an open database transaction?
1. **Committed Precondition:** An epoch range $[\text{start\_chain\_seq}, \text{end\_chain\_seq}]$ is selected **strictly from links that are already committed** in `audit_chain_links`.
2. **Database Immutability:** Because `audit_chain_links` has active PostgreSQL immutability triggers strictly prohibiting `UPDATE` and `DELETE`, every row in $[\text{start\_chain\_seq}, \text{end\_chain\_seq}]$ is **permanently frozen and unalterable**.
3. **Non-Overlapping Future Writes:** Any subsequent chain incorporation (whether by the active leader or a surviving leader after failover) assigns sequence numbers strictly $> \text{end\_chain\_seq}$. Future writes **cannot mutate or shift** the frozen links or their Merkle root.
4. **Leader Advisory Guard:** The session advisory lock remains continuously held across the entire cycle (incorporation, Merkle calculation, KMS signing, and seal persistence). This guarantees that no competing sealer process can assign chain sequence numbers or alter chain state during the epoch sealing workflow.
5. **No Long-Held Locks:** Consequently, KMS network calls never hold database connection resources, row locks, or transactions open, preventing connection pool exhaustion and deadlocks.

---

## 9. Canonical Chain Hash Formula

To achieve mathematical collision resistance and unambiguous binary encoding, the canonical `chain_hash` is computed over a strictly fixed-width 72-byte binary preimage:

$$\mathbf{preimage} = \mathbf{prev\_chain\_hash\_bytes} \parallel \mathbf{event\_hash\_bytes} \parallel \mathbf{chain\_seq\_bytes}$$
$$\mathbf{chain\_hash} = \text{SHA-256}(\mathbf{preimage})\quad [\text{rendered as 64 lowercase hexadecimal characters}]$$

### 9.1 Binary Preimage Specification

| Field | Source Column | Type / Length | Encoding Specification |
| :--- | :--- | :--- | :--- |
| `prev_chain_hash_bytes` | `audit_chain_links.prev_chain_hash` | 32 bytes | Raw bytes decoded from 64-char hexadecimal string (`bytes.fromhex(prev_hash)`). |
| `event_hash_bytes` | `audit_chain_links.event_hash` | 32 bytes | Raw bytes decoded from 64-char hexadecimal string (`bytes.fromhex(event_hash)`). |
| `chain_seq_bytes` | `audit_chain_links.chain_seq` | 8 bytes | Big-endian unsigned 64-bit integer (`struct.pack('>Q', chain_seq)`). |
| **Total Preimage Length** | — | **Exactly 72 bytes** | Fixed length. Zero ambiguity. Delimiters unnecessary. |

### 9.2 Reference Formulation
```python
import hashlib
import struct

def compute_canonical_chain_hash(
    prev_chain_hash_hex: str, 
    event_hash_hex: str, 
    chain_seq: int
) -> str:
    if len(prev_chain_hash_hex) != 64 or len(event_hash_hex) != 64:
        raise ValueError("Hash strings must be exactly 64 hexadecimal characters")
    if chain_seq < 1:
        raise ValueError("chain_seq must be a positive non-zero integer")

    prev_bytes = bytes.fromhex(prev_chain_hash_hex)
    event_bytes = bytes.fromhex(event_hash_hex)
    seq_bytes = struct.pack(">Q", chain_seq)

    preimage = prev_bytes + event_bytes + seq_bytes  # Exactly 72 bytes
    return hashlib.sha256(preimage).hexdigest()
```

---

## 10. Genesis Condition

### 10.1 Chain Genesis (`chain_seq = 1`)
When the `audit_chain_links` table is empty, the sealer establishes the Genesis link:
- **`chain_seq`:** `1`
- **`prev_chain_hash`:** The standard B-SEA Genesis Constant:
  $$\texttt{GENESIS\_CHAIN\_HASH} = \texttt{"0"} \times 64\quad (\text{64 hexadecimal ASCII zeros})$$
- **Preimage for Link 1:**
  $$\text{preimage}_1 = (\texttt{b"\\x00"} \times 32) \parallel \text{bytes.fromhex}(event\_hash_1) \parallel \text{struct.pack}(">Q", 1)$$
- **`chain_hash` for Link 1:**
  $$\text{chain\_hash}_1 = \text{SHA-256}(\text{preimage}_1)$$

### 10.2 Epoch Genesis (`epoch_id = 1`)
For the first epoch seal in `audit_epoch_seals`:
- **`epoch_id`:** `1`
- **`prev_seal_hash`:**
  $$\texttt{GENESIS\_EPOCH\_HASH} = \texttt{"0"} \times 64$$
- **`start_chain_seq`:** `1`

---

## 11. Exactly-Once Incorporation Proof

### 11.1 Threat: Duplicate Incorporation
Could an audit event $E$ ever be incorporated into `audit_chain_links` twice?

### 11.2 Multi-Layered Defense Proof
1. **Application Query Exclusion:**
   The sealer candidate selection query includes `WHERE NOT EXISTS (SELECT 1 FROM audit_chain_links acl WHERE acl.audit_log_id = al.id)`. Any event already linked is filtered out before memory allocation.
2. **Cluster-Wide Single Leader:**
   The session-scoped advisory lock guarantees that only one sealer process executes the candidate selection and incorporation loop.
3. **Database Uniqueness Constraint (Hard Guarantee):**
   `audit_chain_links` has an immutable unique constraint created in Phase 3C-4A:
   ```sql
   CONSTRAINT uq_audit_chain_links_audit_log_id UNIQUE (audit_log_id)
   ```
   If a rogue or parallel thread attempts to link the same `audit_log_id`, PostgreSQL immediately raises a `unique_violation` (error code `23505`) and rolls back the transaction.
4. **Sequence Uniqueness Constraint:**
   `audit_chain_links` enforces:
   ```sql
   CONSTRAINT uq_audit_chain_links_chain_seq UNIQUE (chain_seq)
   ```
   No two events can ever share or overwrite a sequence position.

---

## 12. Sealer Crash & Recovery Matrix

| Failure Case | State at Failure | State Remaining in DB | Recovery Action on Restart / Failover | Chain Integrity Guarantee |
| :--- | :--- | :--- | :--- | :--- |
| **Case 1: Crash before Tx begins** | Candidate batch selected in memory; process crashes before `BEGIN`. | Zero change to DB. Events remain unlinked in `audit_logs`. | Standby acquires advisory lock; re-queries unlinked candidates. | Safe. Zero orphaned or partial records. |
| **Case 2: Crash after `BEGIN`, before `INSERT`** | Tx opened, chain head locked `FOR UPDATE`; process dies. | Backend connection terminates. PostgreSQL executes automatic `ROLLBACK`. | Standby acquires lock; queries clean chain head and unlinked candidates. | Safe. No locks remain held. |
| **Case 3: Crash during `INSERT`, before `COMMIT`** | Some links inserted in transaction buffer; process crashes. | PostgreSQL connection loss triggers immediate, automatic `ROLLBACK`. | No rows inserted into `audit_chain_links`. Standby restarts batch from clean head. | Safe. Gapless atomicity guaranteed by DB ACID properties. |
| **Case 4: Crash immediately after `COMMIT`** | Transaction B committed; process crashes before checking epoch. | All $N$ links are permanently committed in `audit_chain_links`. | New leader acquires lock; queries `MAX(chain_seq)`, sees links are sealed; evaluates epoch boundary. | Safe. Links are durable. Epoch evaluation resumes seamlessly. |
| **Case 5: KMS signing fails / times out** | Epoch boundary detected; KMS API returns 500 or times out. | Chain links remain committed. No row inserted in `audit_epoch_seals`. | Sealer catches `KMSError`, logs alert, backs off (5s), and retries Operation C with same parameters. | Safe. Chain sealing continues; epoch seal retries until KMS recovers. |
| **Case 6: Crash after KMS sign, before Seal Insert** | Signature received in memory; process crashes before Transaction D commits. | Signature lost from memory. Zero rows in `audit_epoch_seals`. | New leader evaluates epoch boundary, reconstructs identical canonical payload, re-signs with KMS, and commits seal. | Safe. Ed25519 signatures over identical deterministic manifests are valid. |
| **Case 7: DB connection lost during sealing** | Network drop between sealer and PostgreSQL. | TCP disconnect causes PostgreSQL to abort active Tx and release advisory lock. | Sealer enters `ERROR_BACKOFF`, reconnects, re-acquires lock, and resumes. | Safe. Session-scoped advisory lock prevents phantom leaders. |
| **Case 8: Two sealers run concurrently** | Second worker attempts to start sealing cycle. | Second worker calls `pg_try_advisory_lock()`, receives `FALSE`. | Second worker drops to `STANDBY`, sleeps 5.0 seconds. | Safe. Only one leader ever executes incorporation. |
| **Case 9: Long Tx commits during sealing** | Event $E_{slow}$ commits while sealer is processing batch $B$. | $E_{slow}$ becomes visible in `audit_logs` after batch $B$ begins. | Batch $B$ completes. On next cycle, $E_{slow}$ is selected and linked at `head_seq + 1`. | Safe. No sequence gaps; no stranded records. |

---

## 13. Epoch Continuity, Identity Allocation & Boundary Policy

### 13.1 Correction: Phase 3C-4A Database Constraint Boundaries
It must be explicitly understood and stated:
> **The Phase 3C-4A database schema DOES NOT enforce cross-epoch sequence continuity ($\text{start\_chain\_seq}_N = \text{end\_chain\_seq}_{N-1} + 1$).**

The schema constraints in `audit_epoch_seals` created in Phase 3C-4A enforce only:
- `start_chain_seq >= 1`
- `start_chain_seq <= end_chain_seq`
- `record_count > 0`
- `record_count = end_chain_seq - start_chain_seq + 1`
- `UNIQUE (end_chain_seq)`

Therefore, **Phase 3C-4B provides the authoritative, atomic mechanism** to guarantee cross-epoch continuity, prevent sequence gaps, prevent overlapping ranges, and resolve crash-recovery races without relying on volatile application memory.

### 13.2 Exact Epoch Sizing & Boundary Policy

B-SEA defines an explicit, unambiguous policy governing epoch creation:
- **`TARGET_EPOCH_SIZE`:** `1,000` links (Target / maximum batch size, **NOT** a mandatory minimum).
- **`MAX_EPOCH_AGE`:** `15` minutes.

#### Precise Definition of Epoch Age Trigger:
The age threshold is measured **strictly from the `created_at` timestamp of the OLDEST currently unsealed audit event** eligible for canonical incorporation:
$$\text{oldest\_unsealed\_event\_age} = \text{NOW}() - \min_{al \in \text{Unsealed}}(\texttt{al.created\_at})$$

`created_at` is used **ONLY as a sealing-age trigger**. It is **NOT** a claim of database commit ordering. Authoritative ordering remains strictly sealer-assigned `chain_seq`.

#### Authoritative Policy Rules:
1. **Rule A (Zero Unsealed):**
   If $\text{unsealed\_count} = 0$:
   Do nothing. Zero epoch rows are created.
2. **Rule B (Full Epoch):**
   If at least 1,000 contiguous unsealed committed links are available ($\text{unsealed\_count} \ge 1,000$):
   Seal exactly 1,000 links:
   $$\text{end\_chain\_seq} = \text{start\_chain\_seq} + 1,000 - 1 = \text{start\_chain\_seq} + 999$$
   $$\text{record\_count} = 1,000$$
3. **Rule C (Partial Epoch):**
   If fewer than 1,000 contiguous unsealed committed links are available ($1 \le \text{unsealed\_count} < 1,000$) **AND** $\text{oldest\_unsealed\_event\_age} \ge 15\text{ minutes}$:
   Seal ALL currently available contiguous links as a **PARTIAL EPOCH**:
   $$\text{end\_chain\_seq} = \text{start\_chain\_seq} + \text{unsealed\_count} - 1 = \text{MAX(committed chain\_seq)}$$
   $$\text{record\_count} = \text{end\_chain\_seq} - \text{start\_chain\_seq} + 1 = \text{unsealed\_count}$$
4. **Rule D (No Phantom Links):**
   The sealer must **NEVER** construct an epoch range containing a `chain_seq` for which no committed `audit_chain_link` exists.
5. **Rule E (Mathematical Invariants):**
   Every epoch range must strictly satisfy:
   $$\text{start\_chain\_seq} \le \text{end\_chain\_seq}$$
   $$\text{record\_count} = \text{end\_chain\_seq} - \text{start\_chain\_seq} + 1$$
6. **Rule F (Strict Contiguity Anchor):**
   The next epoch MUST begin strictly at:
   $$\text{start\_chain\_seq}_N = \text{end\_chain\_seq}_{N-1} + 1$$

---

## 14. Binary Merkle Tree Specification (RFC 6962 Domain Separation)

To eliminate any ambiguity in binary tree construction, B-SEA strictly specifies an RFC 6962-compliant binary Merkle Tree algorithm with 1-byte domain separation prefixes to prevent second-preimage attacks:

### 14.1 Exact Hashing Primitive
1. **Leaf Nodes:**
   $$\text{leaf\_hash}_i = \text{SHA-256}(\texttt{0x00} \parallel \text{bytes.fromhex}(\texttt{chain\_links}[i].\texttt{chain\_hash}))$$
   - Domain prefix: `0x00` (1 raw byte).
   - Payload: 32 raw bytes of the link's `chain_hash`.
   - Total leaf preimage: Exactly 33 bytes.
   - Result: 32 raw binary bytes.
2. **Internal Parent Nodes:**
   $$\text{parent\_hash} = \text{SHA-256}(\texttt{0x01} \parallel \text{left\_child\_bytes} \parallel \text{right\_child\_bytes})$$
   - Domain prefix: `0x01` (1 raw byte).
   - Payload: 32 bytes left child + 32 bytes right child.
   - Total parent preimage: Exactly 65 bytes.
   - Result: 32 raw binary bytes.

### 14.2 Construction Rules
- **Sequential Ordering:** Leaf nodes are ordered strictly by ascending `chain_seq` ($\text{start\_chain\_seq} \dots \text{end\_chain\_seq}$).
- **Odd Node Duplication:** If a tree level contains an odd number of nodes ($> 1$), the final node is duplicated to balance the pair:
  $$\text{parent} = \text{SHA-256}(\texttt{0x01} \parallel \text{final\_node} \parallel \text{final\_node})$$
- **Single-Link Epoch ($N = 1$):**
  If an epoch contains exactly one link ($\text{record\_count} = 1$), the Merkle root is defined strictly as its leaf hash:
  $$\text{epoch\_root\_hash} = \text{leaf\_hash}_1 = \text{SHA-256}(\texttt{0x00} \parallel \text{bytes.fromhex}(\texttt{chain\_hash}_1))$$
- **Empty Epoch ($N = 0$):** Strictly forbidden.
- **Output:** The final Merkle root is encoded as a 64-character lowercase hexadecimal string (`epoch_root_hash`).

---

## 15. Canonical Epoch Manifest Specification & `prev_seal_hash`

### 15.1 Manifest Fields
The epoch manifest signed by AWS KMS contains exactly nine participating fields:

```json
{
  "manifest_version": 1,
  "policy_version": "BSEA-AUDIT-v1",
  "epoch_id": 42,
  "start_chain_seq": 41001,
  "end_chain_seq": 42000,
  "record_count": 1000,
  "epoch_root_hash": "789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456",
  "prev_seal_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "kms_key_id": "arn:aws:kms:ap-south-1:123456789012:key/mrk-ed25519-audit-sealer"
}
```

### 15.2 Invariant Field Requirements
1. **No Retry Timestamps:** The manifest **MUST NOT** contain dynamic creation timestamps (`created_at` or retry timestamps). Creation time is recorded separately in the database row. Excluding timestamps guarantees byte-for-byte reproducibility during crash recovery.
2. **Immutable KMS Key ARN:** `kms_key_id` must be the exact, immutable AWS KMS Key ARN (e.g. `arn:aws:kms:...:key/...`). **Mutable KMS aliases (e.g. `alias/audit-sealer`) are strictly prohibited** in the signed manifest to ensure historical verification succeeds across key migrations.
3. **Serialization:** Serialized via deterministic key-sorted compact JSON following RFC 8785 principles (`separators=(',', ':')`, `ensure_ascii=False`, UTF-8).

### 15.3 Exact `prev_seal_hash` Definition
The previous seal hash links epoch manifests into an unbreakable cryptographic chain:
$$\mathbf{prev\_seal\_hash}_N = \text{SHA-256}(\mathbf{manifest\_bytes}_{N-1})\quad [\text{rendered as 64 lowercase hex characters}]$$

- **Exclusion of Signature:** `prev_seal_hash` hashes the **exact canonical manifest bytes** of the preceding epoch, **WITHOUT the digital signature**.
- **Signature Verification Boundary:** The digital signature is independently verified using the stored `kms_key_id` and `signature_b64`.
- **Genesis Value:** For Epoch 1, $\mathbf{prev\_seal\_hash}_1 = \texttt{"0"} \times 64$.

---

## 16. KMS Retry & Deterministic Ed25519 Recovery Model

### 16.1 Disclaimer of KMS-Level Idempotency Cache
AWS KMS does **NOT** provide an application-level cached idempotency service for `kms:Sign`. B-SEA makes no claim that AWS KMS caches or de-duplicates signature requests.

### 16.2 Deterministic Crash Recovery Protocol
If KMS signing succeeds but database persistence fails (e.g. process killed before Transaction D commits):
1. The immutable chain range $[\text{start\_chain\_seq}, \text{end\_chain\_seq}]$ remains intact in `audit_chain_links`.
2. The surviving sealer acquires the advisory lock and determines the unsealed range.
3. It derives the **exact same `epoch_id`** ($\text{last\_seal.epoch\_id} + 1$).
4. It reads the **exact same immutable links** and recomputes the **exact same `epoch_root_hash`**.
5. It reconstructs the **exact same byte-for-byte canonical JSON manifest**.
6. It retries `kms:Sign` against AWS KMS using the exact same KMS key ARN.
7. Because the approved asymmetric signing algorithm is **deterministic Ed25519 (RFC 8032 / PureEd25519)**, signing the identical manifest bytes with the identical private key produces the **exact same digital signature**.
8. Transaction D commits the seal record cleanly.

$$\mathbf{Same\ Chain\ Range} \longrightarrow \mathbf{Same\ epoch\_id} \longrightarrow \mathbf{Same\ Manifest\ Bytes} \longrightarrow \mathbf{Same\ Ed25519\ Signature}$$

---

## 17. Historical Backfill Policy (5,982 Records)

The B-SEA repository currently contains **5,982 historical rows** in `audit_logs`.

### 17.1 Administrative Migration Procedure
- Historical backfill is an explicit, one-time administrative migration procedure executed under the sealer advisory lock.
- The standard 15-minute age policy is **NOT** applied during historical backfill.
- All 5,982 records are backfilled sequentially into `audit_chain_links` with contiguous $\text{chain\_seq} = 1 \dots 5982$.

### 17.2 Exact Historical Epoch Mapping

| Epoch ID | Start Chain Seq | End Chain Seq | Record Count | Epoch Type | Preceding Seal Pointer (`prev_seal_hash`) |
| :---: | :---: | :---: | :---: | :---: | :--- |
| **Epoch 1** | `1` | `1000` | `1000` | Full | $\texttt{"0"} \times 64$ (Genesis Constant) |
| **Epoch 2** | `1001` | `2000` | `1000` | Full | $\text{SHA-256}(\text{manifest\_bytes}(\text{Epoch 1}))$ |
| **Epoch 3** | `2001` | `3000` | `1000` | Full | $\text{SHA-256}(\text{manifest\_bytes}(\text{Epoch 2}))$ |
| **Epoch 4** | `3001` | `4000` | `1000` | Full | $\text{SHA-256}(\text{manifest\_bytes}(\text{Epoch 3}))$ |
| **Epoch 5** | `4001` | `5000` | `1000` | Full | $\text{SHA-256}(\text{manifest\_bytes}(\text{Epoch 4}))$ |
| **Epoch 6** | `5001` | `5982` | `982` | **Partial** | $\text{SHA-256}(\text{manifest\_bytes}(\text{Epoch 5}))$ |

- **Total Historical Coverage:** Exactly $(5 \times 1000) + 982 = 5,982$ links.
- **Strict Contiguity:** $\forall i \in [2, 6], \text{start}_i = \text{end}_{i-1} + 1$.
- **Live Chain Cutover:** Live application sealing begins strictly at $\text{chain\_seq} = 5983$ (destined for **Epoch 7**).

---

## 18. Multi-Worker & Multi-Process Safety Analysis

The B-SEA production container runs Gunicorn with multiple Uvicorn workers (`GUNICORN_WORKERS=4`).

### 18.1 Elimination of In-Process Assumptions
- **No `asyncio.Lock`:** `asyncio.Lock` operates only within a single Python event loop inside a single process. It provides zero synchronization across the 4 Gunicorn worker processes. It is strictly banned for sealer coordination.
- **No In-Memory Queues:** In-memory queues partition state across processes, causing event isolation and loss.
- **No Local Counters:** No worker maintains an internal sequence counter in memory. All sequence state is derived from PostgreSQL transactional reads.

### 18.2 Connection Pooling Dynamics
- The application uses `asyncpg` via SQLAlchemy `AsyncSessionLocal`.
- Advisory locks are held per physical session. The `AuditSealer` background task must maintain its own **dedicated, long-lived database connection** for holding the session-scoped advisory lock.
- Normal API request handlers acquire short-lived connections from the connection pool (`DB_POOL_SIZE = 10`, `DB_MAX_OVERFLOW = 20`) and never interfere with the sealer's advisory lock.

---

## 19. Performance, Batching & Backlog Strategy

### 19.1 Tunable Operational Parameters

| Parameter | Environment Variable | Default Value | Operational Rationale |
| :--- | :--- | :--- | :--- |
| `SEALER_BATCH_SIZE` | `BSEA_SEALER_BATCH_SIZE` | `100` | Optimal compromise between transaction duration (<15ms) and row-lock contention. Configurable up to 500. |
| `SEALER_POLL_INTERVAL_MS`| `BSEA_SEALER_POLL_INTERVAL_MS`| `500` | Polling frequency when the backlog is small. Minimizes sealing latency without overwhelming PostgreSQL. |
| `SEALER_IDLE_SLEEP_MS` | `BSEA_SEALER_IDLE_SLEEP_MS` | `2000` | Sleep duration when candidate query returns 0 rows. |
| `STANDBY_POLL_INTERVAL_S`| `BSEA_STANDBY_POLL_INTERVAL_S`| `5.0` | Heartbeat interval for standby workers attempting to acquire advisory lock. |
| `TARGET_EPOCH_SIZE` | `BSEA_TARGET_EPOCH_SIZE` | `1000` | Target/maximum number of chain links per signed KMS epoch seal. |
| `MAX_EPOCH_AGE_MINUTES` | `BSEA_MAX_EPOCH_AGE_MINUTES` | `15` | Maximum elapsed time from oldest unsealed event before sealing a partial epoch. |

### 19.2 Dynamic Backpressure & Backlog Draining
- If the candidate query returns a full batch (`len(candidates) == SEALER_BATCH_SIZE`), the sealer immediately triggers the next incorporation cycle **without sleeping** (`await asyncio.sleep(0)` to yield the event loop).
- This allows the sealer to drain high-volume exam submission backlogs at peak database throughput.

---

## 20. Audit Sealer State Machine

```
              +-----------------------+
              |      INITIALIZING     |
              +-----------------------+
                          |
                          v
              +-----------------------+
              |     ACQUIRE_LOCK      |<-------------------------+
              +-----------------------+                          |
                /                   \                           |
      [Lock == False]            [Lock == True]                  |
              /                       \                         |
             v                         v                         |
+------------------------+   +------------------------+          |
|        STANDBY         |   |     LEADER_ACTIVE      |          |
| (Sleep 5.0s, retry)    |   +------------------------+          |
+------------------------+                 |                     |
             |                             v                     |
             |                 +------------------------+        |
             +---------------->|   SELECT_CANDIDATES    |        |
                               +------------------------+        |
                                 /                    \         |
                       [Candidates == 0]     [Candidates > 0]    |
                               /                        \       |
                              v                          v       |
                   +--------------------+      +-----------------------+
                   |     IDLE_SLEEP     |      |  INCORPORATE_BATCH    |
                   |    (Sleep 2.0s)    |      | (Compute hashes, Ins) |
                   +--------------------+      +-----------------------+
                              |                          |
                              |                          v
                              |                +-----------------------+
                              |                |     COMMIT_BATCH      |
                              |                +-----------------------+
                              |                          |
                              +------------+             v
                                           |   +-----------------------+
                                           +-->| CHECK_EPOCH_BOUNDARY  |
                                               +-----------------------+
                                                 /                   \
                                         [No Boundary]          [Boundary Met]
                                               /                       \
                                              v                         v
                                     (Loop to Select)         +-----------------------+
                                                              |   COMPUTE_MERKLE_ROOT |
                                                              +-----------------------+
                                                                        |
                                                                        v
                                                              +-----------------------+
                                                              |     KMS_SIGN_ASYNC    |
                                                              | (Non-blocking network)|
                                                              +-----------------------+
                                                                        |
                                                                        v
                                                              +-----------------------+
                                                              |     PERSIST_EPOCH     |
                                                              |  (INSERT epoch_seals) |
                                                              +-----------------------+
                                                                        |
                                                                        v
                                                              (Loop to Select)
```

---

## 21. Security Threat Model

| # | Attack / Failure Vector | Threat Description | Architectural Mitigation / Control | Residual Risk |
| :--- | :--- | :--- | :--- | :--- |
| **1** | **Concurrent Sealers** | Two sealer instances running in separate processes attempt to assign sequence numbers simultaneously. | PostgreSQL session-scoped advisory lock `0x4253454100000001` ensures single active leader. Secondary `uq_audit_chain_links_chain_seq` rejects duplicates at DB level. | None. PostgreSQL advisory lock is strictly mutually exclusive. |
| **2** | **Duplicate Incorporation** | The same raw event is incorporated into the chain multiple times. | Anti-join candidate query filters existing links; `uq_audit_chain_links_audit_log_id` constraint strictly rejects duplicates with error `23505`. | None. Enforced by database schema constraint. |
| **3** | **Sequence Collision** | Sequence numbers collide ($seq=100$ assigned to two events). | Head query with `FOR UPDATE` serializes assignment. DB UNIQUE constraint enforces uniqueness. | None. |
| **4** | **Chain Link Tampering** | Attacker executes SQL `UPDATE` on `audit_chain_links.chain_hash`. | PostgreSQL trigger `trg_audit_chain_links_immutable` executes `BEFORE UPDATE` and unconditionally raises exception. | Privileged DBA (`postgres` superuser) can disable triggers. (Separate trust boundary). |
| **5** | **Audit Event Deletion** | Attacker executes SQL `DELETE` on `audit_logs`. | PostgreSQL trigger `trg_audit_logs_immutable` unconditionally blocks `DELETE`. FK constraint with `ON DELETE RESTRICT` also blocks deletion if linked. | Privileged DBA can drop table or bypass triggers. |
| **6** | **Audit Event Mutation** | Attacker modifies event payload (e.g. changes `actor_id` or `result`). | PostgreSQL trigger blocks `UPDATE`. Furthermore, verification recomputes canonical `event_hash` and detects hash mismatch against `audit_chain_links.event_hash`. | None for application users. Tampering is cryptographically detectable. |
| **7** | **Candidate Race** | High-throughput concurrent inserts race with candidate query. | Candidate query is deterministic via `ORDER BY created_at ASC, id ASC`. Any event not captured in batch $B$ is captured in batch $B+1$. | None. |
| **8** | **Long-Running Tx Race**| Transaction remains open for minutes, committing later. | MVCC hides uncommitted rows. Once committed, event is picked up in subsequent batch and given the next available `chain_seq`. | None. No sequence gaps; no stranded records. |
| **9** | **Sealer Crash** | Process crashes mid-batch or mid-epoch. | Transactions provide ACID atomicity. Advisory lock automatically releases on connection teardown. Standby resumes from clean head. | None. |
| **10**| **Replay of Linked Event**| Stale candidate list attempts to re-link an already-linked event. | `ON CONFLICT (audit_log_id) DO NOTHING` or `IntegrityError` catch handles stale memory state cleanly. | None. |
| **11**| **Epoch Overlap** | Epoch $E_2$ starts before $E_1$ finishes, overlapping sequences. | Schema constraint: `UNIQUE(end_chain_seq)` and sealer checks `start_chain_seq == last_end_chain_seq + 1`. | None. |
| **12**| **Epoch Truncation** | Epoch claims fewer records than sequence range covers. | CHECK constraint `ck_audit_epoch_seals_count_match`: `record_count = (end_chain_seq - start_chain_seq + 1)`. | None. |
| **13**| **KMS Failure / Timeout** | AWS KMS API is throttled or unreachable during epoch signing. | KMS call occurs strictly outside DB transaction. Failure leaves chain links intact. Sealer retries signing with exponential backoff. | Temporary delay in epoch seal publication; zero audit data loss. |
| **14**| **Privileged Database Admin**| Rogue PostgreSQL administrator alters records or disables triggers. | Database mutations cannot forge AWS KMS Ed25519 signatures. Independent verifier detects mismatch between modified chain and KMS-signed epoch seals. | Historical epoch seals are tamper-evident; unsealed recent links could be altered by superuser. |

---

## 22. Comprehensive Verification & Test Strategy

Prior to Phase 3C-4B implementation, the following 20 test specifications (A through T) must be developed using real PostgreSQL instances (concurrency and advisory locks cannot be verified against SQLite):

| Test ID | Test Category | Scenario & Verification Mechanics |
| :--- | :--- | :--- |
| **Test A** | Single-Event Incorporation | Insert 1 raw `AuditLog`. Run sealer. Verify 1 `AuditChainLink` created with `chain_seq=1`, correct `prev_chain_hash` (Genesis), and matching `event_hash`. |
| **Test B** | Batch Incorporation | Insert 250 raw events. Run sealer with `batch_size=100`. Verify 3 cycles execute, creating exactly 250 contiguous links ($1..250$). |
| **Test C** | Genesis Integrity | Verify first link has `prev_chain_hash = "0"*64` and `chain_seq=1`. |
| **Test D** | Contiguous Sequence | Verify $\forall i \in [2, N], \text{chain\_seq}_i = \text{chain\_seq}_{i-1} + 1$. Zero gaps. |
| **Test E** | Previous Hash Pointer | Verify $\forall i \in [2, N], \text{prev\_chain\_hash}_i = \text{chain\_hash}_{i-1}$. |
| **Test F** | Cryptographic Hash Match | Recompute SHA-256 over 72-byte binary preimage for every link; assert exact match against stored `chain_hash`. |
| **Test G** | Duplicate Event Rejection | Attempt to insert duplicate link with existing `audit_log_id`. Assert PostgreSQL raises `IntegrityError` (`uq_audit_chain_links_audit_log_id`). |
| **Test H** | Duplicate Sequence Rejection| Attempt to insert link with existing `chain_seq`. Assert PostgreSQL raises `IntegrityError` (`uq_audit_chain_links_chain_seq`). |
| **Test I** | Concurrent Sealer Race | Spawn 5 concurrent asyncio tasks attempting to run sealer simultaneously. Assert exactly 1 leader acquires lock; zero conflicting sequences generated. |
| **Test J** | Advisory Lock Exclusivity | Verify `pg_try_advisory_lock` returns `True` for session 1 and `False` for session 2 on the same key. |
| **Test K** | Sealer Crash Recovery | Kill sealer process mid-incorporation. Start new sealer instance. Assert chain resumes from latest committed `chain_seq` without corruption. |
| **Test L** | Retry Idempotency | Re-run sealer when zero unlinked events exist. Assert zero rows inserted; sequence head unchanged. |
| **Test M** | Long Transaction Behavior | Start Tx A (holds event $E_1$, sleeps). Tx B commits event $E_2$. Sealer seals $E_2$ at $seq=1$. Tx A commits $E_1$. Sealer seals $E_1$ at $seq=2$. Assert zero errors and gapless sequence. |
| **Test N** | Concurrent Ingestion | 50 concurrent client threads insert 1,000 events while sealer runs continuously. Assert all 1,000 events are incorporated gaplessly. |
| **Test O** | Uncommitted Isolation | Insert event in open transaction without commit. Run sealer. Assert event is NOT selected. Roll back transaction. Assert event is never sealed. |
| **Test P** | Epoch Range Contiguity | Generate 2,500 links. Run epoch sealer with $K=1,000$. Assert Epoch 1 is $[1, 1000]$, Epoch 2 is $[1001, 2000]$. |
| **Test Q** | Epoch Overlap Rejection | Attempt manual insert into `audit_epoch_seals` with overlapping range. Assert DB constraint rejection. |
| **Test R** | KMS Failure Resilience | Mock KMS to raise `ClientError`. Run sealer. Assert chain links are committed; epoch seal failure is caught, logged, and retried. |
| **Test S** | Historical Compatibility | Verify 5,982 historical rows are backfilled into `audit_chain_links` and sealed into Epochs 1..6 ($1000 \times 5 + 982$). |
| **Test T** | Multi-Worker Execution | Spin up 4 independent OS processes running the application. Assert only 1 process becomes sealer leader. |

---

## 23. Implementation Sequence (When Authorized)

When implementation is formally authorized by the architectural review board, work will proceed in the following strict conceptual order:

```
Step 1:  Canonical Chain-Hash Primitive
         - Implement `compute_canonical_chain_hash()` in `backend/app/modules/audit/canonical.py`.
         - Implement 72-byte binary preimage parser and unit tests.

Step 2:  Dual-Mode Durable Audit Ingestion
         - Refactor `AuditService.log()` to insert raw `AuditLog` records directly into caller's DB transaction (Mode A).
         - Implement `AuditService.log_security_event()` using dedicated independent session (Mode B).
         - Terminate in-memory `_audit_queue` and legacy `audit_worker`.

Step 3:  AuditSealer Canonical Incorporation
         - Implement `AuditSealer` class in `backend/app/modules/audit/sealer.py`.
         - Implement session advisory lock acquisition (`0x4253454100000001`).
         - Implement candidate selection query with `WHERE NOT EXISTS`.
         - Implement batch incorporation transaction with chain-head row locking (`FOR UPDATE`).

Step 4:  Epoch Candidate & Range Determination
         - Implement deterministic `epoch_id` derivation without DB sequences.
         - Implement contiguous range mapping: `start_chain_seq = last_seal.end_chain_seq + 1`.

Step 5:  Partial / Full Epoch Policy
         - Implement `TARGET_EPOCH_SIZE` (1,000) and `MAX_EPOCH_AGE` (15 min) evaluation.
         - Handle partial epochs without creating phantom link bounds or zero-record epochs.

Step 6:  RFC 6962 Binary Merkle Tree
         - Implement binary Merkle tree root hash calculation (`epoch_root_hash`) over frozen epoch links using `0x00` / `0x01` prefixes.

Step 7:  KMS Signing Outside Database Transaction
         - Implement non-blocking asynchronous KMS Ed25519 signing.
         - Verify zero database transactions or locks are held during network execution.

Step 8:  Epoch Seal Persistence
         - Implement Transaction D with latest seal row locking (`FOR UPDATE`) and continuity assertions.
         - Persist epoch seal into `audit_epoch_seals`.

Step 9:  Historical Data Backfill
         - Create one-time idempotent script to backfill existing 5,982 rows into `audit_chain_links`.
         - Establish Epochs 1 through 6 (Epochs 1..5 full 1,000 links; Epoch 6 partial 982 links).

Step 10: Crash & Concurrency Testing
         - Execute crash recovery and retry tests on real PostgreSQL.
         - Validate long-running transactions and uncommitted MVCC isolation.

Step 11: Multi-Worker Testing
         - Test 4 Gunicorn worker processes running simultaneously.
         - Validate single-leader election and automatic failover.

Step 12: Final Security Review & Checkpoint Commit
         - Perform pre-commit security audit review.
         - Create Git commit checkpoint.
```

---

## 24. Implementation Gate (Pre-Implementation Verification)

Prior to authorizing implementation of Phase 3C-4B, every gate item below must be verified:

| Gate Item | Status | Verified Technical Specification |
| :--- | :---: | :--- |
| **1. Epoch age trigger precisely defined** | **YES** | Measured from `created_at` of oldest unsealed committed event (`NOW() - MIN(created_at) >= 15 min`). |
| **2. Full/partial epoch policy unambiguous** | **YES** | Full: $\ge 1,000$ unsealed links $\rightarrow$ seal 1,000. Partial: $< 1,000$ links and age $\ge 15$ min $\rightarrow$ seal all available. |
| **3. Historical event-hash semantics defined**| **YES** | Historical 5,982 hashes preserved without recomputation; verifier dual-path specified. |
| **4. Chain hash primitive defined** | **YES** | Fixed 72-byte binary preimage: `prev (32) || event (32) || seq_be (8)`. |
| **5. Merkle tree algorithm fully defined** | **YES** | RFC 6962 domain-separated binary tree: `0x00` leaf prefix, `0x01` parent prefix, odd duplication. |
| **6. Epoch manifest fields frozen** | **YES** | Exactly 9 frozen fields; retry timestamps excluded. |
| **7. Manifest serialization frozen** | **YES** | Deterministic key-sorted compact JSON following RFC 8785 principles. |
| **8. `prev_seal_hash` semantics frozen** | **YES** | Defined as $\text{SHA256}(\text{manifest\_bytes}_{N-1})$ strictly excluding signature. |
| **9. KMS retry semantics correct** | **YES** | Deterministic Ed25519 re-signing over identical bytes; KMS caching disclaimed. |
| **10. Epoch identity deterministic** | **YES** | $\text{epoch\_id} = \text{last\_seal.epoch\_id} + 1$ under advisory lock; no DB sequences. |
| **11. Cross-epoch continuity transaction defined**| **YES**| Transaction D checks `start_seq == last_end_seq + 1` under `FOR UPDATE` before commit. |
| **12. Frozen-range invariant defined** | **YES** | Range consists strictly of committed, immutable links; later writes receive $> end\_seq$. |
| **13. Advisory lock lifecycle defined** | **YES** | Session-scoped `0x4253454100000001` held continuously across sealer cycle. |
| **14. DB/KMS transaction boundaries defined**| **YES** | Zero database transactions or locks held during KMS network calls. |
| **15. Dual-mode durable ingestion defined** | **YES** | Mode A (business-atomic) vs. Mode B (security-isolated); in-memory queue eliminated. |
| **16. Historical backfill mapping defined** | **YES** | 5,982 rows mapped to Epochs 1..5 (1,000 links each) and Epoch 6 (982 links). |
| **17. PostgreSQL trust boundary stated** | **YES** | Privileged DBA superusers acknowledged as a distinct trust boundary. |
| **18. No production overclaims** | **YES** | Defensible claims only; zero-loss and commit-order overclaims eliminated. |
