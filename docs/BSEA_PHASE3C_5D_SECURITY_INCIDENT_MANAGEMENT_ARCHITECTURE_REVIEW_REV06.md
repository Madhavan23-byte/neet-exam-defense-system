# B-SEA Phase 3C-5D — Security Incident Management Foundation
## Final Architecture & Design Review (Rev-06)

**System:** Bharat Secure Examination Architecture (B-SEA)  
**Milestone:** Phase 3C-5D — Security Incident Management Foundation  
**Status:** ARCHITECTURE REVIEW REV-06 (FINAL ARCHITECTURAL RECONCILIATION)  
**Document Revision:** Rev-06 (Reconciliation of Distributed Generation Protocol, Canonical JCS Identity, and Containment Verification Timing)  
**Baseline Commit:** `7683dd6` (`feat: implement Phase 3C-5C detection correlation foundation`)  
**Baseline Verification:** `HEAD == origin/main` | Regression: 240 passed, 5 skipped, 0 failed  
**Governing Security Boundary:** Observational and Human-Managed Incident Case Workflow. **ZERO Autonomous Containment.**  

---

## 1. Executive Summary

Phase 3C-5D establishes the **Security Incident Management Foundation** for the Bharat Secure Examination Architecture (B-SEA). Where Phase 3C-5C delivered an observational, non-intrusive stream of deterministic, versioned advisory signals, Phase 3C-5D establishes the formal, auditable, and human-managed incident case lifecycle that ingests, triages, investigates, and resolves those signals.

### Final Gap Reconciliation Summary (Rev-05 to Rev-06)
Rev-06 completes the final architectural hardening required prior to implementation authorization:
1. **Distributed Generation Creation Protocol (No-OPEN-Generation Case)**: Formally defines the distributed concurrency protocol when a threat vector has historical generations ($1, 2, 3$) all in `correlation_status = 'CLOSED'` and two workers concurrently receive qualifying signals. Leverages **PostgreSQL Transaction-Scoped Advisory Locks** (`pg_advisory_xact_lock`) combined with double-checked locking and database partial uniqueness to ensure that Generation 4 is created exactly once, strictly monotonically, without signal loss, duplicate generations, or race deadlocks.
2. **Formally Canonical Threat Vector Identity (RFC 8785 JCS)**: Replaces ambiguous delimiter concatenation with the **JSON Canonicalization Scheme (RFC 8785 / JCS)**. Enforces deterministic multi-dimension key sorting, UTF-8 normalization (NFC), ASCII casing rules, empty/null omission, and strict time-independence. Provides a worked multi-dimension example (`candidate_id` + `node_id`).
3. **Dual-Phase Containment Verification Timing**: Resolves the timing gap between real-time external containment execution and periodic audit epoch sealing. Authorizes transition to `CONTAINED` upon **immediate cryptographic Ed25519 signature verification** of the authoritative audit record in PostgreSQL (`seal_verification_status = 'PENDING_SEAL'`), followed by asynchronous reconciliation once the epoch is sealed into AWS S3 (`'SEALED_VERIFIED'`). Defines complete failure and retry semantics.
4. **The Seven Generation Invariants**: Formally codifies seven mathematical and relational invariants governing generation derivation, active window singularity, strictly increasing monotonicity, and the immutable separation between threat identity and incident generation.
5. **Complete Generation State Machine**: Extensively documents the full generation lifecycle from initial signal ingestion, 3600-second rolling activity, inactivity rollover, human resolution closure, permanent historical queryability, and the rule that reopening an investigation does not reopen the correlation window.
6. **Preservation of Approved Invariants**: Retains zero autonomous containment, frozen legacy `SecurityService`, OCC versioning, 6-layer comment confidentiality, append-only records, and pure AWS KMS CMK production cryptography.

---

## 2. Repository Baseline

- **Current Repository Commit:** `7683dd6` (`feat: implement Phase 3C-5C detection correlation foundation`)
- **Branch Tracking:** `HEAD == origin/main` (Clean working tree on all tracked files)
- **Regression Baseline:** 240 passed, 5 skipped, 0 failed in 110.32s
- **Phase 3C-5C Status:** Formally implemented, verified, and locked in SHADOW MODE
- **Active Schema State:** PostgreSQL 16 schema at revision `f1a2b3c4d5e6` (Phase 3C-5A poison quarantine)
- **Metric Series Baseline:** 646 base series (520 from 5B + 126 from 5C), 1,516 expanded Prometheus series
- **File Freeze Invariant:** `backend/app/core/models.py`, `alembic/`, `service.py`, `sealer.py`, `quarantine.py`, `kms_interface.py`, and `terraform/` remain strictly frozen during architecture discovery.

---

## 3. Rev-05 to Rev-06 Architectural Gap Reconciliation

| Review Gap Identified | Rev-05 Status | Rev-06 Final Architectural Solution |
| :--- | :--- | :--- |
| **Generation Creation Race with No OPEN Row** | Specified rollover from active row; left gap when all past generations are `CLOSED`. | **Transaction-scoped PostgreSQL advisory lock (`pg_advisory_xact_lock`) with double-checked read; ensures strictly monotonic next generation derivation.** |
| **Threat Vector Identity Canonicalization** | Colon-separated string concatenation (`rule:dim:val`). | **RFC 8785 JSON Canonicalization Scheme (JCS). Exact UTF-8 bytes, lexicographical dimension sorting, deterministic multi-dimension hashing.** |
| **Containment Verification Timing** | Ambiguous whether 5D waited for epoch sealing to complete. | **Dual-phase verification: Immediate Ed25519 signature verification allows real-time `CONTAINED`; asynchronous reconciliation verifies seal.** |
| **Generation Invariants** | Distributed across sections. | **Codified into 7 explicit, non-negotiable architectural generation invariants.** |
| **Generation Lifecycle** | Covered primarily through rollover example. | **Formally mapped as a standalone state machine covering initial creation, rolling attachment, handover, resolution, and reopen.** |

---

## 4. Existing Architecture Inspection

1. **Phase 3C-5C Detection Architecture**:
   - `backend/app/detection/engine.py`: Evaluates advisory rules `R-001` through `R-007` against normalized audit events. Emits `AdvisorySignal`.
   - `backend/app/detection/models.py`: Defines `AdvisorySignal` (fields: `signal_id`, `rule_id`, `rule_version`, `severity`, `title`, `description`, `context_dimensions`, `evidence_event_ids`, `emitted_at`).
   - `backend/app/detection/normalizer.py`: Normalizes audit events into canonical dimensions.
   - Operating Mode: Asynchronous, read-only shadow mode.

2. **Core Authentication & RBAC**:
   - `backend/app/core/models.py` (`UserRoleEnum`): Authoritative roles are `SUPER_ADMIN`, `SECURITY_OFFICER`, `AUDITOR`, and `EXAM_AUTHORITY`.
   - `backend/app/modules/auth/service.py` (`ROLE_PERMISSIONS`): Defines granular permissions for each role.

3. **Audit Chain Architecture**:
   - `backend/app/audit/service.py`: Authoritative `AuditService` writing append-only audit rows with Ed25519 payload signatures.
   - `backend/app/audit/sealer.py`: Periodic cryptographic block sealing to AWS S3/KMS.
   - `backend/app/audit/quarantine.py`: Quarantine isolation for corrupted or unparseable audit events.

4. **Cryptographic Infrastructure**:
   - `backend/app/crypto/kms_interface.py`: Defines `KMSInterface` with two concrete implementations:
     - `MockKMS`: Software provider utilizing `AES-256-GCM` for symmetric envelope encryption, `Ed25519PrivateKey`/`Ed25519PublicKey` for cryptographic signing/verification, and HKDF for key derivation.
     - `AWSKMSClient`: Production provider calling standard AWS KMS APIs (`GenerateDataKey`, `Sign`, `Verify`).

---

## 5. 5C → 5D Boundary

The boundary between Detection (5C) and Incident Management (5D) is strictly asynchronous, decoupled, and unidirectional:

```
+─────────────────────────────────────────────────────────────────────────────+
| Phase 3C-5C: Detection & Correlation Engine (SHADOW MODE)                   |
| - Evaluates normalized audit events against rules R-001 .. R-007            |
| - Produces AdvisorySignal (signal_id, canonical_rule_id, dimensions)        |
| - Dispatches to SQS / Celery advisory_signals queue                         |
+─────────────────────────────────────────────────────────────────────────────+
                                       │
                                       │ (AdvisorySignal JSON Payload)
                                       ▼
+─────────────────────────────────────────────────────────────────────────────+
| Phase 3C-5D: Security Incident Management Engine                            |
| - Consumes AdvisorySignal                                                   |
| - Computes Canonical JCS Threat Vector Identity                             |
| - Executes Distributed Advisory Lock Generation Creation Protocol          |
| - Creates or Attaches to SecurityIncident in PostgreSQL                     |
| - Exposes REST APIs for Security Officer Triage & Investigation            |
| - Emits Authoritative Audit Events via AuditService                         |
| - Observational CONTAINED milestone (ZERO autonomous containment)           |
+─────────────────────────────────────────────────────────────────────────────+
                                       │
                                       │ (Read-only Reference Linking)
                                       ▼
+─────────────────────────────────────────────────────────────────────────────+
| Authoritative Audit Log & Evidence Storage (PostgreSQL / S3)                |
+─────────────────────────────────────────────────────────────────────────────+
```

### Invariants:
- 5C produces signals; 5C **never** creates incidents directly.
- 5D consumes signals; 5D **never** re-evaluates raw detection rules or mutates 5C configurations.
- Failure of 5D ingestion never blocks or impacts 5C detection or candidate examination traffic.

---

## 6. Incident Domain Model (`incident_id` vs. `incident_number`)

Phase 3C-5D separates machine-readable identities from human-readable case identifiers:

1. **`incident_id` (Primary Key)**:
   - Type: `UUIDv4`
   - Purpose: Authoritative database primary key, foreign key target, API resource identifier, and distributed tracing handle.
   - Immutability: Permanently invariant once generated.

2. **`incident_number` (Human Reference)**:
   - Type: `VARCHAR(32)`
   - Format: `INC-YYYYMMDD-XXXXX` (e.g., `INC-20260916-00042`)
   - Purpose: Human-readable tracking identifier used in analyst dashboards, support communications, and audit reports.
   - Generation: Generated deterministically via a dedicated PostgreSQL sequence (`incident_number_seq`) reset annually.

---

## 7. Formally Canonical Threat Vector Identity (RFC 8785 JCS)

Rev-06 replaces delimiter-based concatenation with **RFC 8785 JSON Canonicalization Scheme (JCS)**, providing a mathematically unambiguous, standardized byte-level serialization.

### 7.1 Mathematical Definition of Threat Vector Identity
$$\text{threat\_vector\_key} = \text{SHA-256}(\text{JCS}(\mathcal{D}))$$
Where $\mathcal{D}$ is the normalized canonical document containing exactly four top-level keys:
```json
{
  "canonical_rule_id": "R-003",
  "dimensions": {
    "candidate_id": "CAND-001",
    "node_id": "NODE-042"
  },
  "exam_id": "EXAM-99",
  "policy_version": "v1"
}
```

### 7.2 RFC 8785 JSON Canonicalization Scheme (JCS) Algorithm
1. **UTF-8 Encoding**: The canonical string is encoded strictly into UTF-8 bytes.
2. **Deterministic Key Sorting**: All JSON object keys (at root and within nested dictionaries) are sorted lexicographically by UTF-16 code units (identical to standard ASCII/Unicode codepoint sorting).
3. **Zero Extraneous Whitespace**: No whitespace characters (spaces, tabs, newlines) are permitted outside string literals. Delimiters are strictly `:` and `,`.
4. **Unicode Normalization**: All Unicode string values are normalized using **Unicode Normalization Form C (NFC)** prior to serialization.
5. **Number Representation**: Floats and integers (if present) follow strict IEEE 754 JCS formatting without trailing zeros or exponential representations unless standardized.
6. **No Escaped Slashes**: Solidus characters (`/`) are not escaped.

### 7.3 Canonical Normalization Rules
1. **`canonical_rule_id`**: Trimmed, uppercase ASCII string (e.g., `"R-003"`). Revision or patch version suffixes (e.g., `".v1"`, `".v2"`) are stripped.
2. **`dimensions` Dictionary**:
   - Keys: Trimmed, lowercase ASCII strings (e.g., `"candidate_id"`, `"node_id"`). Must match regex `^[a-z][a-z0-9_]*$`.
   - Values: Trimmed, normalized according to semantic type:
     - UUIDs: Lowercase hexadecimal with standard hyphens (e.g., `"123e4567-e89b-12d3-a456-426614174000"`).
     - IP Addresses: Canonical expanded notation via `ipaddress.ip_address(val).exploded` (e.g., IPv4 `"192.168.1.1"`, IPv6 `"2001:0db8:85a3:0000:0000:8a2e:0370:7334"`).
     - Identifiers (Nodes, Workstations, Accounts): Trimmed, uppercase ASCII (e.g., `"NODE-042"`, `"CAND-001"`).
   - Rejection of Duplicates: Duplicate dimension keys in an incoming signal payload cause immediate validation failure (HTTP 422).
   - Empty/Null Rejection: Dimension keys with null, empty, or whitespace-only values are strictly stripped prior to canonicalization. A dimension set cannot be empty.
3. **`exam_id`**:
   - Exam-scoped events: Lowercase UUID string (e.g., `"550e8400-e29b-41d4-a716-446655440000"`) or canonical string identifier (e.g., `"EXAM-99"`).
   - Cross-exam / Infrastructure events: Literal string `"GLOBAL"`.
4. **`policy_version`**: Trimmed, lowercase string representing the major rule engine policy version (e.g., `"v1"`).

### 7.4 Multi-Dimension Support & Deterministic Ordering
When a detection rule evaluates multiple contextual entities (e.g., Candidate $C$ on Workstation $N$), JCS guarantees that the resulting JSON keys are sorted identically regardless of runtime dictionary ordering:
- Incoming Dict: `{"node_id": "NODE-042", "candidate_id": "CAND-001"}`
- JCS Canonical Output: `{"candidate_id":"CAND-001","node_id":"NODE-042"}`

### 7.5 Worked Multi-Dimension Example
Given:
- `canonical_rule_id` = `"R-003"`
- `dimensions` = `{"candidate_id": "CAND-001", "node_id": "NODE-042"}`
- `exam_id` = `"EXAM-99"`
- `policy_version` = `"v1"`

**Step 1: Canonical Document Construction**:
```json
{"canonical_rule_id":"R-003","dimensions":{"candidate_id":"CAND-001","node_id":"NODE-042"},"exam_id":"EXAM-99","policy_version":"v1"}
```

**Step 2: UTF-8 Byte Sequence**:
```text
7b 22 63 61 6e 6f 6e 69 63 61 6c 5f 72 75 6c 65 5f 69 64 22 3a 22 52 2d 30 30 33 22 2c 22 64 69 6d 65 6e 73 69 6f 6e 73 22 3a 7b 22 63 61 6e 64 69 64 61 74 65 5f 69 64 22 3a 22 43 41 4e 44 2d 30 30 31 22 2c 22 6e 6f 64 65 5f 69 64 22 3a 22 4e 4f 44 45 2d 30 34 32 22 7d 2c 22 65 78 61 6d 5f 69 64 22 3a 22 45 58 41 4d 2d 39 39 22 2c 22 70 6f 6c 69 63 79 5f 76 65 72 73 69 6f 6e 22 3a 22 76 31 22 7d
```

**Step 3: SHA-256 Digest**:
$$\text{threat\_vector\_key} = \text{SHA-256}(\text{bytes}) = \text{"c89324c1851e44f07a76059d646738914b14d86b7724a87265b746ea5f72cb9a"}$$

### 7.6 Strict Time-Independence & Redaction Invariants
- **ZERO Time Elements**: `threat_vector_key` contains **no** clock-hour, epoch, timestamp, window, or generation data.
- **Strict Content Redaction**: The key **MUST NOT** contain question text, answer keys, candidate responses, passwords, session tokens, JWTs, DEKs, KEKs, or secrets.

---

## 8. Stable Threat Identity vs. Correlation Generation

Phase 3C-5D separates the invariant threat vector from the temporal incident generation:

```
+─────────────────────────────────────────────────────────────────────────────+
|                     THREAT-VECTOR IDENTITY (STABLE & INVARIANT)             |
|  threat_vector_key = SHA-256(JCS({rule, dimensions, exam, policy}))        |
+─────────────────────────────────────────────────────────────────────────────+
                                       │
                                       │ 1-to-Many Temporal Lineage
                                       ▼
+──────────────────────────+   +──────────────────────────+   +───────────────+
| Generation 1             |   | Generation 2             |   | Generation 3  |
| - incident_id: UUID_1    |   | - incident_id: UUID_2    |   | - incident_id:|
| - generation: 1          |──>| - generation: 2          |──>|   UUID_3      |
| - correlation: CLOSED    |   | - correlation: CLOSED    |   | - generation:3|
| - status: RESOLVED       |   | - status: INVESTIGATING  |   | - correlation:|
|                          |   |                          |   |   OPEN        |
+──────────────────────────+   +──────────────────────────+   +───────────────+
```

### The Seven Generation Invariants
1. **Invariant G-1 (Singular Active Generation)**: For every `threat_vector_key`, at most **one** generation may have `correlation_status = 'OPEN'` at any instant across the entire database cluster.
2. **Invariant G-2 (Generation Uniqueness)**: Every generation within a `threat_vector_key` possesses exactly one unique, immutable positive integer `generation` ($1, 2, 3, \dots$).
3. **Invariant G-3 (Strictly Increasing Monotonicity)**: Successive generations for a given `threat_vector_key` are strictly monotonically increasing without gaps or regression: $\text{Gen}_{N+1} = \text{Gen}_N + 1$.
4. **Invariant G-4 (Serialized Generation Creation)**: A new generation may only be created through an atomic, transaction-serialized generation-creation protocol. Uncoordinated parallel creation is mathematically prevented.
5. **Invariant G-5 (Zero Signal Loss)**: No legitimate advisory signal may be dropped, ignored, or rejected due to a generation rollover race or creation conflict.
6. **Invariant G-6 (Identity Purity)**: The stable `threat_vector_key` **MUST NOT** contain `generation` or any temporal parameter.
7. **Invariant G-7 (Generation Separation)**: The `generation` number **MUST NOT** be used as a replacement for the stable `threat_vector_key`. Grouping, historical aggregation, and cross-exam analytics must always key on `threat_vector_key`.

---

## 9. Complete Generation Lifecycle & State Machine

The generation lifecycle manages the opening, active signal reception, inactivity rollover, and administrative closure of correlation windows:

```
                         Incoming Advisory Signal
                                    │
                                    ▼
                     +─────────────────────────────+
                     | Does an OPEN Generation     |
                     | exist for threat_vector_key?|
                     +─────────────────────────────+
                                    │
                    NO              │             YES
          ┌─────────────────────────┴─────────────────────────┐
          ▼                                                   ▼
+─────────────────────────────+                     +─────────────────────────────+
| PROTOCOL: Create Next Gen   |                     | Check Inactivity:           |
| (Advisory Lock Protocol)    |                     | (t_signal - t_latest)<=3600?|
+─────────────────────────────+                     +─────────────────────────────+
          │                                                   │
          │                                        YES        │        NO
          │                                  ┌────────────────┴────────────────┐
          ▼                                  ▼                                 ▼
+─────────────────────────────+   +─────────────────────────────+   +─────────────────────────────+
| Set generation = MAX + 1    |   | ATTACH EVIDENCE TO OPEN GEN |   | ATOMIC ROLLOVER:            |
| correlation_status = 'OPEN' |   | - Touch latest_signal_at    |   | 1. Update Gen_N to CLOSED   |
| status = 'TRIAGE'           |   | - Insert evidence link      |   | 2. Insert Gen_(N+1) as OPEN |
+─────────────────────────────+   | - Emit audit event          |   | 3. Attach signal to Gen_N+1 |
                                  +─────────────────────────────+   +─────────────────────────────+
                                                 │
                                                 ▼
                                  +─────────────────────────────+
                                  | Human Lifecycle Event:      |
                                  | Case marked RESOLVED/CLOSED/|
                                  | FALSE_POSITIVE/DUPLICATE    |
                                  +─────────────────────────────+
                                                 │
                                                 ▼
                                  +─────────────────────────────+
                                  | correlation_status = CLOSED |
                                  | (Active window concludes;   |
                                  | historical record preserved)|
                                  +─────────────────────────────+
```

### Lifecycle Rules:
1. **First Signal Ingestion**: When no generation exists in the database for `threat_vector_key`, the engine creates Generation 1 with `correlation_status = 'OPEN'`, `status = 'TRIAGE'`, and `preceding_incident_id = NULL`.
2. **Rolling Signal Attachment ($\le 3600\text{s}$)**: Incoming signals arriving within 3600 seconds of `latest_signal_at` attach to the currently open generation, updating `latest_signal_at = MAX(latest_signal_at, t_signal)`.
3. **Inactivity Rollover ($> 3600\text{s}$)**: When a signal arrives after $>3600\text{s}$ of inactivity, the open generation's window is closed (`correlation_status = 'CLOSED'`), and Generation $N+1$ is opened with `preceding_incident_id = Gen_N.id`.
4. **Human Resolution Closes Window**: When an analyst transitions an incident to `RESOLVED`, `CLOSED`, `FALSE_POSITIVE`, or `DUPLICATE`, the system automatically transitions `correlation_status` to `'CLOSED'`.
5. **Reopening Does NOT Reopen Correlation**: Transitioning a resolved case to `INVESTIGATING` via `INCIDENT_REOPENED` updates the human investigation lifecycle **only**. It **does NOT** reopen the correlation window. Any subsequent signal arriving for that vector will initiate a new generation, preventing new signals from corrupting previously closed investigative scopes.
6. **Permanent Queryability**: All historical generations remain permanently indexed, queryable, and linked via `preceding_incident_id`.

---

## 10. Distributed Concurrency Protocol for Generation Creation

### 10.1 The Concurrency Challenge: No-OPEN-Generation Case
Consider threat vector $K$:
- Generation 1 = `CLOSED`
- Generation 2 = `CLOSED`
- Generation 3 = `CLOSED`
- Currently **NO** generation has `correlation_status = 'OPEN'`.

Worker A and Worker B simultaneously receive new qualifying signals for $K$ at $T = 15:00:00$. If both workers query `SELECT MAX(generation)` naively, both read `3`, and both attempt to insert Generation 4. Without a serialized protocol, one succeeds while the other fails with a `UniqueViolation` and risks dropping the signal or corrupting the generation sequence.

### 10.2 PostgreSQL Transactional Advisory Locking Protocol
To serialize generation creation without table-level locks or distributed lock managers (e.g. Redis), Phase 3C-5D utilizes **PostgreSQL Transaction-Scoped Advisory Locks** (`pg_advisory_xact_lock`):

```sql
-- Derive 64-bit integer lock key from the first 8 bytes of the SHA-256 threat_vector_key
SELECT pg_advisory_xact_lock(('x' || substr(:threat_vector_key, 1, 16))::bit(64)::bigint);
```

#### Properties of `pg_advisory_xact_lock`:
1. **Scope**: Scoped strictly to the active database transaction. Automatically and unconditionally released upon `COMMIT` or `ROLLBACK` (including worker crashes or network timeouts). Zero dangling locks.
2. **Granularity**: Keys are hashed to 64-bit integers. Collisions between distinct threat vectors are astronomically rare ($\approx 1 \text{ in } 2^{64}$) and at worst introduce momentary, harmless serialization between unrelated keys.
3. **Zero Contention with Normal Reads**: Advisory locks do not lock rows or tables; normal reads on `security_incidents` proceed at full speed.

### 10.3 Full Handshake Flow: Worker A & Worker B Race on Generation 4

```
Worker A (Pod 1)                                       Worker B (Pod 2)
      │                                                      │
      │ Receives Signal A (Vector K)                         │ Receives Signal B (Vector K)
      │ BEGIN TRANSACTION                                    │ BEGIN TRANSACTION
      │                                                      │
      │ SELECT pg_advisory_xact_lock(K_hash);                │ SELECT pg_advisory_xact_lock(K_hash);
      ▼ [ACQUIRES LOCK IMMEDIATELY]                          │
  Worker A proceeds                                          │ [BLOCKS WAITING FOR LOCK]
      │                                                      │
      │ -- Double-Check for Open Generation                  │
      │ SELECT id, generation FROM security_incidents        │
      │ WHERE threat_vector_key = K                          │
      │   AND correlation_status = 'OPEN';                   │
      │ (Result: None found)                                 │
      │                                                      │
      │ -- Derive Next Generation Monotonically              │
      │ SELECT COALESCE(MAX(generation), 0), id              │
      │ FROM security_incidents                              │
      │ WHERE threat_vector_key = K                          │
      │ GROUP BY id ORDER BY generation DESC LIMIT 1;        │
      │ (Result: Max = 3, Preceding_ID = UUID_3)             │
      │                                                      │
      │ -- Insert Generation 4                               │
      │ INSERT INTO security_incidents (                     │
      │   threat_vector_key, generation,                     │
      │   correlation_status, status,                        │
      │   preceding_incident_id, latest_signal_at            │
      │ ) VALUES (K, 4, 'OPEN', 'TRIAGE', UUID_3, 15:00:00); │
      │                                                      │
      │ -- Attach Signal A                                   │
      │ INSERT INTO incident_evidence_links (...);           │
      │                                                      │
      │ COMMIT; ─────────────────────────────────────────────┤
      ▼ [LOCK AUTOMATICALLY RELEASED]                        ▼ [ACQUIRES LOCK]
  Worker A Finished                                      Worker B Unblocks
                                                             │
                                                             │ -- Double-Check for Open Generation
                                                             │ SELECT id, generation FROM security_incidents
                                                             │ WHERE threat_vector_key = K
                                                             │   AND correlation_status = 'OPEN';
                                                             │ (Result: FOUND Generation 4, UUID_4!)
                                                             │
                                                             │ -- Evaluate Inactivity Window
                                                             │ Delta_t = 15:00:00 - 15:00:00 = 0s <= 3600s
                                                             │
                                                             │ -- Attach Signal B to Generation 4
                                                             │ INSERT INTO incident_evidence_links (
                                                             │   incident_id = UUID_4, ...);
                                                             │
                                                             │ UPDATE security_incidents
                                                             │ SET latest_signal_at = 15:00:00,
                                                             │     updated_at = NOW()
                                                             │ WHERE id = UUID_4;
                                                             │
                                                             │ COMMIT;
                                                             ▼ [LOCK RELEASED]
                                                         Worker B Finished (Zero Loss, Gen 4 Shared)
```

### 10.4 Normal Rollover Race (Active OPEN Generation Rollover)
When Generation $N$ is currently `'OPEN'` and two workers arrive after $>3600\text{s}$ inactivity:
1. Both workers execute `pg_advisory_xact_lock(K_hash)`.
2. Worker 1 acquires lock: checks open generation, sees inactivity $>3600\text{s}$, sets Generation $N$ to `'CLOSED'`, creates Generation $N+1$ as `'OPEN'`, attaches Signal 1, and commits.
3. Worker 2 unblocks: checks open generation, finds newly created Generation $N+1$ (`latest_signal_at` = current time), attaches Signal 2 to Generation $N+1$, and commits safely.

### 10.5 Crash Recovery, Retries, and Poison Handling
- **Worker Crash During Transaction**: If a worker crashes, is SIGKILLed, or loses database connectivity while holding an advisory lock, PostgreSQL's transaction manager immediately aborts the transaction, rolls back all changes, and **automatically releases the advisory lock**.
- **Retry Semantics**: The SQS visibility timeout will expire, delivering the unacknowledged signal message to another worker. The next worker will acquire the advisory lock cleanly and process the signal.
- **Poison Signals**: If a malformed signal causes an unhandled crash 3 consecutive times, SQS dead-letter queue (DLQ) routing isolates the message for offline quarantine.

---

## 11. Human Investigation Lifecycle & State Machine

Phase 3C-5D implements a clean, deterministic 7-state human lifecycle. In accordance with architectural review findings, **`REOPENED` is modeled strictly as an auditable transition/action**, rather than a persistent lifecycle state.

### State Diagram

```
                        +--------------------+
                        |       TRIAGE       |<────────────────────────────────+
                        +--------------------+                                 │
                          │        │       │                                   │
             Confirm Valid│        │       │ Mark False Positive               │
                          ▼        │       ▼                                   │
        +--------------------+     │     +--------------------+                │
        |   INVESTIGATING    |     │     |   FALSE_POSITIVE   |                │
        +--------------------+     │     +--------------------+                │
          │        │       │       │                                           │
          │        │       │Mark   │ Mark Duplicate                            │
          │        │       │Dup    ▼                                           │
          │        │       │     +--------------------+                        │
          │        │       +---->|     DUPLICATE      |                        │
          │        │             +--------------------+                        │
          │        │                                                           │
          │        │ Containment Result Verified (Observational)               │
          │        ▼                                                           │
          │      +--------------------+                                        │
          │      |     CONTAINED      |                                        │
          │      +--------------------+                                        │
          │        │                                                           │
          │        │ Resolution Complete                                       │
          ▼        ▼                                                           │
        +--------------------+                                                 │
        |      RESOLVED      |                                                 │
        +--------------------+                                                 │
          │        │                                                           │
          │        │ Administrative Supervisory Review                         │
          │        ▼                                                           │
          │      +--------------------+                                        │
          │      |       CLOSED       |                                        │
          │      +--------------------+                                        │
          │        │                                                           │
          │        │ INCIDENT_REOPENED (Audited Action)                        │
          └────────┴───────────────────────────────────────────────────────────┘
```

### The 7 Persistent States
1. **`TRIAGE`**: Initial state upon creation. Signal is unverified. Requires analyst review within SLA.
2. **`INVESTIGATING`**: Case confirmed as a valid security concern. Active investigation underway.
3. **`CONTAINED`**: **Observational milestone**. Recorded only when authorized external containment (e.g. Phase 3C-5E) has taken place and independently verified against the sealed audit chain.
4. **`RESOLVED`**: Technical remediation and root cause analysis completed by the assigned analyst. Transitioning to `RESOLVED` automatically sets `correlation_status = 'CLOSED'`.
5. **`CLOSED`**: Administrative sign-off completed by a supervisory authority (`SECURITY_OFFICER` or `SUPER_ADMIN`). **CLOSED represents administrative closure, never database deletion.**
6. **`FALSE_POSITIVE`**: Terminal evaluation determining the signal was benign. Automatically sets `correlation_status = 'CLOSED'`.
7. **`DUPLICATE`**: Terminal consolidation state indicating the incident represents an event stream tracked by an authoritative parent incident. Requires `duplicate_of_incident_id`. Automatically sets `correlation_status = 'CLOSED'`.

---

## 12. State Transition Matrix & Authority

| From State | To State | Action / Trigger | Authorized Role | Preconditions & Requirements | Required Audit Event |
| :--- | :--- | :--- | :--- | :--- | :--- |
| *(None)* | `TRIAGE` | `CREATE_INCIDENT` | System (Worker) | Qualifying advisory signal received | `INCIDENT_CREATED` |
| `TRIAGE` | `INVESTIGATING` | `START_INVESTIGATION` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Analyst assigned; initial assessment documented | `INCIDENT_STATUS_CHANGED` |
| `TRIAGE` | `FALSE_POSITIVE` | `MARK_FALSE_POSITIVE` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Justification ($\ge 20$ chars); sets `correlation_status = 'CLOSED'` | `INCIDENT_STATUS_CHANGED` |
| `TRIAGE` | `DUPLICATE` | `MARK_DUPLICATE` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Valid `duplicate_of_incident_id`; acyclic check passed; sets `correlation_status = 'CLOSED'` | `INCIDENT_STATUS_CHANGED` |
| `INVESTIGATING`| `CONTAINED` | `RECORD_CONTAINMENT` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Dual-phase verification passes against authoritative audit log | `INCIDENT_STATUS_CHANGED` |
| `INVESTIGATING`| `RESOLVED` | `RESOLVE_INCIDENT` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Resolution summary and category; sets `correlation_status = 'CLOSED'` | `INCIDENT_STATUS_CHANGED` |
| `INVESTIGATING`| `FALSE_POSITIVE` | `MARK_FALSE_POSITIVE` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Justification ($\ge 20$ chars); sets `correlation_status = 'CLOSED'` | `INCIDENT_STATUS_CHANGED` |
| `INVESTIGATING`| `DUPLICATE` | `MARK_DUPLICATE` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Valid `duplicate_of_incident_id`; acyclic check passed; sets `correlation_status = 'CLOSED'` | `INCIDENT_STATUS_CHANGED` |
| `CONTAINED` | `RESOLVED` | `RESOLVE_INCIDENT` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Resolution summary and category; sets `correlation_status = 'CLOSED'` | `INCIDENT_STATUS_CHANGED` |
| `RESOLVED` | `CLOSED` | `CLOSE_INCIDENT` | `SUPER_ADMIN`, `SECURITY_OFFICER` | Supervisory review completed; administrative sign-off | `INCIDENT_CLOSED` |
| `RESOLVED` | `INVESTIGATING`| `INCIDENT_REOPENED` | `SECURITY_OFFICER`, `SUPER_ADMIN` | New evidence identified; mandatory justification | `INCIDENT_REOPENED` |
| `CLOSED` | `INVESTIGATING`| `INCIDENT_REOPENED` | `SUPER_ADMIN` | Supervisory authorization + mandatory audit justification | `INCIDENT_REOPENED` |

---

## 13. Observational `CONTAINED` State & Verification Timing

Phase 3C-5D is **STRICTLY OBSERVATIONAL**. Phase 3C-5D contains **zero** active mitigation, enforcement, or containment logic.

### 13.1 Strict Observational Milestone (Zero 5D Containment)
5D does **NOT**:
- Revoke candidate sessions or tokens
- Block candidates or test center accounts
- Block devices or IP addresses
- Quarantine questions or question banks
- Rotate cryptographic keys
- Cancel or suspend examinations
- Execute emergency containment scripts

*All active containment capabilities belong strictly to Phase 3C-5E.*

### 13.2 Dual-Phase Verification Timing (Immediate vs. Sealed Confirmation)
In production, containment actions are executed in real-time (e.g. within seconds by Phase 3C-5E), whereas audit epoch sealing to S3/KMS is a periodic batch process running every 5 to 15 minutes. Requiring an incident to wait for sealed epoch confirmation before entering `CONTAINED` would create unacceptable operational delay.

Phase 3C-5D establishes a **Dual-Phase Verification Protocol**:
1. **Phase 1: Immediate Cryptographic Verification (Authorizes `CONTAINED`)**:
   When an analyst or automated webhook submits the containment reference payload:
   - 5D queries `AuditService` for `audit_event_reference`.
   - 5D verifies that the audit record exists in PostgreSQL `audit_logs`.
   - 5D verifies the Ed25519 cryptographic payload signature using the KMS public verification key.
   - 5D verifies that `event_type` is `CONTAINMENT_EXECUTED` and that payload fields (`containment_reference_id`, `containment_mechanism`, `authorization_principal`) match the transition request.
   - **Upon passing Phase 1, the incident transitions immediately to `CONTAINED`**, recording `seal_verification_status = 'PENDING_SEAL'`. Operational agility is fully preserved.
2. **Phase 2: Asynchronous Seal Reconciliation (Forensic Confirmation)**:
   - When the periodic audit sealer seals the epoch containing that audit event, a background reconciliation task confirms that the event is anchored in the sealed Merkle tree on S3.
   - The task updates the incident: `seal_verification_status = 'SEALED_VERIFIED'`, persisting `sealed_epoch_id` and `seal_block_hash`.

### 13.3 Failure & Retry Semantics Matrix
| Verification Failure Condition | System Action | HTTP Status | Retry / Remediation Semantics |
| :--- | :--- | :--- | :--- |
| **Audit Event Missing** | Transition rejected. State unchanged. | `HTTP 422` | Audit write may be lagging. Client retries with exponential backoff. |
| **Audit Signature Invalid** | Transition rejected. Security alert raised. | `HTTP 403` | Potential database tampering. Audit quarantine triggered immediately. |
| **Event Type Mismatch** | Transition rejected. | `HTTP 422` | Referenced event is not a containment event. Permanent client error. |
| **Principal Mismatch** | Transition rejected. | `HTTP 422` | Ticket authorizer does not match audit actor. Permanent client error. |
| **Reference ID Mismatch** | Transition rejected. | `HTTP 422` | Ticket execution ID mismatch. Permanent client error. |
| **Event Exists but Unsealed** | **Transition APPROVED to `CONTAINED`**. | `HTTP 200` | Sets `seal_verification_status = 'PENDING_SEAL'`. Sealed asynchronously. |
| **AuditService Unavailable** | Transaction rolled back. State unchanged. | `HTTP 503` | Returns `Retry-After: 5`. Client retries when database recovers. |

### 13.4 Schema of Containment Evidence
Persisted in `security_incidents`:
- `containment_reference_id` (`VARCHAR(128)` NOT NULL on CONTAINED)
- `authorization_principal` (`VARCHAR(128)` NOT NULL on CONTAINED)
- `containment_timestamp` (`TIMESTAMPTZ` NOT NULL on CONTAINED)
- `containment_mechanism` (`VARCHAR(64)` NOT NULL on CONTAINED)
- `audit_event_reference` (`VARCHAR(128)` NOT NULL on CONTAINED)
- `seal_verification_status` (`VARCHAR(32)` NOT NULL DEFAULT 'UNCONTAINED') -- Values: `UNCONTAINED`, `PENDING_SEAL`, `SEALED_VERIFIED`
- `sealed_epoch_id` (`UUID` NULL)
- `seal_block_hash` (`CHAR(64)` NULL)

---

## 14. Evidence Reference Architecture

Phase 3C-5D adheres strictly to:
$$\text{Evidence Reference} \neq \text{Evidence Payload}$$

Incidents do not store raw event logs, HTTP bodies, or candidate exam papers. Storing raw data in incident tables creates data duplication, cache leakage, and inadvertent exposure of sensitive exam materials.

### `incident_evidence_links` Table
5D stores cryptographically verifiable references into the authoritative audit chain:

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | UUID | PRIMARY KEY | Unique link identifier |
| `incident_id` | UUID | NOT NULL, FK `security_incidents(id)` | Parent incident case |
| `evidence_type` | VARCHAR(32) | NOT NULL | `AUDIT_EVENT`, `DETECTION_SIGNAL`, `CLOUDTRAIL_EVENT` |
| `evidence_reference_id` | VARCHAR(128) | NOT NULL | UUID or sequence ID of the target audit event |
| `evidence_hash` | CHAR(64) | NOT NULL | SHA-256 hash of the target record at time of link |
| `attached_by` | UUID | NOT NULL, FK `users(id)` | System worker UUID or analyst UUID |
| `attached_at` | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | Timestamp of attachment |

- **Immutability**: `incident_evidence_links` has **zero** update or delete endpoints.
- **Integrity Verification**: `evidence_hash` enables analysts to verify that the underlying audit record in PostgreSQL or S3 has not been tampered with since attachment.

---

## 15. Evidence Access Control

1. **Metadata vs. Payload Separation**: Analysts with incident read access can view evidence metadata (`evidence_type`, `evidence_reference_id`, `attached_at`).
2. **Payload Resolution**: Resolving the raw audit payload requires fetching the record from `AuditService`. The analyst must possess explicit read permissions for the specific audit domain (`audit:read`).
3. **Candidate PII Masking**: Raw audit payloads containing candidate PII are dynamically masked at the API gateway layer unless the analyst holds `SUPER_ADMIN` or `EXAM_AUTHORITY` with an active, audited justification ticket.
4. **Examination Content Redaction**: Question text, options, and answer keys are never stored in the audit chain or incident tables.

---

## 16. RBAC Model & Repository Role Alignment

Phase 3C-5D introduces **zero new roles**. It aligns strictly with the existing `UserRoleEnum` in `backend/app/core/models.py`:

| Role Enum | 5D Incident Management Permissions |
| :--- | :--- |
| **`SUPER_ADMIN`** | Full incident management authority: view, assign, triage, investigate, contain (record), resolve, close, reopen, and perform forensic export. |
| **`SECURITY_OFFICER`** | Primary operational authority: view, assign, triage, investigate, contain (record), resolve, reopen, and add comments/evidence. |
| **`AUDITOR`** | Strictly read-only compliance authority: view all incidents, inspect timelines, view audit links, and verify cryptographic evidence chains. Cannot mutate state. |
| **`EXAM_AUTHORITY`** | Read-only executive oversight: view aggregate incident metrics, view high-severity incident summaries affecting exam delivery. Cannot view raw telemetry or mutate state. |
| *Candidate / Proctor* | **Zero Access**: Incident management APIs are completely inaccessible to examinees, test proctors, and public endpoints. |

---

## 17. Analyst Assignment

- **Assignment Target**: Incidents can be assigned to any active user possessing `SECURITY_OFFICER` or `SUPER_ADMIN`.
- **Concurrency & Self-Assignment**: Analysts can assign incidents to themselves or reassign them to team members.
- **Audit Requirement**: Every assignment updates `assigned_to`, increments `version`, and logs an immutable `INCIDENT_ASSIGNED` event recording previous analyst, new analyst, and authorizing user.
- **Unassigned Triage**: New incidents created from advisory signals initialize with `assigned_to = NULL`.

---

## 18. 6-Layer Defense-in-Depth Comment Confidentiality Model

1. **Layer 1: Structural Plaintext Storage**: `comment_text` stores strictly unformatted, sanitized plaintext. HTML, Markdown rendering, scripts, and executable tags are stripped before persistence, preventing stored XSS.
2. **Layer 2: Hard Character Limits**: Comment length is constrained to $2,000$ characters maximum, preventing payload injection, buffer abuse, and database bloat.
3. **Layer 3: Pre-Commit Secret & Exam Screening**: Automated regex filter screens submitted comment text prior to database commit. Comments matching patterns for JWTs, private keys, AWS access keys, or question identifiers are rejected with HTTP 422.
4. **Layer 4: Append-Only Immutability**: `incident_comments` allows **zero updates and zero deletions**. Corrective notes must be added as new append-only comments.
5. **Layer 5: Sealed PostgreSQL Audit Integration**: Every comment creation emits an `INCIDENT_COMMENT_ADDED` audit event, capturing comment hash, author UUID, and timestamp in the sealed Ed25519 audit chain.
6. **Layer 6: Read-Side Role Masking**: When comments are fetched via API, internal system flags or sensitive investigation markers are dynamically redacted based on the requesting user's RBAC role.

---

## 19. Concurrency Strategy & OCC (`version` Column)

To prevent lost updates and race conditions in a multi-analyst environment, Phase 3C-5D implements **Optimistic Concurrency Control (OCC)**:
1. **`version` Column**: Every row in `security_incidents` possesses an integer `version` column, initialized to `1`.
2. **Atomic Update Enforcement**:
   ```sql
   UPDATE security_incidents
   SET status = :new_status,
       version = version + 1,
       updated_at = NOW()
   WHERE id = :incident_id AND version = :expected_version;
   ```
3. **HTTP 409 Conflict**: If the query updates 0 rows, another analyst or worker updated the record concurrently. The API aborts the transaction and returns `HTTP 409 Conflict`, requiring the client to refresh.

---

## 20. Severity Model

| Severity | Definition | Target Triage SLA | Target Resolution SLA |
| :--- | :--- | :--- | :--- |
| **`CRITICAL`** | Direct compromise of examination integrity, active key compromise, or large-scale candidate disruption. | 15 Minutes | 2 Hours |
| **`HIGH`** | Targeted exam tampering attempt, unauthorized administrative access, or systemic node failures. | 30 Minutes | 6 Hours |
| **`MEDIUM`** | Repeated biometric/liveness anomalies, suspicious multi-session attempts, or abnormal API velocity. | 2 Hours | 24 Hours |
| **`LOW`** | Isolated client network glitch, non-critical workstation drift, or minor configuration anomaly. | 8 Hours | 72 Hours |
| **`INFO`** | Observational telemetry notice, routine security drill marker, or scheduled maintenance notice. | 24 Hours | Best Effort |

---

## 21. Incident Types Taxonomy

- `INTEGRITY_TAMPERING`: Unauthorized attempt to alter candidate responses, exam timers, or audit logs.
- `AUTHENTICATION_ANOMALY`: Credential stuffing, simultaneous multi-device logins, or token hijacking.
- `EXAM_LEAK_ATTEMPT`: Suspicious workstation screen scraping, rapid question navigation, or clipboard scraping.
- `INFRASTRUCTURE_ATTACK`: Network flood, unauthorized API probing, KMS request surge, or container escape attempt.
- `WORKSTATION_TAMPERING`: Secure browser bypass, VM detection trigger, peripheral injection, or secondary display.
- `AUDIT_FAILURE`: Cryptographic verification mismatch, sealer failure, or quarantine threshold breach.

---

## 22. Incident Timeline

The timeline provides an immutable, chronological reconstruction synthesized dynamically from three authoritative sources:
1. **Linked Advisory Signals**: Historical signals linked via `incident_evidence_links`.
2. **Audit Log Events**: State transitions, assignments, re-openings, and containment records emitted by `AuditService`.
3. **Analyst Comments**: Append-only investigative notes from `incident_comments`.

Timelines are queried chronologically by `timestamp ASC` with category filtering.

---

## 23. Audit Integration (Authoritative AuditService)

Phase 3C-5D introduces **zero secondary audit tables**. All incident management events are emitted directly to the authoritative `AuditService` (`backend/app/audit/service.py`):

```python
await audit_service.log_security_event(
    event_type="INCIDENT_STATUS_CHANGED",
    actor_id=str(current_user.id),
    resource_id=str(incident.id),
    details={
        "incident_number": incident.incident_number,
        "threat_vector_key": incident.threat_vector_key,
        "generation": incident.generation,
        "old_status": old_status,
        "new_status": new_status,
        "version": incident.version,
        "justification": justification_text
    }
)
```

### Audited 5D Event Types:
- `INCIDENT_CREATED`: Ingestion of initial signal; generation initialized.
- `INCIDENT_EVIDENCE_ATTACHED`: Correlated signal linked within rolling window.
- `INCIDENT_CORRELATION_WINDOW_CLOSED`: Inactivity timeout expired; generation finalized.
- `INCIDENT_STATUS_CHANGED`: Lifecycle state transition executed.
- `INCIDENT_ASSIGNED`: Analyst ownership assigned or transferred.
- `INCIDENT_COMMENT_ADDED`: Investigative note appended.
- `INCIDENT_REOPENED`: Terminal case reopened with supervisory justification.
- `INCIDENT_CLOSED`: Administrative closure completed.

---

## 24. Database Schema Proposal (Reflecting Rev-06 JCS Keys, Generation Lineage, and Seal Status)

```sql
-- 1. Incidents Table
CREATE TABLE security_incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_number VARCHAR(32) UNIQUE NOT NULL,
    threat_vector_key CHAR(64) NOT NULL, -- SHA-256 of RFC 8785 JCS document
    generation INTEGER NOT NULL DEFAULT 1, -- Episode / correlation generation counter
    correlation_status VARCHAR(16) NOT NULL DEFAULT 'OPEN', -- 'OPEN' vs 'CLOSED'
    preceding_incident_id UUID NULL REFERENCES security_incidents(id) ON DELETE RESTRICT,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    incident_type VARCHAR(64) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'TRIAGE', -- Human lifecycle: TRIAGE, INVESTIGATING, etc.
    rule_id VARCHAR(64) NOT NULL,
    canonical_rule_id VARCHAR(64) NOT NULL,
    policy_version VARCHAR(32) NOT NULL DEFAULT 'v1',
    dimensions_json JSONB NOT NULL, -- Canonical JCS dimension dictionary
    exam_id VARCHAR(64) NOT NULL, -- Exam UUID or 'GLOBAL'
    assigned_to UUID NULL REFERENCES users(id),
    duplicate_of_incident_id UUID NULL REFERENCES security_incidents(id) ON DELETE RESTRICT,
    first_signal_at TIMESTAMPTZ NOT NULL,
    latest_signal_at TIMESTAMPTZ NOT NULL,
    containment_reference_id VARCHAR(128) NULL,
    authorization_principal VARCHAR(128) NULL,
    containment_timestamp TIMESTAMPTZ NULL,
    containment_mechanism VARCHAR(64) NULL,
    audit_event_reference VARCHAR(128) NULL,
    seal_verification_status VARCHAR(32) NOT NULL DEFAULT 'UNCONTAINED',
    sealed_epoch_id UUID NULL,
    seal_block_hash CHAR(64) NULL,
    resolution_summary TEXT NULL,
    resolution_category VARCHAR(64) NULL,
    version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_threat_vector_generation UNIQUE (threat_vector_key, generation),
    CONSTRAINT ck_no_self_duplicate CHECK (duplicate_of_incident_id IS NULL OR duplicate_of_incident_id != id),
    CONSTRAINT ck_no_self_preceding CHECK (preceding_incident_id IS NULL OR preceding_incident_id != id)
);

-- 2. Evidence Links Table
CREATE TABLE incident_evidence_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID NOT NULL REFERENCES security_incidents(id) ON DELETE RESTRICT,
    evidence_type VARCHAR(32) NOT NULL,
    evidence_reference_id VARCHAR(128) NOT NULL,
    evidence_hash CHAR(64) NOT NULL,
    attached_by UUID NOT NULL REFERENCES users(id),
    attached_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_incident_evidence UNIQUE (incident_id, evidence_reference_id)
);

-- 3. Comments Table
CREATE TABLE incident_comments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID NOT NULL REFERENCES security_incidents(id) ON DELETE RESTRICT,
    author_id UUID NOT NULL REFERENCES users(id),
    comment_text VARCHAR(2000) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

---

## 25. Constraints, Indexes, and Integrity Rules

```sql
-- Authoritative Active Correlation Boundary: Exactly ONE generation OPEN per threat vector
CREATE UNIQUE INDEX uq_active_correlation_token 
ON security_incidents (threat_vector_key) 
WHERE correlation_status = 'OPEN';

-- Operational Query Indexes
CREATE INDEX ix_incidents_threat_vector ON security_incidents (threat_vector_key);
CREATE INDEX ix_incidents_status ON security_incidents (status);
CREATE INDEX ix_incidents_correlation_status ON security_incidents (correlation_status);
CREATE INDEX ix_incidents_severity ON security_incidents (severity);
CREATE INDEX ix_incidents_assigned_to ON security_incidents (assigned_to);
CREATE INDEX ix_incidents_exam_id ON security_incidents (exam_id);
CREATE INDEX ix_incidents_latest_signal ON security_incidents (latest_signal_at DESC);
CREATE INDEX ix_incidents_created_at ON security_incidents (created_at DESC);

-- Evidence & Comment Query Indexes
CREATE INDEX ix_evidence_incident_id ON incident_evidence_links (incident_id);
CREATE INDEX ix_comments_incident_id ON incident_comments (incident_id, created_at ASC);
```

---

## 26. Retention and Deletion Policy

- **Hard Deletion Strictly Forbidden**: Database users have **zero `DELETE` privileges** on `security_incidents`, `incident_evidence_links`, and `incident_comments`.
- **Statutory Retention**: Minimum of **7 years** retention in compliance with national examination standards.
- **Cold Storage Archive**: After 180 days in `CLOSED` status, an automated job writes signed parquet summaries to KMS-encrypted S3 with Object Lock enabled.

---

## 27. API Architecture

Mounted under `/api/v1/incidents`:

| Method | Path | Required Role | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/incidents` | `SECURITY_OFFICER`, `SUPER_ADMIN`, `AUDITOR`, `EXAM_AUTHORITY` | List incidents with filtering (status, correlation_status, severity, exam) and pagination. |
| `GET` | `/api/v1/incidents/{id}` | `SECURITY_OFFICER`, `SUPER_ADMIN`, `AUDITOR`, `EXAM_AUTHORITY` | Get detailed incident record by UUID. |
| `POST` | `/api/v1/incidents/{id}/transition` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Transition lifecycle state. Validates OCC `version` and executes Dual-Phase Verification for `CONTAINED`. |
| `POST` | `/api/v1/incidents/{id}/assign` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Assign or reassign incident to an analyst. Requires OCC `version`. |
| `POST` | `/api/v1/incidents/{id}/comments` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Append an investigative note (sanitized plaintext, $\le 2000$ chars). |
| `GET` | `/api/v1/incidents/{id}/comments` | `SECURITY_OFFICER`, `SUPER_ADMIN`, `AUDITOR` | Retrieve comment thread chronologically. |
| `POST` | `/api/v1/incidents/{id}/evidence` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Attach an audit event or telemetry reference as evidence. |
| `GET` | `/api/v1/incidents/{id}/timeline` | `SECURITY_OFFICER`, `SUPER_ADMIN`, `AUDITOR` | Get unified chronological activity timeline. |

---

## 28. Frontend / Analyst UI Architecture

1. **Dashboard**: Real-time triage view grouping active cases by severity, SLA urgency countdown, and correlation generation.
2. **Case Workspace**:
   - *Left Column*: Metadata summary, lifecycle stepper, correlation status badge (`OPEN`/`CLOSED`), generation indicator, assigned analyst, and OCC version.
   - *Right Column*: Tabs for Timeline, Linked Evidence, Comment Thread, and Containment Audit Verification (with `seal_verification_status` badge).
3. **Generation Lineage Viewer**: Enables analysts to navigate backward and forward through generations ($N-1 \leftrightarrow N \leftrightarrow N+1$) for the same threat vector.
4. **Optimistic Updates**: Intercepts HTTP 409 Conflict, halts optimistic UI updates, displays collision notice, and pulls fresh data.

---

## 29. Failure Semantics

- **Database Down**: Worker halts SQS consumption. Messages remain in queue with exponential backoff.
- **Audit Service Unavailable**: State transitions and incident creations rollback if `AuditService.log_security_event()` fails.
- **Signal Parse Failure**: Malformed signals routed to dead-letter queue (DLQ) for forensic inspection.

---

## 30. 5D vs. 5E Boundary

| Concern | Phase 3C-5D (Incident Management) | Phase 3C-5E (Autonomous/Supervised Containment) |
| :--- | :--- | :--- |
| **Primary Responsibility** | Human investigation, triage, state tracking, evidence collation. | Active threat mitigation, isolation, policy enforcement. |
| **Containment Action** | **Strictly Observational** (records and verifies external action). | **Active Execution** (session revocation, workstation isolation). |
| **Automation Boundary** | Ingests signals $\to$ Creates cases. Zero enforcement. | Evaluates policy $\to$ Executes automated containment workflows. |
| **Database Authority** | Authoritative owner of `security_incidents` tables. | Consumes incident events; updates containment status via 5D API. |

---

## 31. 5D vs. 5F Boundary

| Concern | Phase 3C-5D (Incident Management) | Phase 3C-5F (External SIEM / SOC Integration) |
| :--- | :--- | :--- |
| **Primary Scope** | Platform-internal security incident lifecycle. | External SIEM export (Splunk, Elastic, Datadog), webhook alerts. |
| **Data Flow** | Internal SQS $\to$ 5D PostgreSQL. | 5D Audit Chain / S3 $\to$ External SOC ingestion pipeline. |
| **Authentication** | B-SEA Internal RBAC (`UserRoleEnum`). | External mTLS, API keys, and IAM role federation. |

---

## 32. Legacy SecurityService Coexistence & Controlled Migration Boundary

1. **Legacy Freeze**: The legacy `SecurityService` (`backend/app/services/security_service.py`) remains **strictly frozen**.
2. **Zero Modification**: Phase 3C-5D introduces no changes to `SecurityService` code, schemas, or endpoints.
3. **No Reliance on Unilateral Containment**: 5D does not call legacy containment endpoints (`isolate_node`, `terminate_session`).
4. **Controlled Migration Milestone**: Decommissioning or migrating the legacy security service is a separate, dedicated architectural milestone. Phase 3C-5E may consume or migrate specific containment capabilities only if explicitly authorized by its own approved architecture review.

---

## 33. Security Invariants for 5D

1. **Invariant 5D-1 (Zero Autonomous Containment)**: Under no circumstances shall Phase 3C-5D code execute active containment or disruption of candidate sessions, devices, or exam papers.
2. **Invariant 5D-2 (Append-Only Evidence & Comments)**: Evidence links and investigative comments cannot be updated or deleted by any user or API endpoint.
3. **Invariant 5D-3 (Authoritative Audit Integration)**: Every incident state change, assignment, reopen, and evidence link must emit a cryptographically signed event to the authoritative `AuditService`.
4. **Invariant 5D-4 (OCC Integrity)**: No incident record may be updated without matching the current database `version`.
5. **Invariant 5D-5 (Content Redaction)**: Question text, answer keys, candidate responses, and cryptographic secrets are strictly prohibited from incident titles, descriptions, dedup keys, comments, and metadata.
6. **Invariant 5D-6 (Authoritative Deduplication)**: Worker-side in-memory caches are non-authoritative. PostgreSQL transactional partial unique constraints constitute the sole authoritative duplicate-prevention boundary.
7. **Invariant 5D-7 (Acyclic Duplicates)**: Circular or self-referential duplicate relationships are strictly prevented by database constraints and application validation.
8. **Invariant 5D-8 (Inactivity Handover Liveness)**: No single stable correlation identity may prevent legitimate creation of a new incident after the configured inactivity window has expired.
9. **Invariant 5D-9 (Generation Monotonicity and Singularity)**: Every threat vector possesses at most one active correlation window (`OPEN`), and generations advance strictly monotonically without gap or reuse under transaction-scoped advisory lock synchronization.

---

## 34. Future Test Matrix (T01–T24)

When implementation is authorized, the following 24 unit and integration tests must pass:

- `T01_signal_ingestion_creates_incident`: Verifies valid advisory signal creates a new `TRIAGE` incident.
- `T02_rfc8785_jcs_canonicalization_determinism`: Verifies identical threat vector keys are computed regardless of input dictionary key order.
- `T03_multi_dimension_sorting_and_hashing`: Proves multi-dimension vectors (`candidate_id` + `node_id`) hash to identical digest across runtimes.
- `T04_rolling_inactivity_window_attaches_signal`: Signals arriving at 12:00, 12:59, and 13:58 attach to Generation 1.
- `T05_rolling_inactivity_window_expiration_rollover`: Signal arriving at 15:00 closes Generation 1 correlation window and creates Generation 2.
- `T06_coexistence_of_investigating_and_new_generation`: Verifies Generation 1 (`INVESTIGATING`, `CLOSED`) and Generation 2 (`TRIAGE`, `OPEN`) coexist in PostgreSQL without constraint violation.
- `T07_advisory_lock_generation_race_no_open_row`: Two concurrent workers arriving when all past generations are `CLOSED` safely serialize; exactly Generation 4 is created and shared.
- `T08_advisory_lock_crash_resilience`: If worker crashes while holding advisory lock, PostgreSQL aborts and releases lock; next worker succeeds.
- `T09_dual_phase_contained_immediate_ed25519_verification`: Proves valid Ed25519 signed audit event authorizes `CONTAINED` with `PENDING_SEAL`.
- `T10_dual_phase_contained_asynchronous_seal_reconciliation`: Asynchronous task verifies sealed Merkle root on S3 and updates to `SEALED_VERIFIED`.
- `T11_contained_rejects_missing_or_forged_audit_event`: Transition to `CONTAINED` returns HTTP 422 if audit record is missing or signature fails.
- `T12_5d_executes_zero_containment`: Verifies zero network, session, or exam disruption occurs upon entering `CONTAINED`.
- `T13_occ_version_conflict_409`: Stale version update returns HTTP 409 Conflict.
- `T14_reopen_transition_flow`: Reopening a `CLOSED` incident emits `INCIDENT_REOPENED` and returns case to `INVESTIGATING`.
- `T15_reopen_does_not_reopen_correlation`: Proves reopening a human investigation leaves `correlation_status = 'CLOSED'`.
- `T16_closed_does_not_delete`: Proves `CLOSED` preserves all database rows and audit records intact.
- `T17_duplicate_requires_valid_parent`: Setting `DUPLICATE` requires active parent; rejects invalid parent.
- `T18_circular_duplicate_prevention`: Acyclic validator rejects circular duplicate relationships (`A -> B -> A`).
- `T19_evidence_link_immutability`: Attempted SQL update/delete on `incident_evidence_links` is rejected.
- `T20_comment_sanitization_and_length`: Comments strip HTML/scripts and enforce 2000 character limit.
- `T21_comment_secret_screening`: Comments containing mock API keys or JWT patterns are rejected with HTTP 422.
- `T22_rbac_security_officer_vs_auditor`: Verifies `SECURITY_OFFICER` can mutate state; `AUDITOR` is strictly read-only.
- `T23_authoritative_audit_emission`: Every lifecycle transition produces a verifiable event in `AuditService`.
- `T24_ip_conflation_prevention`: Two candidates sharing an IP in the same exam produce separate incidents unless rule is infrastructure-scoped.

---

## 35. Prototype vs. Production Cryptography

| Architectural Domain | Prototype Implementation (Local / Testing) | Production Implementation (AWS ECS / Fargate) |
| :--- | :--- | :--- |
| **KMS Provider** | `MockKMS` (`backend/app/crypto/kms_interface.py`) | AWS KMS Customer-Managed Keys (CMKs) |
| **Symmetric Encryption** | AES-256-GCM envelope encryption via local master key | AWS KMS `GenerateDataKey` (AES-256-GCM) |
| **Digital Signing** | Ed25519 signing via `Ed25519PrivateKey` in `MockKMS` | AWS KMS Asymmetric Ed25519 Signing Keys |
| **Key Management Boundary** | In-memory test seeds (deterministic test execution) | AWS KMS Service Boundary (IAM-governed key policies) |
| **Database Encryption** | PostgreSQL 16 local instance | AWS Aurora PostgreSQL with KMS Storage Encryption at Rest |
| **Evidence Link Integrity** | SHA-256 hash comparison in PostgreSQL | SHA-256 hash comparison against sealed S3/KMS audit blocks |

*Clarification: AWS CloudHSM and Custom Key Store are not required. Standard AWS KMS Customer-Managed Keys fulfill all B-SEA cryptographic security invariants.*

---

## 36. Architectural Risks & Mitigations

1. **Advisory Lock Contention Under Severe Attack**: Extreme signal volume for the same threat vector. Mitigated by worker LRU in-memory damping before acquiring the advisory lock.
2. **Delayed Seal Reconciliation**: Worker delay in confirming S3 sealed block. Mitigated by treating unsealed records as operationally `CONTAINED` while alerting if seal delay exceeds 30 minutes.
3. **Multi-Dimension Explosion**: Uncontrolled dimension cardinality. Mitigated by strict schema validation permitting only canonical dimensions (`candidate_id`, `node_id`, `ip_address`).

---

## 37. Required Decisions Reconciliation Table

| Decision Area | Rev-05 Gap | Rev-06 Approved Architecture |
| :--- | :--- | :--- |
| **No-OPEN Generation Race** | Unspecified locking mechanism | **`pg_advisory_xact_lock(K_hash)` ensures atomic next-generation derivation** |
| **Canonical Threat Identity** | Delimiter string concatenation | **RFC 8785 JSON Canonicalization Scheme (JCS) over normalized UTF-8** |
| **Multi-Dimension Support** | Implicit single dimension | **Explicit lexicographical dictionary sorting in JCS** |
| **Containment Verification Timing** | Timing of sealing unclear | **Immediate Ed25519 verification allows `CONTAINED`; seal verified asynchronously** |
| **Reopen Correlation Semantics** | Unspecified | **Reopened investigation does NOT reopen correlation window** |

---

## 38. Proposed Implementation File List

When implementation is formally authorized, work will be confined strictly to these files:

### Backend Modules (New)
1. `backend/app/incidents/__init__.py`: Package initialization.
2. `backend/app/incidents/canonical.py`: RFC 8785 JCS threat vector canonicalizer.
3. `backend/app/incidents/models.py`: SQLAlchemy ORM models (`SecurityIncident`, `IncidentEvidenceLink`, `IncidentComment`).
4. `backend/app/incidents/schemas.py`: Pydantic request/response schemas.
5. `backend/app/incidents/service.py`: Incident management business logic, advisory lock generation engine, OCC checks, and audit verification.
6. `backend/app/incidents/router.py`: FastAPI REST API endpoints.
7. `backend/app/incidents/consumer.py`: SQS advisory signal ingestion worker.

### Database Migrations (New)
8. `alembic/versions/xxxx_phase3c_5d_incident_management.py`: Migration creating `security_incidents`, `incident_evidence_links`, `incident_comments`, composite unique generation constraint, and partial unique index for active correlation.

### Test Suite (New)
9. `tests/test_phase3c5d_incident_management.py`: Comprehensive test suite implementing T01–T24.

---

## 39. Explicit Implementation Preconditions

Before any implementation code is written, the following conditions must be met:
1. Rev-06 architecture is explicitly approved by the user.
2. Repository baseline remains at commit `7683dd6`.
3. Working tree remains clean with zero untracked code changes.
4. Test regression baseline remains at 240 passed, 5 skipped, 0 failed.

---

## 40. Final Architecture Verdict

**ARCHITECTURE APPROVED FOR IMPLEMENTATION PENDING USER REVIEW**

*(Implementation is NOT authorized. Awaiting your explicit review and authorization).*
