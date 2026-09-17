# B-SEA Phase 3C-5D — Security Incident Management Foundation
## Final Architecture & Design Review (Rev-05)

**System:** Bharat Secure Examination Architecture (B-SEA)  
**Milestone:** Phase 3C-5D — Security Incident Management Foundation  
**Status:** ARCHITECTURE REVIEW REV-05 (FINAL ARCHITECTURAL RECONCILIATION)  
**Document Revision:** Rev-05 (Resolution of Stable Identity vs. Rolling Correlation Window Conflict)  
**Baseline Commit:** `7683dd6` (`feat: implement Phase 3C-5C detection correlation foundation`)  
**Baseline Verification:** `HEAD == origin/main` | Regression: 240 passed, 5 skipped, 0 failed  
**Governing Security Boundary:** Observational and Human-Managed Incident Case Workflow. **ZERO Autonomous Containment.**  

---

## 1. Executive Summary

Phase 3C-5D establishes the **Security Incident Management Foundation** for the Bharat Secure Examination Architecture (B-SEA). Where Phase 3C-5C delivered an observational, non-intrusive stream of deterministic, versioned advisory signals, Phase 3C-5D establishes the formal, auditable, and human-managed incident case lifecycle that ingests, triages, investigates, and resolves those signals.

### Primary Architectural Reconciliation (Rev-04 to Rev-05)
Rev-05 resolves the fundamental architectural conflict present in Rev-04:
- **The Deadlock Problem in Rev-04**: Rev-04 specified a stable, time-independent `dedup_key` combined with a rolling 3600-second inactivity window, while enforcing database uniqueness via `CREATE UNIQUE INDEX uq_active_incident_dedup ON security_incidents (dedup_key) WHERE status IN ('TRIAGE', 'INVESTIGATING')`. If an incident remained under investigation (`INVESTIGATING`) past the 3600-second inactivity threshold, a subsequent qualifying signal required opening a *new* incident. However, because the prior incident remained in `INVESTIGATING` with the identical `dedup_key`, PostgreSQL raised a `UniqueViolation`. The worker was trapped in a deadlock: it could neither attach the signal (inactivity had expired) nor create a new incident (PostgreSQL uniqueness violation).
- **The Rev-05 Architectural Solution**: Formally decouples the **Stable Threat-Vector Identity** (`threat_vector_key`) from the **Correlation Instance Generation** (`generation`). Introduces an explicit correlation status (`correlation_status` $\in \{\text{'OPEN'}, \text{'CLOSED'}\}$), separate from the human investigation lifecycle (`status` $\in \{\text{'TRIAGE'}, \text{'INVESTIGATING'}, \dots\}$). When inactivity exceeds 3600 seconds, the correlation window for Generation $N$ transitions to `'CLOSED'`, leaving the analyst's investigation (`INVESTIGATING`) completely undisturbed. PostgreSQL enforces uniqueness on active correlation via:
  ```sql
  CREATE UNIQUE INDEX uq_active_correlation_token 
  ON security_incidents (threat_vector_key) 
  WHERE correlation_status = 'OPEN';
  ```
  This allows Generation $N+1$ to be created as `'OPEN'` while Generation $N$ remains in `'INVESTIGATING'` with `correlation_status = 'CLOSED'`. Both incidents safely coexist in PostgreSQL without constraint violation, time-bucket fragmentation, or race conditions.

### Secondary Reconciliations in Rev-05
1. **Independent Verification of `CONTAINED`**: An incident enters `CONTAINED` strictly when the referenced containment action is independently verified against the sealed, cryptographic `AuditService` log. Operator-supplied metadata alone does not constitute proof.
2. **Accurate AWS KMS Cryptography**: Removes ambiguous FIPS 140-2 Level 3 / hardware HSM wording. Clarifies that the prototype uses `MockKMS` (`AES-256-GCM` + `Ed25519`), and production uses standard AWS KMS customer-managed symmetric and asymmetric keys without requiring CloudHSM or Custom Key Store.
3. **Preservation of Approved Decisions**: Preserves zero autonomous containment, frozen legacy `SecurityService`, OCC versioning, append-only evidence/comments, 6-layer comment confidentiality, existing RBAC roles, and asynchronous queue ingestion.
4. **Concrete Worked Example**: Provides an end-to-end trace (12:00, 12:59, 13:58, 15:00) proving safe coexistence and generation handover.
5. **New Core Invariant (Invariant 5D-8)**: Enforces that no single stable correlation identity may prevent the legitimate creation of a new incident after the configured inactivity window has expired.

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

## 3. Rev-04 Findings & Reconciliations

### The Architectural Conflict in Rev-04
Rev-04 attempted to enforce deduplication using a partial unique index over human lifecycle states:
```sql
-- Rev-04 Flawed Index:
CREATE UNIQUE INDEX uq_active_incident_dedup
ON security_incidents (dedup_key)
WHERE status IN ('TRIAGE', 'INVESTIGATING');
```
This created a fatal contradiction with the rolling inactivity correlation window:

```
Time   Event                                         System State
─────────────────────────────────────────────────────────────────────────────────────────────
12:00  Signal 1 arrives for Vector K                 Incident A created (dedup_key = K, status = TRIAGE)
12:30  Analyst begins investigation                  Incident A updated (status = INVESTIGATING)
13:01  Inactivity timer reaches 3660s (>3600s)       Incident A becomes INELIGIBLE for correlation
13:02  Signal 2 arrives for Vector K                 Engine requires NEW Incident B (generation 2)
       Worker attempts INSERT for Incident B         ===> UniqueViolation (SQLSTATE 23505)!
       PostgreSQL blocks INSERT                      Because Incident A is still in INVESTIGATING!
```

#### Why Rev-04 Deadlocked:
1. **Business Policy**: Inactivity $>3600\text{s}$ dictates that Signal 2 cannot attach to Incident A. A new incident must be opened.
2. **Database Constraint**: `uq_active_incident_dedup` forbids inserting a second row with `dedup_key = K` while Incident A is in `INVESTIGATING`.
3. **Catch-and-Attach Failure**: Catching the `UniqueViolation` and attaching Signal 2 to Incident A would violate the 3600-second inactivity policy. Rejecting Signal 2 would drop critical security telemetry.

### The Rev-05 Solution: Orthogonal Lifecycle Decoupling
Rev-05 resolves this conflict by separating the **Correlation Window Lifecycle** (`correlation_status`) from the **Human Investigation Lifecycle** (`status`):

```
+─────────────────────────────────────────────────────────────────────────────+
|                         HUMAN INVESTIGATION LIFECYCLE                       |
|  TRIAGE ────> INVESTIGATING ────> CONTAINED ────> RESOLVED ────> CLOSED     |
|                   │                                                         |
|                   │ (Analyst can remain INVESTIGATING for days)             |
|                   ▼                                                         |
+─────────────────────────────────────────────────────────────────────────────+
                                       ▲
                                       │ (Decoupled & Orthogonal)
                                       ▼
+─────────────────────────────────────────────────────────────────────────────+
|                         CORRELATION WINDOW LIFECYCLE                        |
|                         OPEN ────────────────> CLOSED                       |
|      (Accepts signals within 3600s)       (Inactivity > 3600s or Terminal)  |
+─────────────────────────────────────────────────────────────────────────────+
```

1. **Threat Vector Key (`threat_vector_key`)**: The time-independent SHA-256 hash representing the threat vector.
2. **Correlation Generation (`generation`)**: An integer counter (`1, 2, 3, ...`) identifying the discrete correlation episode.
3. **Correlation Status (`correlation_status`)**: `OPEN` while actively accepting signals; `CLOSED` when inactivity exceeds 3600s or when the case is administratively terminated.
4. **PostgreSQL Unique Boundary**:
   ```sql
   CREATE UNIQUE INDEX uq_active_correlation_token 
   ON security_incidents (threat_vector_key) 
   WHERE correlation_status = 'OPEN';
   ```
5. **Generation Handover**: At 13:02, the worker closes Incident A's correlation window (`correlation_status = 'CLOSED'`), leaving its investigation state (`status = 'INVESTIGATING'`) completely intact. The worker then inserts Incident B (`generation = 2`, `correlation_status = 'OPEN'`, `status = 'TRIAGE'`). Both records coexist seamlessly without unique key violations.

---

## 4. Existing Architecture Inspection

Before formalizing Rev-05, all relevant components in the repository baseline (`7683dd6`) were verified:

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
| - Evaluates Inactivity Window & Generation Handover                         |
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

## 7. Dedicated Section: Stable Identity vs. Incident Correlation Instance

The central architectural innovation of Rev-05 is the formal separation of the **Threat-Vector Identity** from the **Incident Correlation Instance**:

```
+─────────────────────────────────────────────────────────────────────────────+
|                        THREAT-VECTOR IDENTITY (STABLE)                      |
|                                                                             |
|  threat_vector_key = SHA-256(canonical_rule_id : dim_key : dim_val :       |
|                              exam_id : policy_version)                      |
|                                                                             |
|  - Invariant across all time                                                |
|  - Completely independent of clocks, timestamps, or buckets                 |
|  - Represents the abstract threat pattern                                   |
+─────────────────────────────────────────────────────────────────────────────+
                                       │
                                       │ 1-to-Many Lineage
                                       ▼
+───────────────────────────────────────────────+   +─────────────────────────+
| Incident Correlation Instance: Generation 1   |   | Generation 2            |
| - incident_id: UUID_A                         |   | - incident_id: UUID_B   |
| - generation: 1                               |   | - generation: 2         |
| - correlation_status: CLOSED                  |──>| - correlation_status:   |
| - status: INVESTIGATING                       |   |   OPEN                  |
| - first_signal_at: 12:00:00                   |   | - status: TRIAGE        |
| - latest_signal_at: 13:58:00                  |   | - first_signal: 15:00   |
| - preceding_incident_id: NULL                 |   | - preceding_id: UUID_A  |
+───────────────────────────────────────────────+   +─────────────────────────+
```

### 7.1 Threat-Vector Identity vs. Correlation Instance
| Property | Threat-Vector Identity (`threat_vector_key`) | Incident Correlation Instance (`generation`) |
| :--- | :--- | :--- |
| **Concept** | The *what* and *who* of the security risk. | The discrete *temporal episode* of that risk. |
| **Time Encoding** | **ZERO time encoding**. Strictly invariant. | Bounded by `first_signal_at` and `latest_signal_at`. |
| **Cardinality** | Exactly one key per unique attack vector. | Monotonically increasing ($1, 2, 3, \dots, N$). |
| **Database Role** | Grouping key and lineage identifier. | Entity primary key (`id`) and generation index. |
| **Uniqueness Rule** | Never unique on its own in the table. | Unique via composite `(threat_vector_key, generation)`. |

### 7.2 Data Model: Decoupling Threat Identity, Generation, and Lifecycle
In `security_incidents`:
- `threat_vector_key` (`CHAR(64)` NOT NULL): The invariant SHA-256 hash.
- `generation` (`INTEGER` NOT NULL DEFAULT 1): Monotonically increasing generation number for this threat vector.
- `correlation_status` (`VARCHAR(16)` NOT NULL DEFAULT 'OPEN'): Either `'OPEN'` (actively correlating signals) or `'CLOSED'` (correlation window concluded).
- `preceding_incident_id` (`UUID` NULL REFERENCES `security_incidents(id)`): Lineage pointer to Generation $N-1$.
- `status` (`VARCHAR(32)` NOT NULL DEFAULT 'TRIAGE'): Human analyst lifecycle (`TRIAGE`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `CLOSED`, `FALSE_POSITIVE`, `DUPLICATE`).

### 7.3 Generation Derivation and Lineage
When a qualifying signal arrives:
1. The engine checks PostgreSQL for an existing incident with `threat_vector_key = K` and `correlation_status = 'OPEN'`.
2. If found, it evaluates the rolling inactivity window ($t_{\text{signal}} - t_{\text{latest}} \le 3600\text{s}$).
3. If inactivity has expired ($>3600\text{s}$), the engine atomically executes a **Generation Handover**:
   - The prior incident's correlation status is set to `'CLOSED'`:
     ```sql
     UPDATE security_incidents 
     SET correlation_status = 'CLOSED', updated_at = NOW() 
     WHERE id = :prior_id AND correlation_status = 'OPEN';
     ```
   - The new generation number is derived as:
     $$\text{new\_generation} = \text{prior\_incident.generation} + 1$$
   - A new incident is inserted with `generation = new_generation`, `correlation_status = 'OPEN'`, `status = 'TRIAGE'`, and `preceding_incident_id = prior_id`.
   - An immutable audit event `INCIDENT_CORRELATION_WINDOW_CLOSED` is emitted for the prior incident, and `INCIDENT_CREATED` is emitted for the new incident.

### 7.4 Detailed Worked Example: 12:00, 12:59, 13:58, 15:00
Let threat vector $K = \text{SHA-256}(\text{"R-003:node_id:NODE-042:EXAM-99:v1"})$.

#### Step 1: 12:00:00 — Signal 1 Arrives
- Search: No incident exists for $K$ with `correlation_status = 'OPEN'`.
- Max Generation: `SELECT COALESCE(MAX(generation), 0) FROM security_incidents WHERE threat_vector_key = K` returns `0`.
- Action: Worker creates **Incident A**:
  - `id`: `UUID_A`
  - `incident_number`: `INC-20260916-00001`
  - `threat_vector_key`: $K$
  - `generation`: `1`
  - `correlation_status`: `'OPEN'`
  - `status`: `'TRIAGE'`
  - `first_signal_at`: `12:00:00`
  - `latest_signal_at`: `12:00:00`
  - `preceding_incident_id`: `NULL`
- Result: Incident A is now the unique row in `uq_active_correlation_token` for $K$.

#### Step 2: 12:30:00 — Analyst Begins Investigation
- Analyst assigns Incident A to themselves and transitions status to `'INVESTIGATING'`.
- Result: `status = 'INVESTIGATING'`. Critically, `correlation_status` remains `'OPEN'`.

#### Step 3: 12:59:00 — Signal 2 Arrives
- Search: Finds Incident A (`correlation_status = 'OPEN'`).
- Inactivity Evaluation:
  $$\Delta t = 12:59:00 - 12:00:00 = 59\text{ minutes} = 3540\text{ seconds} \le 3600\text{ seconds}$$
- Action: Within rolling window! Attach Signal 2 to Incident A:
  - Insert row in `incident_evidence_links` referencing Signal 2.
  - Update Incident A: `latest_signal_at = 12:59:00`, `updated_at = NOW()`.
  - Emit audit event: `INCIDENT_EVIDENCE_ATTACHED`.
- Result: Incident A remains `'INVESTIGATING'` and `'OPEN'`. The correlation window is extended to $12:59:00 + 3600\text{s} = 13:59:00$.

#### Step 4: 13:58:00 — Signal 3 Arrives
- Search: Finds Incident A (`correlation_status = 'OPEN'`).
- Inactivity Evaluation:
  $$\Delta t = 13:58:00 - 12:59:00 = 59\text{ minutes} = 3540\text{ seconds} \le 3600\text{ seconds}$$
- Action: Within rolling window! Attach Signal 3 to Incident A:
  - Insert row in `incident_evidence_links` referencing Signal 3.
  - Update Incident A: `latest_signal_at = 13:58:00`, `updated_at = NOW()`.
  - Emit audit event: `INCIDENT_EVIDENCE_ATTACHED`.
- Result: Incident A remains `'INVESTIGATING'` and `'OPEN'`. The correlation window is extended to $13:58:00 + 3600\text{s} = 14:58:00$.

#### Step 5: 15:00:00 — Signal 4 Arrives (Generation Handover)
- Search: Finds Incident A (`correlation_status = 'OPEN'`).
- Inactivity Evaluation:
  $$\Delta t = 15:00:00 - 13:58:00 = 62\text{ minutes} = 3720\text{ seconds} > 3600\text{ seconds}$$
- Evaluation: **The rolling inactivity correlation window has expired.** Incident A is no longer eligible to accept signals.
- Action (Atomic Transaction):
  1. Close Incident A's correlation window:
     ```sql
     UPDATE security_incidents 
     SET correlation_status = 'CLOSED', updated_at = NOW() 
     WHERE id = 'UUID_A' AND correlation_status = 'OPEN';
     ```
     *(Notice: Incident A's `status` remains `'INVESTIGATING'`. The analyst's ongoing work is uninterrupted).*
  2. Emit audit event: `INCIDENT_CORRELATION_WINDOW_CLOSED` (reason: `INACTIVITY_TIMEOUT_EXPIRED`, inactivity: `3720s`).
  3. Create **Incident B** (Generation 2):
     - `id`: `UUID_B`
     - `incident_number`: `INC-20260916-00002`
     - `threat_vector_key`: $K$ (Identical stable identity!)
     - `generation`: `2`
     - `correlation_status`: `'OPEN'`
     - `status`: `'TRIAGE'`
     - `first_signal_at`: `15:00:00`
     - `latest_signal_at`: `15:00:00`
     - `preceding_incident_id`: `'UUID_A'` (Explicit lineage pointer)
  4. Attach Signal 4 to Incident B in `incident_evidence_links`.
  5. Emit audit event: `INCIDENT_CREATED`.
- Result: Incident B is now the unique row in `uq_active_correlation_token` for $K$.

### 7.5 Formal Proof of Deadlock Elimination & Coexistence
In PostgreSQL at 15:00:01:
```
+────────+──────────────────+────────────+────────────+────────────────────+───────────────────────+
| id     | incident_number  | threat_key | generation | correlation_status | status (human)        |
+────────+──────────────────+────────────+────────────+────────────────────+───────────────────────+
| UUID_A | INC-20260916-001 | K          | 1          | CLOSED             | INVESTIGATING (Active)|
| UUID_B | INC-20260916-002 | K          | 2          | OPEN               | TRIAGE (Active)       |
+────────+──────────────────+────────────+────────────+────────────────────+───────────────────────+
```
- **Uniqueness Check**:
  `uq_active_correlation_token` indexes only rows `WHERE correlation_status = 'OPEN'`.
  Only `UUID_B` has `correlation_status = 'OPEN'`. `UUID_A` is not in the index.
  **Zero unique constraint violation.**
- **Composite Integrity Check**:
  `uq_threat_vector_generation` requires `(threat_vector_key, generation)` to be unique.
  Row 1 is `(K, 1)`. Row 2 is `(K, 2)`.
  **Zero composite constraint violation.**
- **Analyst Independence Check**:
  The analyst investigating `UUID_A` can continue updating comments, attaching manual forensic notes, and resolving the case without interference.
- **Deadlock Eliminated**: The system can ingest and correlate high-frequency threat signals indefinitely without trapping workers in constraint collisions.

---

## 8. Final Clean Lifecycle & State Machine

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

### The `INCIDENT_REOPENED` Action
`REOPENED` is not a persistent state. When new evidence surfaces regarding a `RESOLVED` or `CLOSED` incident, an authorized analyst triggers the `INCIDENT_REOPENED` action:
$$\text{CLOSED} \xrightarrow[\text{Requires Justification + Audit}]{\text{INCIDENT\_REOPENED}} \text{INVESTIGATING}$$
This transition increments the incident `version`, records an immutable `INCIDENT_REOPENED` event in the audit chain, appends an investigative comment, and returns the case to `INVESTIGATING`. If the incident's correlation window was previously closed, it remains closed unless explicitly reopened for correlation by an administrator.

---

## 9. State Transition Matrix & Authority

| From State | To State | Action / Trigger | Authorized Role | Preconditions & Requirements | Required Audit Event |
| :--- | :--- | :--- | :--- | :--- | :--- |
| *(None)* | `TRIAGE` | `CREATE_INCIDENT` | System (Worker) | Qualifying advisory signal received | `INCIDENT_CREATED` |
| `TRIAGE` | `INVESTIGATING` | `START_INVESTIGATION` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Analyst assigned; initial assessment documented | `INCIDENT_STATUS_CHANGED` |
| `TRIAGE` | `FALSE_POSITIVE` | `MARK_FALSE_POSITIVE` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Justification ($\ge 20$ chars); sets `correlation_status = 'CLOSED'` | `INCIDENT_STATUS_CHANGED` |
| `TRIAGE` | `DUPLICATE` | `MARK_DUPLICATE` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Valid `duplicate_of_incident_id`; acyclic check passed; sets `correlation_status = 'CLOSED'` | `INCIDENT_STATUS_CHANGED` |
| `INVESTIGATING`| `CONTAINED` | `RECORD_CONTAINMENT` | `SECURITY_OFFICER`, `SUPER_ADMIN` | 5 external reference fields verified against sealed audit log | `INCIDENT_STATUS_CHANGED` |
| `INVESTIGATING`| `RESOLVED` | `RESOLVE_INCIDENT` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Resolution summary and category; sets `correlation_status = 'CLOSED'` | `INCIDENT_STATUS_CHANGED` |
| `INVESTIGATING`| `FALSE_POSITIVE` | `MARK_FALSE_POSITIVE` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Justification ($\ge 20$ chars); sets `correlation_status = 'CLOSED'` | `INCIDENT_STATUS_CHANGED` |
| `INVESTIGATING`| `DUPLICATE` | `MARK_DUPLICATE` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Valid `duplicate_of_incident_id`; acyclic check passed; sets `correlation_status = 'CLOSED'` | `INCIDENT_STATUS_CHANGED` |
| `CONTAINED` | `RESOLVED` | `RESOLVE_INCIDENT` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Resolution summary and category; sets `correlation_status = 'CLOSED'` | `INCIDENT_STATUS_CHANGED` |
| `RESOLVED` | `CLOSED` | `CLOSE_INCIDENT` | `SUPER_ADMIN`, `SECURITY_OFFICER` | Supervisory review completed; administrative sign-off | `INCIDENT_CLOSED` |
| `RESOLVED` | `INVESTIGATING`| `INCIDENT_REOPENED` | `SECURITY_OFFICER`, `SUPER_ADMIN` | New evidence identified; mandatory justification | `INCIDENT_REOPENED` |
| `CLOSED` | `INVESTIGATING`| `INCIDENT_REOPENED` | `SUPER_ADMIN` | Supervisory authorization + mandatory audit justification | `INCIDENT_REOPENED` |

### Forbidden Transitions
- `CLOSED` $\to$ `RESOLVED` (Direct reversal forbidden; must reopen to `INVESTIGATING`).
- `CLOSED` $\to$ `FALSE_POSITIVE` / `DUPLICATE` (Administrative closure is final unless reopened).
- `FALSE_POSITIVE` $\to$ `CONTAINED` / `RESOLVED` (Terminal state).
- `DUPLICATE` $\to$ `CONTAINED` / `RESOLVED` (A duplicate cannot be independently resolved).
- Any state $\to$ *(Deletion)* (**DATABASE DELETION IS PERMANENTLY FORBIDDEN**).

---

## 10. The Five Pillars of Deduplication & Correlation Architecture

Phase 3C-5D organizes deduplication into five non-confusable architectural pillars:

### 10.1 Pillar A: Stable Correlation Identity (Time-Independent)
The `threat_vector_key` represents the invariant identity of the attack vector across all time:
$$\text{raw\_identity} = \text{canonical\_rule\_id} \mathbin{\Vert} \text{":"} \mathbin{\Vert} \text{dim\_key} \mathbin{\Vert} \text{":"} \mathbin{\Vert} \text{dim\_val} \mathbin{\Vert} \text{":"} \mathbin{\Vert} \text{exam\_id\_or\_GLOBAL} \mathbin{\Vert} \text{":"} \mathbin{\Vert} \text{policy\_version}$$
$$\text{threat_vector_key} = \text{SHA-256}(\text{raw\_identity})$$

#### Invariants:
- **Zero Time Bucketing**: The `threat_vector_key` **strictly does not contain** clock hours, calendar dates, epoch timestamps, or time windows.
- **Rule ID Normalization**: Uses `canonical_rule_id` (e.g. `R-003`). Version suffixes (e.g. `.v1`) are stripped.
- **Strict Content Redaction**: The key **MUST NOT** contain:
  - Question text or question identifiers
  - Answer keys or scoring criteria
  - Candidate responses or exam submissions
  - Plaintext examination material
  - Candidate passwords or credential hashes
  - JWTs, auth tokens, or session keys
  - DEKs, KEKs, or cryptographic keys
  - Secrets or private key material

### 10.2 Pillar B: Correlation Generation & Instance Identifier
- **Generation Number (`generation`)**: An integer counter (`1, 2, 3, ...`) scoped to `threat_vector_key`.
- **Instance Identifier (`id`)**: The UUID primary key of the specific incident representing that generation.
- **Instance Derivation**: Monotonically increments whenever a new correlation window opens for an existing threat vector.

### 10.3 Pillar C: Rolling Inactivity Correlation Window (3600 Seconds)
The time dimension is governed by a **Rolling Inactivity Correlation Window** ($W_{\text{inactivity}} = 3600\text{ seconds}$):
- **Eligibility Check**: A signal attaches to an open incident if and only if:
  $$t_{\text{signal}} - t_{\text{latest\_signal\_at}} \le 3600\text{ seconds}$$
- **Window Extension**: When a qualifying signal attaches, `latest_signal_at` is updated to $\max(t_{\text{latest\_signal\_at}}, t_{\text{signal}})$, extending the rolling window by another 3600 seconds.
- **Threshold Nature**: The 3600-second window is an **inactivity threshold**, not an absolute lifespan.

### 10.4 Pillar D: Active Incident Eligibility & Correlation Window Status
Correlation eligibility is decoupled from human investigation:
- **`correlation_status = 'OPEN'`**: The incident is actively eligible to receive incoming signals.
- **`correlation_status = 'CLOSED'`**: The correlation window has closed (inactivity timeout expired or human resolution completed). Incoming signals for this vector will trigger Generation Handover to a new incident.

### 10.5 Pillar E: Authoritative Database Uniqueness Boundary
Enforced strictly by PostgreSQL:
```sql
-- At most ONE active correlation window per threat vector across the cluster
CREATE UNIQUE INDEX uq_active_correlation_token 
ON security_incidents (threat_vector_key) 
WHERE correlation_status = 'OPEN';

-- Enforces historical generation uniqueness
ALTER TABLE security_incidents 
ADD CONSTRAINT uq_threat_vector_generation 
UNIQUE (threat_vector_key, generation);
```

### 10.6 Pillar F: Worker-Side In-Memory Optimization Layer (Non-Authoritative)
- Workers maintain an in-memory LRU cache (`capacity = 10,000`, `ttl = 60s`) mapping `threat_vector_key` to `incident_id`.
- **Optimization Only**: Exists purely to damp high-frequency signal bursts.
- **Non-Authoritative**: Has zero authority over correctness. Node restarts or cache misses do not affect correctness. PostgreSQL remains the sole source of truth.

### 10.7 Deterministic Normalization & Redaction
Inputs are canonicalized before hashing:
1. `canonical_rule_id`: Trimmed, uppercase ASCII (e.g. `"R-003"`).
2. `dim_key`: Trimmed, lowercase ASCII (e.g. `"node_id"`).
3. `dim_val`: Normalized by type (UUID lowercase hex; IPv4/IPv6 exploded; Node ID trimmed uppercase).
4. `exam_id_or_GLOBAL`: Lowercase UUID or literal `"GLOBAL"`.
5. `policy_version`: Lowercase string (e.g. `"v1"`).

### 10.8 IP Conflation Anti-Pattern Elimination
Phase 3C-5D strictly forbids assuming $\text{Same IP} \implies \text{Same Actor}$ or $\text{Same IP} \implies \text{Same Incident}$. In examination centers with shared NAT gateways:
- IP dimensions must be qualified with `exam_id`.
- Multiple candidates sharing an IP produce distinct incidents unless the rule is explicitly flagged as infrastructure-scoped (e.g. DDoS).

---

## 11. Concurrency & Race Resolution Model

### 11.1 Concurrent Creation Race (Same Generation)
When Worker A and Worker B concurrently receive the initial signal for threat vector $K$:
1. Both attempt `INSERT INTO security_incidents (threat_vector_key, generation, correlation_status, ...) VALUES (K, 1, 'OPEN', ...)`.
2. PostgreSQL serializes via `uq_active_correlation_token`.
3. Worker A succeeds (HTTP 201).
4. Worker B receives `UniqueViolation` (SQLSTATE `23505`).
5. Worker B catches `IntegrityError`, queries `SELECT id, latest_signal_at FROM security_incidents WHERE threat_vector_key = K AND correlation_status = 'OPEN' FOR UPDATE`.
6. Worker B attaches its signal to Worker A's incident in `incident_evidence_links`, touches `latest_signal_at`, and commits (HTTP 200).

### 11.2 Inactivity Expiration Handover Race (Generation Rollover)
When Worker A and Worker B concurrently receive Signal $S$ at 15:00:00 for threat vector $K$ after 3720s of inactivity:
1. Worker A acquires row lock on Generation 1: `SELECT ... FOR UPDATE`.
2. Worker A verifies $\Delta t = 3720\text{s} > 3600\text{s}$.
3. Worker A updates Generation 1: `correlation_status = 'CLOSED'`.
4. Worker A inserts Generation 2: `generation = 2`, `correlation_status = 'OPEN'`, `preceding_incident_id = Gen1.id`.
5. Worker A commits.
6. Worker B acquires lock on Generation 1, re-reads row: `correlation_status` is now `'CLOSED'`.
7. Worker B re-queries for `correlation_status = 'OPEN'`: finds Generation 2 (created by Worker A).
8. Worker B attaches its evidence to Generation 2 and commits safely.

### 11.3 Zero Last-Write-Wins & Zero Silent Merging
- The losing transaction never overwrites the winning transaction's core metadata (`title`, `description`, `created_at`, `assigned_to`, `severity`).
- Every signal attachment creates an immutable record in `incident_evidence_links` and emits an `INCIDENT_EVIDENCE_ATTACHED` audit log.

---

## 12. Observational `CONTAINED` State Specification & Independent Audit Verification

Phase 3C-5D is **STRICTLY OBSERVATIONAL**. Phase 3C-5D contains **zero** active mitigation, enforcement, or containment logic.

### 12.1 Strict Observational Milestone (Zero 5D Containment)
5D does **NOT**:
- Revoke candidate sessions or tokens
- Block candidates or test center accounts
- Block devices or IP addresses
- Quarantine questions or question banks
- Rotate cryptographic keys
- Cancel or suspend examinations
- Execute emergency containment scripts

*All active containment capabilities belong strictly to Phase 3C-5E.*

### 12.2 Mandatory Independent Audit Verification (Metadata Alone is Not Proof)
In Rev-05, operator-supplied metadata alone **does not constitute proof** of containment. When an analyst submits a request to transition an incident to `CONTAINED`:

```json
{
  "containment_reference_id": "CONT-20260916-8841",
  "authorization_principal": "usr_sec_officer_042",
  "containment_timestamp": "2026-09-16T18:30:00Z",
  "containment_mechanism": "PHASE_3C_5E_WORKFLOW",
  "audit_event_reference": "aud_evt_99b78a12e4f04c1a"
}
```

The backend **independently verifies the external action** prior to accepting the transition:
1. **Authoritative Record Check**: The service queries `AuditService` to verify that `audit_event_reference` exists in the authoritative PostgreSQL audit table.
2. **Cryptographic Signature Verification**: The audit event's Ed25519 payload signature is verified against the KMS public key.
3. **Event Type Validation**: The verified audit event type must be an authorized external containment event (e.g. `CONTAINMENT_EXECUTED` or `EXTERNAL_CONTAINMENT_VERIFIED`).
4. **Principal & Ticket Matching**: The audit event payload must contain matching values for `containment_reference_id`, `containment_mechanism`, and `authorization_principal`.

*If the audit record is missing, unverified, or does not match, the transition is REJECTED with HTTP 422 Unprocessable Entity.*

### 12.3 Schema of Containment Evidence
The 5 reference fields are persisted immutably in `security_incidents`:
- `containment_reference_id` (`VARCHAR(128)` NOT NULL on CONTAINED)
- `authorization_principal` (`VARCHAR(128)` NOT NULL on CONTAINED)
- `containment_timestamp` (`TIMESTAMPTZ` NOT NULL on CONTAINED)
- `containment_mechanism` (`VARCHAR(64)` NOT NULL on CONTAINED)
- `audit_event_reference` (`VARCHAR(128)` NOT NULL on CONTAINED)

---

## 13. Evidence Reference Architecture

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

## 14. Evidence Access Control

1. **Metadata vs. Payload Separation**: Analysts with incident read access can view evidence metadata (`evidence_type`, `evidence_reference_id`, `attached_at`).
2. **Payload Resolution**: Resolving the raw audit payload requires fetching the record from `AuditService`. The analyst must possess explicit read permissions for the specific audit domain (`audit:read`).
3. **Candidate PII Masking**: Raw audit payloads containing candidate PII are dynamically masked at the API gateway layer unless the analyst holds `SUPER_ADMIN` or `EXAM_AUTHORITY` with an active, audited justification ticket.
4. **Examination Content Redaction**: Question text, options, and answer keys are never stored in the audit chain or incident tables.

---

## 15. RBAC Model & Repository Role Alignment

Phase 3C-5D introduces **zero new roles**. It aligns strictly with the existing `UserRoleEnum` in `backend/app/core/models.py`:

| Role Enum | 5D Incident Management Permissions |
| :--- | :--- |
| **`SUPER_ADMIN`** | Full incident management authority: view, assign, triage, investigate, contain (record), resolve, close, reopen, and perform forensic export. |
| **`SECURITY_OFFICER`** | Primary operational authority: view, assign, triage, investigate, contain (record), resolve, reopen, and add comments/evidence. |
| **`AUDITOR`** | Strictly read-only compliance authority: view all incidents, inspect timelines, view audit links, and verify cryptographic evidence chains. Cannot mutate state. |
| **`EXAM_AUTHORITY`** | Read-only executive oversight: view aggregate incident metrics, view high-severity incident summaries affecting exam delivery. Cannot view raw telemetry or mutate state. |
| *Candidate / Proctor* | **Zero Access**: Incident management APIs are completely inaccessible to examinees, test proctors, and public endpoints. |

---

## 16. Analyst Assignment

- **Assignment Target**: Incidents can be assigned to any active user possessing `SECURITY_OFFICER` or `SUPER_ADMIN`.
- **Concurrency & Self-Assignment**: Analysts can assign incidents to themselves or reassign them to team members.
- **Audit Requirement**: Every assignment updates `assigned_to`, increments `version`, and logs an immutable `INCIDENT_ASSIGNED` event recording previous analyst, new analyst, and authorizing user.
- **Unassigned Triage**: New incidents created from advisory signals initialize with `assigned_to = NULL`.

---

## 17. 6-Layer Defense-in-Depth Comment Confidentiality Model

1. **Layer 1: Structural Plaintext Storage**: `comment_text` stores strictly unformatted, sanitized plaintext. HTML, Markdown rendering, scripts, and executable tags are stripped before persistence, preventing stored XSS.
2. **Layer 2: Hard Character Limits**: Comment length is constrained to $2,000$ characters maximum, preventing payload injection, buffer abuse, and database bloat.
3. **Layer 3: Pre-Commit Secret & Exam Screening**: Automated regex filter screens submitted comment text prior to database commit. Comments matching patterns for JWTs, private keys, AWS access keys, or question identifiers are rejected with HTTP 422.
4. **Layer 4: Append-Only Immutability**: `incident_comments` allows **zero updates and zero deletions**. Corrective notes must be added as new append-only comments.
5. **Layer 5: Sealed PostgreSQL Audit Integration**: Every comment creation emits an `INCIDENT_COMMENT_ADDED` audit event, capturing comment hash, author UUID, and timestamp in the sealed Ed25519 audit chain.
6. **Layer 6: Read-Side Role Masking**: When comments are fetched via API, internal system flags or sensitive investigation markers are dynamically redacted based on the requesting user's RBAC role.

---

## 18. Concurrency Strategy & OCC (`version` Column)

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

## 19. Severity Model

| Severity | Definition | Target Triage SLA | Target Resolution SLA |
| :--- | :--- | :--- | :--- |
| **`CRITICAL`** | Direct compromise of examination integrity, active key compromise, or large-scale candidate disruption. | 15 Minutes | 2 Hours |
| **`HIGH`** | Targeted exam tampering attempt, unauthorized administrative access, or systemic node failures. | 30 Minutes | 6 Hours |
| **`MEDIUM`** | Repeated biometric/liveness anomalies, suspicious multi-session attempts, or abnormal API velocity. | 2 Hours | 24 Hours |
| **`LOW`** | Isolated client network glitch, non-critical workstation drift, or minor configuration anomaly. | 8 Hours | 72 Hours |
| **`INFO`** | Observational telemetry notice, routine security drill marker, or scheduled maintenance notice. | 24 Hours | Best Effort |

---

## 20. Incident Types Taxonomy

- `INTEGRITY_TAMPERING`: Unauthorized attempt to alter candidate responses, exam timers, or audit logs.
- `AUTHENTICATION_ANOMALY`: Credential stuffing, simultaneous multi-device logins, or token hijacking.
- `EXAM_LEAK_ATTEMPT`: Suspicious workstation screen scraping, rapid question navigation, or clipboard scraping.
- `INFRASTRUCTURE_ATTACK`: Network flood, unauthorized API probing, KMS request surge, or container escape attempt.
- `WORKSTATION_TAMPERING`: Secure browser bypass, VM detection trigger, peripheral injection, or secondary display.
- `AUDIT_FAILURE`: Cryptographic verification mismatch, sealer failure, or quarantine threshold breach.

---

## 21. Incident Timeline

The timeline provides an immutable, chronological reconstruction synthesized dynamically from three authoritative sources:
1. **Linked Advisory Signals**: Historical signals linked via `incident_evidence_links`.
2. **Audit Log Events**: State transitions, assignments, re-openings, and containment records emitted by `AuditService`.
3. **Analyst Comments**: Append-only investigative notes from `incident_comments`.

Timelines are queried chronologically by `timestamp ASC` with category filtering.

---

## 22. Audit Integration (Authoritative AuditService)

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

## 23. Database Schema Proposal (Reflecting Rev-05 Generation Decoupling)

```sql
-- 1. Incidents Table
CREATE TABLE security_incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_number VARCHAR(32) UNIQUE NOT NULL,
    threat_vector_key CHAR(64) NOT NULL,
    generation INTEGER NOT NULL DEFAULT 1,
    correlation_status VARCHAR(16) NOT NULL DEFAULT 'OPEN',
    preceding_incident_id UUID NULL REFERENCES security_incidents(id) ON DELETE RESTRICT,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    incident_type VARCHAR(64) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'TRIAGE',
    rule_id VARCHAR(64) NOT NULL,
    canonical_rule_id VARCHAR(64) NOT NULL,
    policy_version VARCHAR(32) NOT NULL DEFAULT 'v1',
    dimension_key VARCHAR(64) NOT NULL,
    dimension_val VARCHAR(255) NOT NULL,
    exam_id UUID NULL,
    assigned_to UUID NULL REFERENCES users(id),
    duplicate_of_incident_id UUID NULL REFERENCES security_incidents(id) ON DELETE RESTRICT,
    first_signal_at TIMESTAMPTZ NOT NULL,
    latest_signal_at TIMESTAMPTZ NOT NULL,
    containment_reference_id VARCHAR(128) NULL,
    authorization_principal VARCHAR(128) NULL,
    containment_timestamp TIMESTAMPTZ NULL,
    containment_mechanism VARCHAR(64) NULL,
    audit_event_reference VARCHAR(128) NULL,
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

## 24. Constraints, Indexes, and Integrity Rules

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

## 25. Retention and Deletion Policy

- **Hard Deletion Strictly Forbidden**: Database users have **zero `DELETE` privileges** on `security_incidents`, `incident_evidence_links`, and `incident_comments`.
- **Statutory Retention**: Minimum of **7 years** retention in compliance with national examination standards.
- **Cold Storage Archive**: After 180 days in `CLOSED` status, an automated job writes signed parquet summaries to KMS-encrypted S3 with Object Lock enabled.

---

## 26. API Architecture

Mounted under `/api/v1/incidents`:

| Method | Path | Required Role | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/incidents` | `SECURITY_OFFICER`, `SUPER_ADMIN`, `AUDITOR`, `EXAM_AUTHORITY` | List incidents with filtering (status, correlation_status, severity, exam) and pagination. |
| `GET` | `/api/v1/incidents/{id}` | `SECURITY_OFFICER`, `SUPER_ADMIN`, `AUDITOR`, `EXAM_AUTHORITY` | Get detailed incident record by UUID. |
| `POST` | `/api/v1/incidents/{id}/transition` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Transition lifecycle state. Validates OCC `version` and independent audit proof for `CONTAINED`. |
| `POST` | `/api/v1/incidents/{id}/assign` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Assign or reassign incident to an analyst. Requires OCC `version`. |
| `POST` | `/api/v1/incidents/{id}/comments` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Append an investigative note (sanitized plaintext, $\le 2000$ chars). |
| `GET` | `/api/v1/incidents/{id}/comments` | `SECURITY_OFFICER`, `SUPER_ADMIN`, `AUDITOR` | Retrieve comment thread chronologically. |
| `POST` | `/api/v1/incidents/{id}/evidence` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Attach an audit event or telemetry reference as evidence. |
| `GET` | `/api/v1/incidents/{id}/timeline` | `SECURITY_OFFICER`, `SUPER_ADMIN`, `AUDITOR` | Get unified chronological activity timeline. |

---

## 27. Frontend / Analyst UI Architecture

1. **Dashboard**: Real-time triage view grouping active cases by severity, SLA urgency countdown, and correlation generation.
2. **Case Workspace**:
   - *Left Column*: Metadata summary, lifecycle stepper, correlation status badge (`OPEN`/`CLOSED`), generation indicator, assigned analyst, and OCC version.
   - *Right Column*: Tabs for Timeline, Linked Evidence, Comment Thread, and Containment Audit Verification.
3. **Generation Lineage Viewer**: Enables analysts to navigate backward and forward through generations ($N-1 \leftrightarrow N \leftrightarrow N+1$) for the same threat vector.
4. **Optimistic Updates**: Intercepts HTTP 409 Conflict, halts optimistic UI updates, displays collision notice, and pulls fresh data.

---

## 28. Failure Semantics

- **Database Down**: Worker halts SQS consumption. Messages remain in queue with exponential backoff.
- **Audit Service Unavailable**: State transitions and incident creations rollback if `AuditService.log_security_event()` fails.
- **Signal Parse Failure**: Malformed signals routed to dead-letter queue (DLQ) for forensic inspection.

---

## 29. 5D vs. 5E Boundary

| Concern | Phase 3C-5D (Incident Management) | Phase 3C-5E (Autonomous/Supervised Containment) |
| :--- | :--- | :--- |
| **Primary Responsibility** | Human investigation, triage, state tracking, evidence collation. | Active threat mitigation, isolation, policy enforcement. |
| **Containment Action** | **Strictly Observational** (records and verifies external action). | **Active Execution** (session revocation, workstation isolation). |
| **Automation Boundary** | Ingests signals $\to$ Creates cases. Zero enforcement. | Evaluates policy $\to$ Executes automated containment workflows. |
| **Database Authority** | Authoritative owner of `security_incidents` tables. | Consumes incident events; updates containment status via 5D API. |

---

## 30. 5D vs. 5F Boundary

| Concern | Phase 3C-5D (Incident Management) | Phase 3C-5F (External SIEM / SOC Integration) |
| :--- | :--- | :--- |
| **Primary Scope** | Platform-internal security incident lifecycle. | External SIEM export (Splunk, Elastic, Datadog), webhook alerts. |
| **Data Flow** | Internal SQS $\to$ 5D PostgreSQL. | 5D Audit Chain / S3 $\to$ External SOC ingestion pipeline. |
| **Authentication** | B-SEA Internal RBAC (`UserRoleEnum`). | External mTLS, API keys, and IAM role federation. |

---

## 31. Legacy SecurityService Coexistence & Controlled Migration Boundary

1. **Legacy Freeze**: The legacy `SecurityService` (`backend/app/services/security_service.py`) remains **strictly frozen**.
2. **Zero Modification**: Phase 3C-5D introduces no changes to `SecurityService` code, schemas, or endpoints.
3. **No Reliance on Unilateral Containment**: 5D does not call legacy containment endpoints (`isolate_node`, `terminate_session`).
4. **Controlled Migration Milestone**: Decommissioning or migrating the legacy security service is a separate, dedicated architectural milestone. Phase 3C-5E may consume or migrate specific containment capabilities only if explicitly authorized by its own approved architecture review.

---

## 32. Security Invariants for 5D

1. **Invariant 5D-1 (Zero Autonomous Containment)**: Under no circumstances shall Phase 3C-5D code execute active containment or disruption of candidate sessions, devices, or exam papers.
2. **Invariant 5D-2 (Append-Only Evidence & Comments)**: Evidence links and investigative comments cannot be updated or deleted by any user or API endpoint.
3. **Invariant 5D-3 (Authoritative Audit Integration)**: Every incident state change, assignment, reopen, and evidence link must emit a cryptographically signed event to the authoritative `AuditService`.
4. **Invariant 5D-4 (OCC Integrity)**: No incident record may be updated without matching the current database `version`.
5. **Invariant 5D-5 (Content Redaction)**: Question text, answer keys, candidate responses, and cryptographic secrets are strictly prohibited from incident titles, descriptions, dedup keys, comments, and metadata.
6. **Invariant 5D-6 (Authoritative Deduplication)**: Worker-side in-memory caches are non-authoritative. PostgreSQL transactional partial unique constraints constitute the sole authoritative duplicate-prevention boundary.
7. **Invariant 5D-7 (Acyclic Duplicates)**: Circular or self-referential duplicate relationships are strictly prevented by database constraints and application validation.
8. **Invariant 5D-8 (Inactivity Handover Liveness)**: **No single stable correlation identity may prevent legitimate creation of a new incident after the configured inactivity window has expired.**

---

## 33. Future Test Matrix (T01–T22)

When implementation is authorized, the following 22 unit and integration tests must pass:

- `T01_signal_ingestion_creates_incident`: Verifies valid advisory signal creates a new `TRIAGE` incident.
- `T02_stable_threat_vector_key_no_time_bucket`: Proves `threat_vector_key` computation contains zero time-bucket strings.
- `T03_rolling_inactivity_window_attaches_signal`: Signals arriving at 12:00, 12:59, and 13:58 attach to Generation 1.
- `T04_rolling_inactivity_window_expiration_rollover`: Signal arriving at 15:00 closes Generation 1 correlation window and creates Generation 2.
- `T05_coexistence_of_investigating_and_new_generation`: Verifies Generation 1 (`INVESTIGATING`, `CLOSED`) and Generation 2 (`TRIAGE`, `OPEN`) coexist in PostgreSQL without constraint violation.
- `T06_concurrent_creation_race_loser_attaches`: Concurrent worker race on same generation triggers `UniqueViolation`; losing worker catches and attaches evidence.
- `T07_concurrent_handover_race_serialization`: Concurrent workers arriving at 15:00 safely serialize generation handover without duplicate active generation.
- `T08_observational_contained_requires_audit_proof`: Transition to `CONTAINED` is rejected if `audit_event_reference` does not exist or fails cryptographic signature verification.
- `T09_5d_executes_zero_containment`: Verifies zero network, session, or exam disruption occurs upon entering `CONTAINED`.
- `T10_occ_version_conflict_409`: Stale version update returns HTTP 409 Conflict.
- `T11_reopen_transition_flow`: Reopening a `CLOSED` incident emits `INCIDENT_REOPENED` and returns case to `INVESTIGATING`.
- `T12_closed_does_not_delete`: Proves `CLOSED` preserves all database rows and audit records intact.
- `T13_duplicate_requires_valid_parent`: Setting `DUPLICATE` requires active parent; rejects invalid parent.
- `T14_circular_duplicate_prevention`: Acyclic validator rejects circular duplicate relationships (`A -> B -> A`).
- `T15_evidence_link_immutability`: Attempted SQL update/delete on `incident_evidence_links` is rejected.
- `T16_comment_sanitization_and_length`: Comments strip HTML/scripts and enforce 2000 character limit.
- `T17_comment_secret_screening`: Comments containing mock API keys or JWT patterns are rejected with HTTP 422.
- `T18_rbac_security_officer_vs_auditor`: Verifies `SECURITY_OFFICER` can mutate state; `AUDITOR` is strictly read-only.
- `T19_authoritative_audit_emission`: Every lifecycle transition produces a verifiable event in `AuditService`.
- `T20_ip_conflation_prevention`: Two candidates sharing an IP in the same exam produce separate incidents unless rule is infrastructure-scoped.
- `T21_generation_lineage_navigation`: Verifies `preceding_incident_id` correctly links sequential generations.
- `T22_human_resolution_closes_correlation`: Transitioning to `RESOLVED` automatically sets `correlation_status = 'CLOSED'`.

---

## 34. Prototype vs. Production Cryptography

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

## 35. Architectural Risks & Mitigations

1. **High-Velocity Signal Bursts**: Rapid arrival of hundreds of signals for an active threat vector. Mitigated by worker LRU rate damping and row-level locking (`FOR UPDATE`) on evidence attachment.
2. **Long-Running Investigations Blocking Telemetry**: In Rev-04, an analyst investigating for hours blocked new incident creation. Mitigated in Rev-05 by decoupling human `status` from `correlation_status`.
3. **Forged Containment Claims**: Analysts attempting to mark cases `CONTAINED` without verified action. Mitigated by automated cryptographic verification against the authoritative `AuditService` log.

---

## 36. Required Decisions Reconciliation

| Decision Area | Rev-04 Flawed Approach | Rev-05 Approved Architectural Solution |
| :--- | :--- | :--- |
| **Dedup Key & Inactivity** | Single key locked to active human status (`TRIAGE`/`INVESTIGATING`) | **Decoupled: Invariant `threat_vector_key` + dynamic `generation`** |
| **Inactivity Deadlock** | Deadlocked when incident remained in `INVESTIGATING` $>3600\text{s}$ | **Generation Handover: Closes correlation window, opens Generation $N+1$** |
| **Database Uniqueness** | `WHERE status IN ('TRIAGE', 'INVESTIGATING')` caused collisions | **`WHERE correlation_status = 'OPEN'` allows multi-generation coexistence** |
| **`CONTAINED` Proof** | Operator metadata was accepted as input | **Mandatory independent verification against sealed `AuditService` log** |
| **Production Crypto** | Ambiguous FIPS/HSM phrasing implied CloudHSM | **Standard AWS KMS Customer-Managed Keys (no CloudHSM requirement)** |

---

## 37. Proposed Implementation File List

When implementation is formally authorized, work will be confined strictly to these files:

### Backend Modules (New)
1. `backend/app/incidents/__init__.py`: Package initialization.
2. `backend/app/incidents/models.py`: SQLAlchemy ORM models (`SecurityIncident`, `IncidentEvidenceLink`, `IncidentComment`).
3. `backend/app/incidents/schemas.py`: Pydantic request/response schemas.
4. `backend/app/incidents/service.py`: Incident management business logic, generation handover engine, OCC checks, and audit verification.
5. `backend/app/incidents/router.py`: FastAPI REST API endpoints.
6. `backend/app/incidents/consumer.py`: SQS advisory signal ingestion worker.

### Database Migrations (New)
7. `alembic/versions/xxxx_phase3c_5d_incident_management.py`: Migration creating `security_incidents`, `incident_evidence_links`, `incident_comments`, composite unique generation constraint, and partial unique index for active correlation.

### Test Suite (New)
8. `tests/test_phase3c5d_incident_management.py`: Comprehensive test suite implementing T01–T22.

---

## 38. Explicit Implementation Preconditions

Before any implementation code is written, the following conditions must be met:
1. Rev-05 architecture is explicitly approved by the user.
2. Repository baseline remains at commit `7683dd6`.
3. Working tree remains clean with zero untracked code changes.
4. Test regression baseline remains at 240 passed, 5 skipped, 0 failed.

---

## 39. Final Architecture Verdict

**ARCHITECTURE APPROVED FOR IMPLEMENTATION PENDING USER REVIEW**

*(Implementation is NOT authorized. Awaiting your explicit review and authorization).*
