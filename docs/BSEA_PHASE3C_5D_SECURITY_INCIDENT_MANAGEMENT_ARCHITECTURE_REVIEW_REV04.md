# B-SEA Phase 3C-5D — Security Incident Management Foundation
## Final Architecture & Design Review (Rev-04)

**System:** Bharat Secure Examination Architecture (B-SEA)  
**Milestone:** Phase 3C-5D — Security Incident Management Foundation  
**Status:** ARCHITECTURE REVIEW REV-04 (FINAL ARCHITECTURE RECONCILIATION)  
**Document Revision:** Rev-04 (Reconciled against Rev-03 Mandatory Corrections 1–10)  
**Baseline Commit:** `7683dd6` (`feat: implement Phase 3C-5C detection correlation foundation`)  
**Baseline Verification:** `HEAD == origin/main` | Regression: 240 passed, 5 skipped, 0 failed  
**Governing Security Boundary:** Observational and Human-Managed Incident Case Workflow. **ZERO Autonomous Containment.**  

---

## 1. Executive Summary

Phase 3C-5D establishes the **Security Incident Management Foundation** for the Bharat Secure Examination Architecture (B-SEA). Where Phase 3C-5C delivered an observational, non-intrusive stream of deterministic, versioned advisory signals, Phase 3C-5D establishes the formal, auditable, and human-managed incident case lifecycle that ingests, triages, investigates, and resolves those signals.

### Final Reconciliation Summary (Rev-03 to Rev-04)
Rev-04 resolves the ten final mandatory architectural corrections:
1. **Authoritative Dedup Key (Time Bucket Removed)**: The authoritative `dedup_key` represents the stable incident correlation identity and strictly **does not contain any clock-hour, epoch, or time bucket**. The database uniqueness constraint operates on this stable identity. Sensitive data (questions, answers, credentials, keys, secrets) are strictly prohibited.
2. **Separation of Stable Identity from Rolling Correlation Window**: Defines the **Rolling Inactivity Correlation Window (3600 seconds)** separately from the stable identity. An active case remains eligible to receive new qualifying signals as long as the arrival gap between the latest correlated signal and the incoming signal is $\le 3600$ seconds. This 3600-second window is an inactivity threshold, **not an absolute incident lifetime**.
3. **Database Uniqueness & Inactive State Semantics**: Formally establishes that the PostgreSQL partial unique index (`WHERE status IN ('TRIAGE', 'INVESTIGATING')`) operates on active correlation states. Non-correlation-eligible states (`CONTAINED`, `RESOLVED`, `CLOSED`, `FALSE_POSITIVE`, `DUPLICATE`) release the constraint, allowing historical and active uniqueness to coexist safely. Clarifies that the correlation service determines eligibility while the database enforces concurrency boundaries.
4. **Authoritative PostgreSQL Concurrency vs. Worker LRU**: Formally establishes that worker LRU/hash caching is a **process-local optimization only**. PostgreSQL transactional partial uniqueness is the authoritative deduplication boundary. Defines the concurrent creation race resolution (catch `UniqueViolation`, query locked active row `FOR UPDATE`, attach evidence, never overwrite, audit, and commit) with zero last-write-wins and zero silent merging.
5. **Observational `CONTAINED` State Specification**: Defines `CONTAINED` strictly as an observational milestone recording external action. 5D executes **zero containment actions** (no session revocation, candidate blocking, device blocking, IP blocking, question quarantine, key rotation, or exam cancellation; all deferred to Phase 3C-5E). Mandates 5 immutable reference fields linking to the sealed audit chain.
6. **Legacy SecurityService Coexistence & Controlled Migration Boundary**: Freezes legacy `SecurityService`. 5D neither modifies nor relies on the legacy service. Decommissioning is classified as an independent future migration milestone, not a side-effect of Phase 3C-5E.
7. **Accurate Prototype vs. Production Cryptography**: Aligns with existing repository implementations. Prototype uses `MockKMS` (`backend/app/crypto/kms_interface.py`) with `AES-256-GCM` encryption and `Ed25519` signing. Production specifies AWS KMS customer-managed symmetric encryption and asymmetric Ed25519 signing keys. Eliminates unapproved CloudHSM / Custom Key Store requirements.
8. **Preservation of Approved Rev-03 Decisions**: Preserves actual repository RBAC roles (`SUPER_ADMIN`, `SECURITY_OFFICER`, `AUDITOR`, `EXAM_AUTHORITY`), 6-layer comment confidentiality model, evidence reference != evidence payload separation, OCC versioning, append-only comments, and strict traffic isolation.
9. **Final Clean Lifecycle**: Standardizes on the 7-state model (`TRIAGE`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `CLOSED`, `FALSE_POSITIVE`, `DUPLICATE`) with `REOPENED` as an auditable transition action (`CLOSED` $\to$ `INCIDENT_REOPENED` $\to$ `INVESTIGATING`).
10. **Five-Pillar Deduplication Architecture**: Documents Stable Correlation Identity, Rolling Inactivity Window, Active Incident Eligibility, Database Uniqueness, and Worker Optimization as five distinct, non-confusable architectural pillars.

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

## 3. Rev-03 Findings Reconciliation (Core Architectural Solutions)

### Finding 1: Authoritative Dedup Key (Removal of Time Bucket)
- **The Problem in Rev-03**: Rev-03 retained a clock-hour bucket (`time_window_start`) inside the SHA-256 `dedup_key`. This confounded correlation identity with time, causing clock-hour boundary splitting and preventing true multi-hour activity tracking.
- **Rev-04 Solution**: Eliminates time buckets from `dedup_key` entirely. The authoritative `dedup_key` represents the invariant correlation identity:
  $$\text{dedup\_key} = \text{SHA-256}\left(\text{canonical\_rule\_id} \mathbin{\Vert} \text{":"} \mathbin{\Vert} \text{dim\_key} \mathbin{\Vert} \text{":"} \mathbin{\Vert} \text{dim\_val} \mathbin{\Vert} \text{":"} \mathbin{\Vert} \text{exam\_id\_or\_GLOBAL} \mathbin{\Vert} \text{":"} \mathbin{\Vert} \text{policy\_version}\right)$$
  Sensitive examination data (questions, answer keys, candidate responses, credentials, tokens, cryptographic keys) are strictly prohibited.

### Finding 2: Rolling Inactivity Correlation Window
- **The Problem in Rev-03**: Treating correlation as a 1-hour fixed window implied that an incident had an absolute maximum lifespan of 60 minutes.
- **Rev-04 Solution**: Establishes the **Rolling Inactivity Correlation Window (3600 seconds)**. An active incident remains eligible to receive subsequent correlated signals as long as the gap between the latest attached signal (`latest_signal_at`) and the incoming signal is $\le 3600$ seconds. Active incidents can span hours or days under continuous activity.

### Finding 3: Database Uniqueness & State Semantics
- **The Problem in Rev-03**: Unclear explanation of how partial unique indexing interacts with historical incidents.
- **Rev-04 Solution**: Clarifies that PostgreSQL partial unique indexing operates strictly over correlation-eligible active states (`TRIAGE`, `INVESTIGATING`). Non-active states (`CONTAINED`, `RESOLVED`, `CLOSED`, `FALSE_POSITIVE`, `DUPLICATE`) are excluded from the index, allowing historical records with the same `dedup_key` to coexist permanently while strictly preventing duplicate active cases.

### Finding 4: Concurrent Creation Race
- **The Problem in Rev-03**: Ambiguity over the exact transaction flow when two distributed workers concurrently detect an incident.
- **Rev-04 Solution**: Worker LRU caches are explicitly non-authoritative. PostgreSQL transactional partial uniqueness acts as the sole authoritative boundary. Defines the transactional catch-and-attach sequence: the losing worker catches `UniqueViolation` (SQLSTATE `23505`), queries the winner's row `FOR UPDATE`, links its evidence, updates `latest_signal_at`, and audits the attachment without overwriting existing fields.

### Finding 5: Strictly Observational `CONTAINED` State
- **The Problem in Rev-03**: Potential risk of conflating incident recording with active containment execution.
- **Rev-04 Solution**: Explicitly prohibits Phase 3C-5D from executing containment actions. `CONTAINED` is an observational milestone recording external action. Mandates 5 immutable reference fields linking to an authoritative audit event proving the external operation.

### Finding 6: Legacy SecurityService Boundary
- **The Problem in Rev-03**: Stating that legacy `SecurityService` decommissioning is part of Phase 3C-5E conflated incident management with legacy refactoring.
- **Rev-04 Solution**: Freezes legacy `SecurityService`. Phase 3C-5D does not modify or invoke legacy unilateral containment endpoints. Decommissioning is defined as an independent, controlled migration milestone.

### Finding 7: Prototype vs. Production Cryptography Alignment
- **The Problem in Rev-03**: Describing `MockKMS` as "SHA-256 HMAC" was inaccurate relative to the codebase (`AES-256-GCM` + `Ed25519` + HKDF in `kms_interface.py`), and mandating AWS CloudHSM / Custom Key Store went beyond approved Phase 3C-3 architecture.
- **Rev-04 Solution**: Accurately maps the prototype to the implemented `MockKMS` abstraction (`AES-256-GCM` + `Ed25519`), and maps production to AWS KMS customer-managed symmetric and asymmetric keys without introducing unapproved HSM hardware requirements.

---

## 4. Existing Architecture Inspection

Before defining Phase 3C-5D, existing repository assets were forensically inspected:

1. **Phase 3C-5C Detection Architecture**:
   - `backend/app/detection/engine.py`: Evaluates advisory rules `R-001` through `R-007` against normalized audit events. Emits `AdvisorySignal` models.
   - `backend/app/detection/models.py`: Defines `AdvisorySignal` (fields: `signal_id`, `rule_id`, `rule_version`, `severity`, `title`, `description`, `context_dimensions`, `evidence_event_ids`, `emitted_at`).
   - `backend/app/detection/normalizer.py`: Normalizes heterogeneous audit logs into canonical fields.
   - Shadow mode enforcement: Detection engine operates strictly asynchronously in read-only shadow mode, publishing signals to an internal queue without mutating transaction paths.

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
     - `AWSKMSClient`: Production provider calling AWS KMS APIs (`GenerateDataKey`, `Sign`, `Verify`).

---

## 5. 5C → 5D Boundary

The boundary between Detection (5C) and Incident Management (5D) is strictly asynchronous, decoupled, and unidirectional:

```
+-------------------------------------------------------------------------+
| Phase 3C-5C: Detection & Correlation Engine (SHADOW MODE)               |
| - Evaluates normalized audit events against rules R-001 .. R-007        |
| - Produces AdvisorySignal (signal_id, canonical_rule_id, dimensions)    |
| - Dispatches to SQS / Celery advisory_signals queue                     |
+-------------------------------------------------------------------------+
                                     │
                                     │ (AdvisorySignal JSON Payload)
                                     ▼
+-------------------------------------------------------------------------+
| Phase 3C-5D: Security Incident Management Engine                        |
| - Consumes AdvisorySignal                                               |
| - Evaluates 5-Pillar Deduplication Model                                |
| - Creates or Attaches to SecurityIncident in PostgreSQL                 |
| - Exposes REST APIs for Security Officer Triage & Investigation        |
| - Emits Authoritative Audit Events via AuditService                     |
| - Observational CONTAINED milestone (ZERO autonomous containment)       |
+-------------------------------------------------------------------------+
                                     │
                                     │ (Read-only Reference Linking)
                                     ▼
+-------------------------------------------------------------------------+
| Authoritative Audit Log & Evidence Storage (PostgreSQL / S3)            |
+-------------------------------------------------------------------------+
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
   - Format: `INC-YYYYMMDD-XXXXX` (e.g., `INC-20260915-00042`)
   - Purpose: Human-readable tracking identifier used in analyst dashboards, support communications, and audit reports.
   - Generation: Generated deterministically via a dedicated PostgreSQL sequence (`incident_number_seq`) reset annually.

---

## 7. Final Clean Lifecycle & State Machine (Reconciling Finding 4 & 9)

Phase 3C-5D implements a clean, deterministic 7-state lifecycle. In accordance with architectural review findings, **`REOPENED` is modeled strictly as an auditable transition/action**, rather than a persistent lifecycle state.

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
3. **`CONTAINED`**: **Observational milestone**. Recorded only when authorized external containment (e.g. Phase 3C-5E) has taken place and valid external reference metadata is supplied.
4. **`RESOLVED`**: Technical remediation and root cause analysis completed by the assigned analyst.
5. **`CLOSED`**: Administrative sign-off completed by a supervisory authority (`SECURITY_OFFICER` or `SUPER_ADMIN`). **CLOSED represents administrative closure, never database deletion.**
6. **`FALSE_POSITIVE`**: Terminal evaluation determining the signal was benign or caused by benign platform telemetry.
7. **`DUPLICATE`**: Terminal consolidation state indicating the incident represents an event stream already tracked by an authoritative parent incident. Requires `duplicate_of_incident_id`.

### The `INCIDENT_REOPENED` Action
`REOPENED` is not a persistent state. When new evidence surfaces regarding a `RESOLVED` or `CLOSED` incident, an authorized analyst triggers the `INCIDENT_REOPENED` action:
$$\text{CLOSED} \xrightarrow[\text{Requires Justification + Audit}]{\text{INCIDENT\_REOPENED}} \text{INVESTIGATING}$$
This transition increments the incident `version`, records an immutable `INCIDENT_REOPENED` event in the audit chain, appends a system comment with analyst rationale, and returns the case to `INVESTIGATING`.

---

## 8. State Transition Matrix & Authority

Every state transition is strictly governed by RBAC, preconditions, OCC version checks, and mandatory audit logging:

| From State | To State | Action / Trigger | Authorized Role | Preconditions & Requirements | Required Audit Event |
| :--- | :--- | :--- | :--- | :--- | :--- |
| *(None)* | `TRIAGE` | `CREATE_INCIDENT` | System (Worker) | Qualifying advisory signal received | `INCIDENT_CREATED` |
| `TRIAGE` | `INVESTIGATING` | `START_INVESTIGATION` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Analyst assigned; initial assessment documented | `INCIDENT_STATUS_CHANGED` |
| `TRIAGE` | `FALSE_POSITIVE` | `MARK_FALSE_POSITIVE` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Mandatory justification comment ($\ge 20$ chars) | `INCIDENT_STATUS_CHANGED` |
| `TRIAGE` | `DUPLICATE` | `MARK_DUPLICATE` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Valid `duplicate_of_incident_id` supplied; acyclic check passed | `INCIDENT_STATUS_CHANGED` |
| `INVESTIGATING`| `CONTAINED` | `RECORD_CONTAINMENT` | `SECURITY_OFFICER`, `SUPER_ADMIN` | 5 external reference fields verified; external audit event exists | `INCIDENT_STATUS_CHANGED` |
| `INVESTIGATING`| `RESOLVED` | `RESOLVE_INCIDENT` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Resolution summary and category provided | `INCIDENT_STATUS_CHANGED` |
| `INVESTIGATING`| `FALSE_POSITIVE` | `MARK_FALSE_POSITIVE` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Mandatory justification comment ($\ge 20$ chars) | `INCIDENT_STATUS_CHANGED` |
| `INVESTIGATING`| `DUPLICATE` | `MARK_DUPLICATE` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Valid `duplicate_of_incident_id` supplied; acyclic check passed | `INCIDENT_STATUS_CHANGED` |
| `CONTAINED` | `RESOLVED` | `RESOLVE_INCIDENT` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Resolution summary and category provided | `INCIDENT_STATUS_CHANGED` |
| `RESOLVED` | `CLOSED` | `CLOSE_INCIDENT` | `SUPER_ADMIN`, `SECURITY_OFFICER` | Supervisory review completed; administrative sign-off | `INCIDENT_CLOSED` |
| `RESOLVED` | `INVESTIGATING`| `INCIDENT_REOPENED` | `SECURITY_OFFICER`, `SUPER_ADMIN` | New evidence identified; mandatory justification | `INCIDENT_REOPENED` |
| `CLOSED` | `INVESTIGATING`| `INCIDENT_REOPENED` | `SUPER_ADMIN` | New evidence identified; supervisor authorization + audit | `INCIDENT_REOPENED` |

### Forbidden Transitions
- `CLOSED` $\to$ `RESOLVED` (Direct reversal forbidden; must reopen to `INVESTIGATING`).
- `CLOSED` $\to$ `FALSE_POSITIVE` / `DUPLICATE` (Administrative closure is final unless reopened).
- `FALSE_POSITIVE` $\to$ `CONTAINED` / `RESOLVED` (Direct progression forbidden).
- `DUPLICATE` $\to$ `CONTAINED` / `RESOLVED` (A duplicate cannot be independently resolved).
- Any state $\to$ *(Deletion)* (**DATABASE DELETION IS PERMANENTLY FORBIDDEN**).

---

## 9. Deduplication Model & Architecture (Reconciling Findings 1, 2, 3, 10)

Phase 3C-5D establishes a **Five-Pillar Deduplication Model** that strictly separates identity, time, state eligibility, persistence, and caching.

```
+─────────────────────────────────────────────────────────────────────────────+
|                    THE FIVE PILLARS OF 5D DEDUPLICATION                     |
+─────────────────────────────────────────────────────────────────────────────+
|  PILLAR A: STABLE CORRELATION IDENTITY                                      |
|  - Invariant SHA-256 hash over canonical rule + dimensions + exam scope    |
|  - STRICTLY ZERO time-bucket / clock-hour encoding                          |
+─────────────────────────────────────────────────────────────────────────────+
                                     │
                                     ▼
+─────────────────────────────────────────────────────────────────────────────+
|  PILLAR B: ROLLING INACTIVITY CORRELATION WINDOW                            |
|  - Bounded 3600-second inactivity threshold: (t_signal - t_latest) <= 3600  |
|  - An incident remains active as long as signals arrive within 3600s        |
|  - NOT an absolute incident lifetime (can span days under continuous load)  |
+─────────────────────────────────────────────────────────────────────────────+
                                     │
                                     ▼
+─────────────────────────────────────────────────────────────────────────────+
|  PILLAR C: ACTIVE INCIDENT ELIGIBILITY                                      |
|  - Correlation eligibility restricted to: TRIAGE and INVESTIGATING          |
|  - Inactive states (CONTAINED, RESOLVED, CLOSED, etc.) release correlation  |
+─────────────────────────────────────────────────────────────────────────────+
                                     │
                                     ▼
+─────────────────────────────────────────────────────────────────────────────+
|  PILLAR D: AUTHORITATIVE DATABASE UNIQUENESS                                |
|  - PostgreSQL Partial Unique Index: WHERE status IN ('TRIAGE','INVESTIGATING')|
|  - Authoritative concurrency boundary; enforces atomic serialize/catch      |
+─────────────────────────────────────────────────────────────────────────────+
                                     │
                                     ▼
+─────────────────────────────────────────────────────────────────────────────+
|  PILLAR E: WORKER-SIDE OPTIMIZATION LAYER                                   |
|  - Process-local LRU / hash cache for rate damping only                     |
|  - Strictly non-authoritative; zero reliance for correctness               |
+─────────────────────────────────────────────────────────────────────────────+
```

### 9.1 Pillar A: Stable Incident Correlation Identity (No Time Bucket)
The `dedup_key` represents the permanent, stable correlation identity of the threat vector. It is computed deterministically as:
$$\text{raw\_identity} = \text{canonical\_rule\_id} \mathbin{\Vert} \text{":"} \mathbin{\Vert} \text{dim\_key} \mathbin{\Vert} \text{":"} \mathbin{\Vert} \text{dim\_val} \mathbin{\Vert} \text{":"} \mathbin{\Vert} \text{exam\_id\_or\_GLOBAL} \mathbin{\Vert} \text{":"} \mathbin{\Vert} \text{policy\_version}$$
$$\text{dedup\_key} = \text{SHA-256}(\text{raw\_identity})$$

#### Invariants:
- **Zero Time Bucketing**: The `dedup_key` **strictly does not contain** clock hours, calendar dates, epoch timestamps, or time windows.
- **Rule ID Normalization**: Uses `canonical_rule_id` (e.g. `R-003`). Semantic rule engine version suffixes (e.g. `.v1`, `.v2`) are stripped to prevent rule revisions from artificially fragmenting active incidents.
- **Strict Content Redaction**: The `dedup_key` and its components **MUST NOT** contain:
  - Question text or question identifiers
  - Answer keys or scoring criteria
  - Candidate responses or exam submissions
  - Plaintext examination material
  - Candidate passwords or credential hashes
  - JWTs, auth tokens, or session keys
  - DEKs, KEKs, or cryptographic keys
  - Secrets or private key material

### 9.2 Pillar B: Rolling Inactivity Correlation Window (3600 Seconds)
The time dimension is governed by a **Rolling Inactivity Correlation Window** ($W_{\text{inactivity}} = 3600\text{ seconds}$), defined entirely outside the `dedup_key`:
- **Eligibility Check**: An active incident is eligible to correlate an incoming signal if and only if:
  $$t_{\text{signal}} - t_{\text{latest\_signal\_at}} \le 3600\text{ seconds}$$
- **Window Extension**: When a qualifying signal attaches, `latest_signal_at` is updated to $\max(t_{\text{latest\_signal\_at}}, t_{\text{signal}})$, extending the rolling window by another 3600 seconds from the arrival time of the new signal.
- **Concrete Example**:
  - `12:00:00` — Signal 1 arrives $\to$ Incident `INC-1` created (`first_signal_at` = 12:00, `latest_signal_at` = 12:00).
  - `12:59:00` — Signal 2 arrives (gap = 59m $\le$ 60m) $\to$ Attaches to `INC-1` (`latest_signal_at` updated to 12:59).
  - `13:58:00` — Signal 3 arrives (gap = 59m $\le$ 60m) $\to$ Attaches to `INC-1` (`latest_signal_at` updated to 13:58).
  - `15:00:00` — Signal 4 arrives (gap = 62m > 60m) $\to$ Rolling inactivity window expired. `INC-1` is no longer eligible for normal correlation. Signal 4 initiates a new incident case.
- **Critical Distinction**: The 3600-second window is an **inactivity threshold**, not an absolute lifespan. Under sustained attack traffic, an incident may remain active and accumulate correlated evidence across many hours or days.

### 9.3 Pillar C: Active Incident Eligibility
Correlation eligibility is strictly bound to the incident lifecycle state:
- **Eligible States**: `TRIAGE`, `INVESTIGATING`.
- **Non-Eligible States**: `CONTAINED`, `RESOLVED`, `CLOSED`, `FALSE_POSITIVE`, `DUPLICATE`.
Once an incident transitions out of `TRIAGE` or `INVESTIGATING`, it is considered inactive for incoming signal correlation. Subsequent signals matching the same stable correlation identity will not attach to the resolved case; they will initiate a new incident.

### 9.4 Pillar D: Authoritative Database Uniqueness Enforcement
The authoritative duplicate-prevention boundary is enforced solely by PostgreSQL:
```sql
CREATE UNIQUE INDEX uq_active_incident_dedup 
ON security_incidents (dedup_key) 
WHERE status IN ('TRIAGE', 'INVESTIGATING');
```
- **Active Uniqueness**: PostgreSQL enforces that at most **one** incident row with a given `dedup_key` can exist in `TRIAGE` or `INVESTIGATING` at any point in time across the entire cluster.
- **Historical Coexistence**: Because the index is partial, historical rows in `RESOLVED`, `CLOSED`, `FALSE_POSITIVE`, or `DUPLICATE` are excluded. Multiple historical incidents sharing the same `dedup_key` can coexist permanently without constraint violation.
- **Division of Responsibility**:
  - **Correlation Service**: Evaluates business logic (checks if an active incident exists and whether the incoming signal is within the 3600s rolling window).
  - **Database Constraint**: Enforces physical atomicity, preventing concurrent race conditions between distributed workers.

### 9.5 Pillar E: Worker-Side Optimization Layer (Non-Authoritative)
- **Local LRU Cache**: Workers maintain a bounded, process-local in-memory LRU cache (`capacity = 10,000`, `ttl = 60s`) mapping recent `dedup_key` hashes to incident IDs.
- **Rate Damping Only**: The cache exists purely to damp high-frequency signal bursts (e.g. 500 signals/sec for the same node) and reduce database query pressure.
- **Non-Authoritative**: The cache has zero authority over correctness. Node crashes, worker restarts, or cache evictions have zero impact on system correctness. All state verification terminates at PostgreSQL.

### 9.6 Deterministic Serialization, Normalization, & Redaction
To guarantee that identical threats produce identical `dedup_key` digests across different workers and runtimes, inputs are normalized via strict canonicalization:
1. `canonical_rule_id`: Trimmed, uppercase ASCII (e.g., `"R-003"`).
2. `dim_key`: Trimmed, lowercase ASCII (e.g., `"node_id"`, `"candidate_id"`).
3. `dim_val`: Normalized by type:
   - UUIDs: Lowercase hexadecimal with standard hyphens (8-4-4-4-12).
   - IPv4/IPv6: Fully exploded canonical format via `ipaddress.ip_address(val).exploded`.
   - Node/Host IDs: Trimmed, uppercase ASCII.
4. `exam_id_or_GLOBAL`: Lowercase UUID for exam-scoped events; literal string `"GLOBAL"` for platform or infrastructure events.
5. `policy_version`: Lowercase version identifier (e.g., `"v1"`).

### 9.7 Addressing the IP Conflation Anti-Pattern
Phase 3C-5D explicitly forbids the assumptions:
$$\text{Same IP} \implies \text{Same Actor}$$
$$\text{Same IP} \implies \text{Same Incident}$$
In proctored examination environments, multiple legitimate candidates frequently share an egress IP due to institutional NAT, campus firewalls, or test-center gateways. Therefore:
- Rules dimensioned on `ip_address` must qualify the dimension with `exam_id`.
- The correlation engine never aggregates distinct candidate identities into a single incident based solely on shared IP address unless the rule is explicitly flagged as a network-infrastructure rule (e.g., distributed DDoS or credential stuffing).

---

## 10. Authoritative Transactional Deduplication vs. Worker LRU (Reconciling Finding 4)

In a distributed container deployment (e.g., AWS ECS Fargate), multiple independent workers process advisory signals concurrently from SQS. Worker LRU caches are isolated and cannot coordinate.

### The Concurrent Creation Race Flow

```
Worker A (Pod 1)                                       Worker B (Pod 2)
      │                                                      │
      │ Receives Signal 1 (dedup_key = K)                    │ Receives Signal 2 (dedup_key = K)
      │ Queries DB: No active incident                       │ Queries DB: No active incident
      │                                                      │
      ├────────────────── PostgreSQL Transaction ───────────┤
      │                                                      │
      │ INSERT INTO security_incidents                       │ INSERT INTO security_incidents
      │ (dedup_key = K, status = 'TRIAGE')                   │ (dedup_key = K, status = 'TRIAGE')
      │                                                      │
      ▼ [WINNER]                                             ▼ [LOSER]
  Transaction Commits (HTTP 201)                         UniqueViolation (SQLSTATE 23505)
  Incident INC-1 Created                                 Constraint: uq_active_incident_dedup
                                                             │
                                                             │ CATCH IntegrityError
                                                             ▼
                                                         SELECT id, version, latest_signal_at
                                                         FROM security_incidents
                                                         WHERE dedup_key = K 
                                                           AND status IN ('TRIAGE', 'INVESTIGATING')
                                                         FOR UPDATE;
                                                             │
                                                             │ [Acquires Row Lock on INC-1]
                                                             │
                                                             │ INSERT INTO incident_evidence_links
                                                             │ (incident_id, evidence_event_id, ...)
                                                             │
                                                             │ UPDATE security_incidents
                                                             │ SET latest_signal_at = MAX(latest_signal_at, t_signal),
                                                             │     updated_at = NOW()
                                                             │ WHERE id = INC-1.id;
                                                             │
                                                             │ Emit Audit: INCIDENT_EVIDENCE_ATTACHED
                                                             ▼
                                                         Transaction Commits (HTTP 200)
                                                         Signal Attached Safely
```

### Race Resolution Guarantees:
1. **Zero Last-Write-Wins**: The losing transaction never overwrites the authoritative fields (`title`, `description`, `created_at`, `assigned_to`, `severity`) written by the winning transaction.
2. **Zero Silent Merging**: The attachment of Signal 2 generates an explicit row in `incident_evidence_links` and logs an `INCIDENT_EVIDENCE_ATTACHED` event to the immutable audit chain.
3. **Strict Atomicity**: The `FOR UPDATE` lock ensures sequential attachment of evidence without lost updates or race conditions during high-concurrency signal storms.

---

## 11. Observational `CONTAINED` State Specification (Reconciling Finding 5)

Phase 3C-5D is **STRICTLY OBSERVATIONAL**. Phase 3C-5D contains **zero** active mitigation, enforcement, or containment logic.

### 5D Does NOT Execute:
- Revoking candidate tokens or sessions
- Blocking candidate logins or exam access
- Blocking client IP addresses or CIDRs
- Disabling or isolating examination workstations
- Quarantining examination questions or question banks
- Triggering cryptographic key rotations
- Terminating or rescheduling examinations
- Executing emergency automated containment scripts

*All active containment capabilities belong strictly to Phase 3C-5E.*

### Observational Verification & Schema
An incident may enter `CONTAINED` exclusively when an authorized operator records that an external, authorized containment action has already occurred. The transition payload strictly mandates 5 reference fields:

```json
{
  "containment_reference_id": "CONT-20260915-8841",
  "authorization_principal": "usr_sec_officer_042",
  "containment_timestamp": "2026-09-15T18:30:00Z",
  "containment_mechanism": "PHASE_3C_5E_WORKFLOW",
  "audit_event_reference": "aud_evt_99b78a12e4f04c1a"
}
```

#### Field Specifications:
1. **`containment_reference_id`** (`VARCHAR(128)`): The external ticket identifier, execution ID, or workflow ARN of the containment action.
2. **`authorization_principal`** (`VARCHAR(128)`): The unique identifier of the security officer or authority who approved the containment.
3. **`containment_timestamp`** (`TIMESTAMPTZ`): The precise UTC timestamp when containment was executed externally.
4. **`containment_mechanism`** (`VARCHAR(64)`): Enumerated mechanism proving the method of containment:
   - `PHASE_3C_5E_WORKFLOW` (Future Phase 3C-5E automated/supervised response)
   - `AWS_WAF_AUTOMATION` (External perimeter rate-limit/ACL block)
   - `IAM_CREDENTIAL_REVOCATION` (External AWS IAM session revocation)
   - `MANUAL_EXAM_HALL_ISOLATION` (Physical/network disconnect verified by test center invigilator)
5. **`audit_event_reference`** (`VARCHAR(128)`): The cryptographic hash, sequence ID, or UUID of the authoritative audit log record proving the external containment operation occurred.

---

## 12. Evidence Reference Architecture

Phase 3C-5D adheres strictly to the architectural separation:
$$\text{Evidence Reference} \neq \text{Evidence Payload}$$

Incidents do not store raw event logs, HTTP payloads, or candidate data. Storing raw data in incident tables creates severe security vulnerabilities, including data duplication, cache leakage, and inadvertent exposure of sensitive exam materials.

### `incident_evidence_links` Table
Instead, 5D stores cryptographically signed, immutable pointers into the authoritative audit chain:

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | UUID | PRIMARY KEY | Unique link identifier |
| `incident_id` | UUID | NOT NULL, FK `security_incidents(id)` | Parent incident case |
| `evidence_type` | VARCHAR(32) | NOT NULL | `AUDIT_EVENT`, `DETECTION_SIGNAL`, `CLOUDTRAIL_EVENT` |
| `evidence_reference_id` | VARCHAR(128) | NOT NULL | UUID or sequence ID of the target audit event |
| `evidence_hash` | CHAR(64) | NOT NULL | SHA-256 hash of the target record at time of link |
| `attached_by` | UUID | NOT NULL, FK `users(id)` | System worker UUID or analyst UUID |
| `attached_at` | TIMESTAMPTZ | NOT NULL DEFAULT NOW() | Timestamp of attachment |

- **Immutability**: `incident_evidence_links` has **zero** update or delete endpoints. Once linked, evidence cannot be altered or removed.
- **Integrity Verification**: The `evidence_hash` allows analysts to verify that the underlying audit record in PostgreSQL or S3 has not been tampered with since the incident was opened.

---

## 13. Evidence Access Control

Viewing linked evidence is governed by least-privilege role-based access control:
1. **Metadata vs. Payload Separation**: Any analyst with incident read access can view evidence metadata (`evidence_type`, `evidence_reference_id`, `attached_at`).
2. **Payload Resolution**: Resolving the raw audit payload requires fetching the record from `AuditService`. The analyst must possess explicit read permissions for the specific audit domain (e.g., `audit:read`).
3. **Candidate PII Masking**: Raw audit payloads containing candidate identifying information are dynamically masked at the API gateway layer unless the analyst holds the `SUPER_ADMIN` or `EXAM_AUTHORITY` role with an active, audited justification ticket.
4. **Examination Content Redaction**: Questions, options, and answer keys are never stored in the audit chain or incident tables, eliminating leakage risks entirely.

---

## 14. RBAC Model & Repository Role Alignment

Phase 3C-5D introduces **zero new roles**. It aligns strictly with the existing, authoritative `UserRoleEnum` in `backend/app/core/models.py`:

| Role Enum | 5D Incident Management Permissions |
| :--- | :--- |
| **`SUPER_ADMIN`** | Full incident management authority: view, assign, triage, investigate, contain (record), resolve, close, reopen, and perform forensic export. |
| **`SECURITY_OFFICER`** | Primary operational authority: view, assign, triage, investigate, contain (record), resolve, reopen, and add comments/evidence. Cannot administratively close high-impact incidents without supervisory review. |
| **`AUDITOR`** | Strictly read-only compliance authority: view all incidents, inspect timelines, view audit links, and verify cryptographic evidence chains. Cannot modify state, assign cases, or post comments. |
| **`EXAM_AUTHORITY`** | Read-only executive oversight: view aggregate incident metrics, view high-severity incident summaries affecting exam delivery. Cannot view raw telemetry, modify state, or assign cases. |
| *Candidate / Proctor* | **Zero Access**: Incident management APIs are completely inaccessible to examinees, test proctors, and public endpoints. |

---

## 15. Analyst Assignment

- **Assignment Target**: Incidents can be assigned to any active user possessing the `SECURITY_OFFICER` or `SUPER_ADMIN` role.
- **Concurrency & Self-Assignment**: Analysts can assign incidents to themselves or reassign them to team members.
- **Audit Requirement**: Every assignment or reassignment updates `assigned_to`, increments the incident `version`, and logs an immutable `INCIDENT_ASSIGNED` event recording the previous analyst, new analyst, and authorizing user.
- **Unassigned Triage**: New incidents created from advisory signals initialize with `assigned_to = NULL`.

---

## 16. 6-Layer Defense-in-Depth Comment Confidentiality Model

Incident comments frequently contain sensitive investigative notes. Phase 3C-5D protects comments through a comprehensive 6-layer defense model:

1. **Layer 1: Structural Plaintext Storage**: The database column `incident_comments.comment_text` stores strictly unformatted, sanitized plaintext. HTML, Markdown rendering, scripts, and executable tags are stripped before persistence, preventing stored XSS.
2. **Layer 2: Hard Character Limits**: Comment length is constrained to $2,000$ characters maximum, preventing payload injection, buffer abuse, and database bloat.
3. **Layer 3: Pre-Commit Secret & Exam Screening**: An automated secondary regex filter screens submitted comment text prior to database commit. Comments matching patterns for JWTs, private keys, AWS access keys, or question-content identifiers are rejected with HTTP 422 Unprocessable Entity.
4. **Layer 4: Append-Only Immutability**: The `incident_comments` table allows **zero updates and zero deletions**. Analysts cannot edit or erase past notes. Corrective notes must be added as new append-only comments.
5. **Layer 5: Sealed PostgreSQL Audit Integration**: Every comment creation emits an `INCIDENT_COMMENT_ADDED` audit event, capturing the comment hash, author UUID, and timestamp in the sealed Ed25519 audit chain.
6. **Layer 6: Read-Side Role Masking**: When comments are fetched via API, internal system flags or sensitive investigation markers are dynamically redacted based on the requesting user's RBAC role.

---

## 17. Concurrency Strategy & OCC

To prevent lost updates, race conditions, and inconsistent state transitions in a distributed multi-analyst environment, Phase 3C-5D implements **Optimistic Concurrency Control (OCC)**:

1. **`version` Column**: Every row in `security_incidents` possesses an integer `version` column, initialized to `1` upon creation.
2. **Atomic Update Enforcement**: All update and transition operations execute SQL with version predicates:
   ```sql
   UPDATE security_incidents
   SET status = :new_status,
       version = version + 1,
       updated_at = NOW()
   WHERE id = :incident_id AND version = :expected_version;
   ```
3. **HTTP 409 Conflict**: If the query updates 0 rows, another analyst or worker updated the record concurrently. The API immediately aborts the transaction and returns `HTTP 409 Conflict` with the current incident state, forcing the client to refresh and re-evaluate.

---

## 18. Severity Model

Incident severity is governed by an enumerated scale based on platform impact and security threat:

| Severity | Definition | Target Triage SLA | Target Resolution SLA |
| :--- | :--- | :--- | :--- |
| **`CRITICAL`** | Direct compromise of examination integrity, active key compromise, or large-scale candidate disruption. | 15 Minutes | 2 Hours |
| **`HIGH`** | Targeted exam tampering attempt, unauthorized administrative access, or systemic node failures. | 30 Minutes | 6 Hours |
| **`MEDIUM`** | Repeated biometric/liveness anomalies, suspicious multi-session attempts, or abnormal API velocity. | 2 Hours | 24 Hours |
| **`LOW`** | Isolated client network glitch, non-critical workstation drift, or minor configuration anomaly. | 8 Hours | 72 Hours |
| **`INFO`** | Observational telemetry notice, routine security drill marker, or scheduled maintenance notice. | 24 Hours | Best Effort |

---

## 19. Incident Types

Standardized taxonomy for categorization and reporting:
- `INTEGRITY_TAMPERING`: Unauthorized attempt to alter candidate responses, exam timers, or audit logs.
- `AUTHENTICATION_ANOMALY`: Credential stuffing, simultaneous multi-device logins, or token hijacking.
- `EXAM_LEAK_ATTEMPT`: Suspicious workstation screen scraping, rapid question navigation, or clipboard scraping.
- `INFRASTRUCTURE_ATTACK`: Network flood, unauthorized API probing, KMS request surge, or container escape attempt.
- `WORKSTATION_TAMPERING`: Secure browser bypass, VM detection trigger, peripheral injection, or secondary display.
- `AUDIT_FAILURE`: Cryptographic verification mismatch, sealer failure, or quarantine threshold breach.

---

## 20. Incident Timeline

The incident timeline provides an immutable, chronological reconstruction of all activity surrounding a case. The timeline is synthesized dynamically from three authoritative sources:
1. **Linked Advisory Signals**: Historical signals linked to the case via `incident_evidence_links`.
2. **Audit Log Events**: State transitions, assignments, re-openings, and containment records emitted by `AuditService`.
3. **Analyst Comments**: Append-only investigative notes from `incident_comments`.

Timelines are queried chronologically by `timestamp ASC` and support filtering by event category.

---

## 21. Audit Integration

Phase 3C-5D introduces **zero secondary or shadow audit tables**. All incident management events are emitted directly to the platform's authoritative `AuditService` (`backend/app/audit/service.py`):

```python
await audit_service.log_security_event(
    event_type="INCIDENT_STATUS_CHANGED",
    actor_id=str(current_user.id),
    resource_id=str(incident.id),
    details={
        "incident_number": incident.incident_number,
        "old_status": old_status,
        "new_status": new_status,
        "version": incident.version,
        "justification": justification_text
    }
)
```

### Audited 5D Event Types:
- `INCIDENT_CREATED`: Ingestion of initial qualifying advisory signal.
- `INCIDENT_EVIDENCE_ATTACHED`: Correlated signal or secondary evidence linked.
- `INCIDENT_STATUS_CHANGED`: State transition executed.
- `INCIDENT_ASSIGNED`: Analyst ownership assigned or transferred.
- `INCIDENT_COMMENT_ADDED`: Investigative note appended.
- `INCIDENT_REOPENED`: Terminal case reopened with supervisory justification.
- `INCIDENT_CLOSED`: Administrative closure completed.

---

## 22. Database Schema Proposal (Reconciling Findings 1–4)

Phase 3C-5D proposes three relational tables in the PostgreSQL database:

```sql
-- 1. Incidents Table
CREATE TABLE security_incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_number VARCHAR(32) UNIQUE NOT NULL,
    dedup_key CHAR(64) NOT NULL,
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
    duplicate_of_incident_id UUID NULL REFERENCES security_incidents(id),
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
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
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

## 23. Constraints and Indexes

```sql
-- Authoritative Concurrency Boundary: Partial Unique Index for Active Cases
CREATE UNIQUE INDEX uq_active_incident_dedup 
ON security_incidents (dedup_key) 
WHERE status IN ('TRIAGE', 'INVESTIGATING');

-- Operational Query Indexes
CREATE INDEX ix_incidents_status ON security_incidents (status);
CREATE INDEX ix_incidents_severity ON security_incidents (severity);
CREATE INDEX ix_incidents_assigned_to ON security_incidents (assigned_to);
CREATE INDEX ix_incidents_exam_id ON security_incidents (exam_id);
CREATE INDEX ix_incidents_latest_signal ON security_incidents (latest_signal_at DESC);
CREATE INDEX ix_incidents_created_at ON security_incidents (created_at DESC);

-- Evidence & Comment Query Indexes
CREATE INDEX ix_evidence_incident_id ON incident_evidence_links (incident_id);
CREATE INDEX ix_comments_incident_id ON incident_comments (incident_id, created_at ASC);

-- Acyclic Check Constraint (Self-reference prevention)
ALTER TABLE security_incidents 
ADD CONSTRAINT ck_no_self_duplicate 
CHECK (duplicate_of_incident_id IS NULL OR duplicate_of_incident_id != id);
```

---

## 24. Retention and Deletion Policy

- **Hard Deletion Strictly Forbidden**: The database user granted to application services possesses **zero `DELETE` privileges** on `security_incidents`, `incident_evidence_links`, and `incident_comments`.
- **Statutory Retention**: In compliance with national examination security standards, all incident cases, evidence references, and investigative comments are retained for a minimum of **7 years**.
- **Cold Storage Archive**: After 180 days in `CLOSED` status, an automated partition archival job writes signed, cold-storage parquet summaries to an immutable, KMS-encrypted S3 bucket with Object Lock enabled.

---

## 25. API Architecture

All endpoints are mounted under `/api/v1/incidents` and require authentication and RBAC authorization:

| Method | Path | Required Role | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/incidents` | `SECURITY_OFFICER`, `SUPER_ADMIN`, `AUDITOR`, `EXAM_AUTHORITY` | List incidents with filtering (status, severity, exam, date range) and pagination. |
| `GET` | `/api/v1/incidents/{id}` | `SECURITY_OFFICER`, `SUPER_ADMIN`, `AUDITOR`, `EXAM_AUTHORITY` | Get detailed incident record by UUID. |
| `POST` | `/api/v1/incidents/{id}/transition` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Transition lifecycle state. Requires OCC `version` check and mandatory payload fields. |
| `POST` | `/api/v1/incidents/{id}/assign` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Assign or reassign incident to an analyst. Requires OCC `version`. |
| `POST` | `/api/v1/incidents/{id}/comments` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Append an investigative note (sanitized plaintext, $\le 2000$ chars). |
| `GET` | `/api/v1/incidents/{id}/comments` | `SECURITY_OFFICER`, `SUPER_ADMIN`, `AUDITOR` | Retrieve comment thread chronologically. |
| `POST` | `/api/v1/incidents/{id}/evidence` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Attach an audit event or telemetry reference as evidence. |
| `GET` | `/api/v1/incidents/{id}/timeline` | `SECURITY_OFFICER`, `SUPER_ADMIN`, `AUDITOR` | Get unified chronological activity timeline. |

---

## 26. Frontend / Analyst UI Architecture

1. **Incident Dashboard**: Real-time triage view displaying active cases grouped by severity, SLA urgency countdown, and unassigned status.
2. **Case Detail Workspace**: Two-column layout:
   - *Left Column*: Metadata summary, lifecycle state stepper, severity badge, assigned analyst, and OCC version indicator.
   - *Right Column*: Tabbed investigation container (Timeline, Evidence Links, Comment Thread, Containment Verification).
3. **Action Modals**: Dedicated forms for State Transitions, Containment Metadata Entry, Assignment, and Resolution Summaries with client-side validation.
4. **Optimistic Updates & Conflict Handling**: If an analyst attempts an action on a stale record, the UI intercepts HTTP 409, halts the optimistic update, displays a collision notification, and pulls fresh data.

---

## 27. Failure Semantics

- **Database Down**: Signal ingestion worker halts consumption and leaves messages in SQS with exponential backoff. No signals are dropped.
- **Audit Service Unavailable**: State transitions and incident creations fail closed (transaction rollback) if `AuditService.log_security_event()` fails.
- **Signal Parse Failure**: Malformed or unparseable advisory signals are rejected and routed to the dead-letter queue (DLQ) for forensic quarantine.

---

## 28. 5D vs 5E Boundary

| Architectural Concern | Phase 3C-5D (Incident Management) | Phase 3C-5E (Autonomous/Supervised Containment) |
| :--- | :--- | :--- |
| **Primary Responsibility** | Human investigation, triage, state tracking, evidence collation. | Active threat mitigation, isolation, policy enforcement. |
| **Containment Action** | **Strictly Observational** (records external action). | **Active Execution** (session revocation, workstation isolation). |
| **Automation Boundary** | Ingests signals $\to$ Creates cases. Zero enforcement. | Evaluates policy $\to$ Executes automated containment workflows. |
| **Database Authority** | Authoritative owner of `security_incidents` tables. | Consumes incident events; updates containment status via 5D API. |

---

## 29. 5D vs 5F Boundary

| Architectural Concern | Phase 3C-5D (Incident Management) | Phase 3C-5F (External SIEM / SOC Integration) |
| :--- | :--- | :--- |
| **Primary Scope** | Platform-internal security incident lifecycle. | External SIEM export (Splunk, Elastic, Datadog), webhook alerts. |
| **Data Flow Direction** | Internal SQS $\to$ 5D PostgreSQL. | 5D Audit Chain / S3 $\to$ External SOC ingestion pipeline. |
| **Authentication** | B-SEA Internal RBAC (`UserRoleEnum`). | External mTLS, API keys, and IAM role federation. |

---

## 30. Legacy SecurityService Coexistence & Controlled Migration Boundary (Reconciling Finding 6)

1. **Legacy Freeze**: The legacy `SecurityService` (`backend/app/services/security_service.py`) remains **strictly frozen**.
2. **Zero Modification**: Phase 3C-5D introduces no changes to `SecurityService` code, schemas, or endpoints.
3. **No Reliance on Unilateral Containment**: 5D does not call legacy containment endpoints (`isolate_node`, `terminate_session`).
4. **Controlled Migration Milestone**: Decommissioning or migrating the legacy security service is a separate, dedicated architectural milestone. Phase 3C-5E may consume or migrate specific containment capabilities only if explicitly authorized by its own approved architecture review.

---

## 31. Security Invariants for 5D

1. **Invariant 5D-1 (Zero Autonomous Containment)**: Under no circumstances shall Phase 3C-5D code execute active containment or disruption of candidate sessions, devices, or exam papers.
2. **Invariant 5D-2 (Append-Only Evidence & Comments)**: Evidence links and investigative comments cannot be updated or deleted by any user or API endpoint.
3. **Invariant 5D-3 (Authoritative Audit Integration)**: Every incident state change, assignment, reopen, and evidence link must emit a cryptographically signed event to the authoritative `AuditService`.
4. **Invariant 5D-4 (OCC Integrity)**: No incident record may be updated without matching the current database `version`.
5. **Invariant 5D-5 (Content Redaction)**: Question text, answer keys, candidate responses, and cryptographic secrets are strictly prohibited from incident titles, descriptions, dedup keys, comments, and metadata.
6. **Invariant 5D-6 (Authoritative Deduplication)**: Worker-side in-memory caches are non-authoritative. PostgreSQL transactional partial unique constraints constitute the sole authoritative duplicate-prevention boundary.
7. **Invariant 5D-7 (Acyclic Duplicates)**: Circular or self-referential duplicate relationships are strictly prevented by database constraints and application validation.

---

## 32. Future Test Matrix (T01–T20)

When implementation is authorized, the following 20 unit and integration tests must pass:

- `T01_signal_ingestion_creates_incident`: Verifies valid advisory signal creates a new `TRIAGE` incident.
- `T02_stable_dedup_key_no_time_bucket`: Proves `dedup_key` computation is deterministic and contains zero time-bucket strings.
- `T03_rolling_inactivity_window_attaches_signal`: Signals arriving at 12:00, 12:59, and 13:58 attach to the same active incident.
- `T04_rolling_inactivity_window_expiration`: Signal arriving after 3601s inactivity opens a new incident case.
- `T05_concurrent_creation_race_loser_attaches`: Concurrent worker race triggers `UniqueViolation`; losing worker catches and attaches evidence.
- `T06_no_last_write_wins`: Concurrent updates preserve original incident creation metadata.
- `T07_active_uniqueness_released_on_resolution`: Resolving an incident allows a new incident with the same `dedup_key` to be opened later.
- `T08_observational_contained_requires_all_fields`: Transition to `CONTAINED` fails with 422 if any of the 5 reference fields are missing.
- `T09_5d_executes_zero_containment`: Verifies zero network, session, or exam disruption occurs upon entering `CONTAINED`.
- `T10_occ_version_conflict_409`: Stale version update returns HTTP 409 Conflict.
- `T11_reopen_transition_flow`: Reopening a `CLOSED` incident emits `INCIDENT_REOPENED` and returns case to `INVESTIGATING`.
- `T12_closed_does_not_delete`: Proves `CLOSED` preserves all database rows and audit records intact.
- `T13_duplicate_requires_valid_parent`: Setting `DUPLICATE` requires active parent; rejects invalid or closed parent.
- `T14_circular_duplicate_prevention`: Acyclic validator rejects circular duplicate relationships (`A -> B -> A`).
- `T15_evidence_link_immutability`: Attempted SQL update/delete on `incident_evidence_links` is rejected.
- `T16_comment_sanitization_and_length`: Comments strip HTML/scripts and enforce 2000 character limit.
- `T17_comment_secret_screening`: Comments containing mock API keys or JWT patterns are rejected with HTTP 422.
- `T18_rbac_security_officer_vs_auditor`: Verifies `SECURITY_OFFICER` can mutate state; `AUDITOR` is strictly read-only.
- `T19_authoritative_audit_emission`: Every lifecycle transition produces a verifiable event in `AuditService`.
- `T20_ip_conflation_prevention`: Two candidates sharing an IP in the same exam produce separate incidents unless rule is infrastructure-scoped.

---

## 33. Prototype vs Production Cryptography (Reconciling Finding 7)

| Architectural Domain | Prototype Implementation (Local / Testing) | Production Implementation (AWS ECS / Fargate) |
| :--- | :--- | :--- |
| **KMS Provider** | `MockKMS` (`backend/app/crypto/kms_interface.py`) | AWS KMS Customer-Managed Keys (CMKs) |
| **Symmetric Encryption** | AES-256-GCM envelope encryption via local master key | AWS KMS `GenerateDataKey` (AES-256-GCM) with hardware key protection |
| **Digital Signing** | Ed25519 signing via `Ed25519PrivateKey` in `MockKMS` | AWS KMS Asymmetric Ed25519 Signing Keys |
| **Key Material Boundary** | In-memory test seeds (deterministic test execution) | Non-exportable hardware security module (FIPS 140-2 Level 3) |
| **Database Encryption** | PostgreSQL 16 local instance | AWS Aurora PostgreSQL with KMS Storage Encryption at Rest |
| **Evidence Link Integrity** | SHA-256 hash comparison in PostgreSQL | SHA-256 hash comparison against sealed S3/KMS audit blocks |

*Clarification: AWS CloudHSM / Custom Key Store is not required. Standard AWS KMS Customer-Managed Keys fulfill all B-SEA cryptographic security invariants.*

---

## 34. Architectural Risks

1. **Signal Flood During Active Attack**: A massive surge of advisory signals could saturate database connection pools. Mitigated by worker-side LRU rate damping and transactional `FOR UPDATE` batching.
2. **Stale Analyst Overwrites**: Multiple analysts triaging the same incident concurrently. Mitigated by mandatory Optimistic Concurrency Control (`version` column) returning HTTP 409.
3. **Premature Containment Assumption**: Analysts marking an incident `CONTAINED` without verified external action. Mitigated by strict schema enforcement requiring external reference IDs and audit proof.

---

## 35. Required Decisions Reconciliation

| Decision Area | Rev-03 Decision | Rev-04 Final Approved Decision |
| :--- | :--- | :--- |
| **`dedup_key` Format** | Included time bucket | **Strictly stable identity; ZERO time bucket** |
| **Correlation Window** | Described as 1-hour static window | **Rolling 3600-second inactivity window (not absolute lifespan)** |
| **Database Uniqueness** | Claimed index handled entire policy | **Partial unique index for active states; service handles rolling policy** |
| **Concurrent Creation** | Worker LRU described alongside DB | **Worker LRU is optimization only; PostgreSQL is authoritative boundary** |
| **`CONTAINED` Execution** | Ambiguous containment reference | **Strictly observational; 5 mandatory reference fields; 5D executes zero actions** |
| **Legacy Service** | Decommissioning tied to 5E | **Legacy service frozen; decommissioning is a separate future milestone** |
| **Cryptography Table** | MockKMS termed "HMAC"; CloudHSM added | **MockKMS accurately termed AES-GCM/Ed25519; AWS KMS CMKs without CloudHSM** |

---

## 36. Proposed Implementation File List

When implementation is formally authorized, work will be confined strictly to these files:

### Backend Modules (New)
1. `backend/app/incidents/__init__.py`: Package initialization.
2. `backend/app/incidents/models.py`: SQLAlchemy ORM models (`SecurityIncident`, `IncidentEvidenceLink`, `IncidentComment`).
3. `backend/app/incidents/schemas.py`: Pydantic request/response schemas.
4. `backend/app/incidents/service.py`: Incident management business logic, deduplication engine, OCC checks, and audit logging.
5. `backend/app/incidents/router.py`: FastAPI REST API endpoints.
6. `backend/app/incidents/consumer.py`: SQS advisory signal ingestion worker.

### Database Migrations (New)
7. `alembic/versions/xxxx_phase3c_5d_incident_management.py`: Migration creating `security_incidents`, `incident_evidence_links`, `incident_comments`, and partial unique index.

### Test Suite (New)
8. `tests/test_phase3c5d_incident_management.py`: Comprehensive test suite implementing T01–T20.

---

## 37. Explicit Implementation Preconditions

Before any implementation code is written, the following conditions must be met:
1. Rev-04 architecture is explicitly approved by the user.
2. Repository baseline remains at commit `7683dd6`.
3. Working tree remains clean with zero untracked code changes.
4. Test regression baseline remains at 240 passed, 5 skipped, 0 failed.

---

## 38. Final Architecture Verdict

**ARCHITECTURE APPROVED FOR IMPLEMENTATION PENDING USER REVIEW**

*(Implementation is NOT authorized. Awaiting your explicit review and authorization).*
