# B-SEA Phase 3C-5D — Security Incident Management Foundation
## Final Architecture & Design Review (Rev-03)

**System:** Bharat Secure Examination Architecture (B-SEA)  
**Milestone:** Phase 3C-5D — Security Incident Management Foundation  
**Status:** ARCHITECTURE REVIEW REV-03 (FINAL ARCHITECTURE-ONLY REVISION)  
**Document Revision:** Rev-03 (Reconciled against Rev-02 Review Findings 1–4)  
**Baseline Commit:** `7683dd6` (`feat: implement Phase 3C-5C detection correlation foundation`)  
**Baseline Verification:** `HEAD == origin/main` | Regression: 240 passed, 5 skipped, 0 failed  
**Governing Security Boundary:** Observational and Human-Managed Incident Case Workflow. **ZERO Autonomous Containment.**  

---

## 1. Executive Summary

Phase 3C-5D establishes the **Security Incident Management Foundation** for the Bharat Secure Examination Architecture (B-SEA). Where Phase 3C-5C delivered an observational, non-intrusive stream of deterministic, versioned advisory signals, Phase 3C-5D establishes the formal, auditable, and human-managed incident case lifecycle that ingests, triages, investigates, and resolves those signals.

### Final Reconciliation Summary (Rev-02 to Rev-03)
Rev-03 resolves the four final mandatory architectural findings:
1. **Deduplication Semantics**: Establishes a rigorous **Incident Correlation Identity** that moves beyond fixed one-hour bucket fragmentation. Defines continuous sliding-window correlation, boundary crossing behavior, deterministic normalization, and collision handling while strictly excluding sensitive examination data and forbidding naive `same IP = same incident` assumptions.
2. **Worker LRU vs. Authoritative Transactional Deduplication**: Formally establishes that worker-side LRU caches and signal deduplication hashes are **non-authoritative process-local optimizations**. Authoritative deduplication is enforced strictly at the database layer via transactional partial unique indexing and catch-and-attach logic, eliminating last-write-wins and silent merging.
3. **Strictly Observational `CONTAINED` State**: Defines `CONTAINED` strictly as an observational milestone recording that authorized external containment (e.g., via future Phase 3C-5E) was executed. Mandates explicit reference metadata (`containment_reference_id`, `authorization_principal`, `containment_timestamp`, `containment_mechanism`, `audit_event_reference`). Confirms that Phase 3C-5D executes **zero autonomous containment**.
4. **Final Clean Lifecycle & State Machine**: Implements a clean 7-state model (`TRIAGE`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `CLOSED`, `FALSE_POSITIVE`, `DUPLICATE`). Treats **`REOPENED` as an auditable action/transition** returning an incident to `INVESTIGATING` rather than a permanent holding state. Requires `duplicate_of_incident_id` with strict circular-reference prevention, and establishes that `CLOSED` represents supervisory administrative closure, never database deletion.

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

## 3. Rev-02 Findings Reconciliation (Core Architectural Solutions)

### Finding 1: Deduplication Semantics & Correlation Identity
- **The Problem**: A naive static one-hour bucket ($\lfloor \text{epoch} / 3600 \rfloor$) artificially fragments an ongoing incident if correlated signals arrive at 11:59:59 and 12:00:01, or fails to group multi-hour coordinated attacks.
- **Rev-03 Solution**: Defines an **Incident Correlation Identity** based on canonical contextual dimensions (`rule_id`, `dim_key`, `dim_val`, `exam_id`). Introduces continuous sliding-window correlation: an incoming signal attaches to an active incident if the incident was created or updated within the bounded correlation window (3600 seconds), regardless of clock-hour boundaries. When an active case exists, the case is extended and the signal is linked as evidence; only when no active case exists within the correlation window is a new incident opened.

### Finding 2: Worker LRU vs. Authoritative Transactional Deduplication
- **The Problem**: Describing process-local worker LRU caches as the deduplication mechanism creates a false sense of distributed safety. In multi-pod container deployments, Worker A and Worker B do not share memory.
- **Rev-03 Solution**: Worker-side LRU is formally classified as an in-memory optimization to reduce database load. **Authoritative deduplication is enforced solely by PostgreSQL**. Rev-03 specifies a partial unique index on active cases and a transactional **catch-and-attach** workflow (`INSERT ... ON CONFLICT` / `IntegrityError` catch) that safely serializes concurrent creations without race conditions or silent overwrites.

### Finding 3: Observational `CONTAINED` State Specification
- **The Problem**: Unclear definition of `CONTAINED` creates risk of conflation with active containment execution.
- **Rev-03 Solution**: Confirms Phase 3C-5D is **strictly observational**. The `CONTAINED` state does not execute containment. It is an analytical milestone entered only upon verifying an authorized external containment workflow. Entering `CONTAINED` mandates five immutable reference fields linking the external action to the sealed PostgreSQL audit chain.

### Finding 4: Final Clean Lifecycle & State Machine
- **The Problem**: Treating `REOPENED` as a permanent persistent state creates complex cyclic state logic. Allowing `DUPLICATE` without strict parent tracking risks circular duplicate chains.
- **Rev-03 Solution**: Adopts a clean state model with 7 justified states. Reopening is defined as an auditable transition: $\text{CLOSED} \xrightarrow{\text{INCIDENT\_REOPENED}} \text{INVESTIGATING}$. `DUPLICATE` mandates `duplicate_of_incident_id` with acyclic validation rules prohibiting nested or circular duplicate relationships. `CLOSED` is explicitly defined as administrative sign-off, preserving immutable records permanently.

---

## 4. Existing Architecture Inspection

A rigorous code-level audit confirms:

1. **RBAC Implementation (`backend/app/core/models.py` & `backend/app/modules/auth/service.py`)**:
   - `UserRoleEnum` explicitly enumerates: `SUPER_ADMIN`, `EXAM_AUTHORITY`, `QUESTION_SETTER`, `REVIEWER`, `MODERATOR`, `SECURITY_OFFICER`, `RELEASE_AUTHORITY`, `CENTRE_ADMIN`, `INVIGILATOR`, `CANDIDATE`, `AUDITOR`.
   - `ROLE_PERMISSIONS` already grants incident management permissions to `SECURITY_OFFICER` and `SUPER_ADMIN`.
   - Rev-03 maps all incident workflows strictly to these existing roles. Zero hypothetical roles are introduced.

2. **Audit Subsystem (`backend/app/modules/audit/service.py`)**:
   - Authoritative dual-mode ingestion: Mode A (business-atomic, caller transaction) and Mode B (security-isolated, autonomous commit).
   - All 5D incident operations log to `AuditService.log` in Mode A. Unauthorized access attempts log to `log_security_event` in Mode B. 5D never maintains an independent audit log.

3. **Detection Subsystem (`backend/app/modules/detection/`)**:
   - `SecuritySignal` provides the primary advisory trigger. Ingested signals are triaged into incident cases via deterministic correlation.

4. **Legacy Security Subsystem (`backend/app/modules/security/service.py` & `models.py`)**:
   - The legacy endpoint `POST /api/v1/incidents/{id}/action` (which allows unilateral user locking and session revoking) is formally bypassed and marked for deprecation in 5D, to be fully decommissioned in Phase 3C-5E.

---

## 5. 5C → 5D Boundary

The boundary between Phase 3C-5C Detection and Phase 3C-5D Incident Management is strictly unidirectional, asynchronous, and decoupled:

```
┌────────────────────────────────────────────────────────┐
│               PHASE 3C-5C: DETECTION                   │
│                                                        │
│  [Event] ──► [Correlation] ──► [Rules A-J] ──► [Signal] │
│                                            (Shadow Mode)
└───────────────────────────┬────────────────────────────┘
                            │ Advisory Delivery (SQS / Memory)
                            ▼
┌────────────────────────────────────────────────────────┐
│         PHASE 3C-5D: INCIDENT MANAGEMENT               │
│                                                        │
│  [Advisory Signal]                                     │
│         │                                              │
│         ▼                                              │
│  [Deterministic Triage] ──► [Security Incident Case]   │
│                                      │                 │
│                                      ▼                 │
│                           [Human Investigation]        │
│                                      │                 │
│                                      ▼                 │
│                            [Advisory Resolution]       │
│                                                        │
│  * ZERO Autonomous Containment                         │
│  * ZERO Candidate Disruption                           │
└────────────────────────────────────────────────────────┘
```

### Epistemic Invariance
$$\text{Security Event} \neq \text{Detection Signal} \neq \text{Confirmed Incident} \neq \text{Examination Leak}$$
- Detection signals are advisory mathematical assertions of anomaly.
- Security incidents are human-managed investigative containers.
- Incidents only reach confirmed conclusions through qualified analyst investigation.
- Total failure of incident management has zero impact on candidate authentication, question delivery, autosave, or audit sealing.

---

## 6. Incident Domain Model (`incident_id` vs. `incident_number`)

Rev-03 enforces a complete decoupling between internal security principals and human display labels:

| Attribute | `incident_id` | `incident_number` |
| :--- | :--- | :--- |
| **Data Type** | UUIDv4 (`String(36)`) | Monotonic Sequence Reference (`String(32)`) |
| **Example** | `e7c8b412-98e3-4f28-b8d1-123456789abc` | `INC-2026-00042` |
| **System Role** | Primary Key, Foreign Key target | Human display label, ticketing cross-reference |
| **Immutability** | Completely immutable | Immutable after generation |
| **Authorization Boundary** | **YES**: Used for RBAC and access control checks | **NO**: Never trusted for authorization decisions |
| **Security Principal** | **YES**: Authoritative database identity | **NO**: Purely informative presentation attribute |

### Core `SecurityIncident` Schema Attributes
- `id`: UUIDv4 Primary Key (`incident_id`).
- `incident_number`: Unique human-readable reference formatted as `INC-{YYYY}-{SEQUENCE:05d}`.
- `incident_type`: Bounded enumeration (`IncidentTypeEnum`).
- `severity`: Current triage severity (`IncidentSeverity`: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- `initial_severity`: Severity at creation (preserved for escalation audit).
- `status`: Current lifecycle state (`IncidentStatusEnum`).
- `title`: Sanitized, safe summary (max 255 characters).
- `summary`: Contextual investigative description (sanitized text).
- `dedup_key`: Deterministic SHA-256 hash used for clustering recurring signals.
- `policy_version`: Policy definition governing triage (`"BSEA-INCIDENT-v1"`).
- `created_by`: Foreign key to `users.id` (or designated system user).
- `assigned_to`: Foreign key to `users.id` (nullable; restricted to `SECURITY_OFFICER` or `SUPER_ADMIN`).
- `duplicate_of_incident_id`: Foreign key to `security_incidents.id` (nullable; for `DUPLICATE` cases).
- `exam_id`: Optional foreign key to `exams.id`.
- `centre_id`: Optional foreign key to `centres.id`.
- `version`: Monotonic integer for Optimistic Concurrency Control (OCC).
- `resolution_category`: Bounded resolution classification.
- `resolution_notes`: Analytical summary of findings.
- `created_at`: UTC timezone-aware timestamp.
- `updated_at`: UTC timezone-aware timestamp.
- `resolved_at`: UTC timestamp of resolution (nullable).
- `closed_at`: UTC timestamp of administrative sign-off (nullable).

---

## 7. Final Clean Lifecycle & State Machine (Reconciling Finding 4)

Rev-03 establishes a finalized, clean state model consisting of seven justified persistent states:

```
                      ┌──────────────────────┐
                      │        TRIAGE        │
                      └──────────┬───────────┘
                                 │
           ┌─────────────────────┼─────────────────────┐
           ▼                     ▼                     ▼
┌─────────────────────┐┌─────────────────────┐┌─────────────────────┐
│    INVESTIGATING    ││   FALSE_POSITIVE    ││      DUPLICATE      │
└──────────┬──────────┘└─────────────────────┘└─────────────────────┘
           │
           ├─────────────────────┐
           ▼                     ▼
┌─────────────────────┐┌─────────────────────┐
│     CONTAINED*      ││      RESOLVED       │
└──────────┬──────────┘└─────────┬───────────┘
           │                     │
           └──────────┬──────────┘
                      ▼
           ┌─────────────────────┐
           │       CLOSED        │
           └──────────┬──────────┘
                      │
                      │  Action: INCIDENT_REOPENED
                      ▼  (Returns to INVESTIGATING)
           ┌─────────────────────┐
           │    INVESTIGATING    │
           └─────────────────────┘
```

### State Definitions
1. **`TRIAGE`**: Initial state upon ingestion. Pending priority assessment and analyst assignment.
2. **`INVESTIGATING`**: Formally assigned to a Security Officer actively reviewing evidence.
3. **`CONTAINED`\***: Observational milestone recording that authorized external containment was executed and verified. **Phase 3C-5D executes zero containment actions.**
4. **`RESOLVED`**: Analytical determination reached; findings and remediation documented.
5. **`FALSE_POSITIVE`**: Confirmed to be benign activity, operational retry, or system glitch.
6. **`DUPLICATE`**: Redundant case linked to an active primary incident.
7. **`CLOSED`**: Terminal administrative sign-off by a Super Admin. **`CLOSED` represents supervisory closure after resolution, NOT deletion.**

### Reopen Semantics (Action, Not Persistent State)
- Reopening is modeled as an **auditable state transition**, not a distinct permanent holding state:
  $$\text{CLOSED} \xrightarrow{\text{INCIDENT\_REOPENED}} \text{INVESTIGATING}$$
  $$\text{RESOLVED} \xrightarrow{\text{INCIDENT\_REOPENED}} \text{INVESTIGATING}$$
- This keeps the database state machine clean and prevents cases from being stranded in an intermediate pseudo-state. Reopening requires documenting new evidence and emits an `INCIDENT_REOPENED` audit event.

### Duplicate Handling & Circularity Prevention
- An incident entering `DUPLICATE` must populate `duplicate_of_incident_id` pointing to an existing incident.
- **Acyclic Validation Rules**:
  1. `duplicate_of_incident_id != id` (self-referencing prohibited via database check constraint).
  2. The target incident must have status `TRIAGE`, `INVESTIGATING`, or `RESOLVED` (cannot point to a closed or false positive case).
  3. The target incident must have `duplicate_of_incident_id IS NULL` (nesting duplicates is strictly prohibited).
  4. If a target incident is itself marked duplicate in the future, all dependent references must be reassigned to the new primary incident. Circular duplicate chains are impossible.

---

## 8. State Transition Matrix & Authority

Every state transition requires strict role authorization, mandatory preconditions, OCC version verification, and immediate Mode A audit logging:

| From Status | To Status | Authorized Roles | Required Preconditions | Reversible? | Audit Event |
| :--- | :--- | :--- | :--- | :---: | :--- |
| `TRIAGE` | `INVESTIGATING` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Analyst assignment non-null | Yes | `INCIDENT_STATUS_CHANGED` |
| `TRIAGE` | `FALSE_POSITIVE` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Rationale documented ($\ge 20$ chars) | Yes | `INCIDENT_STATUS_CHANGED` |
| `TRIAGE` | `DUPLICATE` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Valid non-duplicate primary ID specified | Yes | `INCIDENT_STATUS_CHANGED` |
| `INVESTIGATING` | `CONTAINED` | `SECURITY_OFFICER`, `SUPER_ADMIN` | External containment reference metadata verified | Yes | `INCIDENT_STATUS_CHANGED` |
| `INVESTIGATING` | `RESOLVED` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Resolution category & summary documented | No | `INCIDENT_RESOLVED` |
| `INVESTIGATING` | `FALSE_POSITIVE` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Rationale documented ($\ge 20$ chars) | Yes | `INCIDENT_STATUS_CHANGED` |
| `CONTAINED` | `RESOLVED` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Resolution category & summary documented | No | `INCIDENT_RESOLVED` |
| `RESOLVED` | `CLOSED` | `SUPER_ADMIN` ONLY | Supervisory review completed | No | `INCIDENT_CLOSED` |
| `RESOLVED` | `INVESTIGATING` | `SECURITY_OFFICER`, `SUPER_ADMIN` | New evidence reference documented | Yes | `INCIDENT_REOPENED` |
| `CLOSED` | `INVESTIGATING` | `SUPER_ADMIN` ONLY | Super Admin formal justification | Yes | `INCIDENT_REOPENED` |

---

## 9. Deduplication Semantics & Correlation Identity (Reconciling Finding 1)

### Incident Correlation Identity
An incident represents an ongoing security context, not a single clock-hour slice. The **Incident Correlation Identity** is defined by the tuple:
$$\text{Correlation Identity} = (\text{rule\_id}, \text{dim\_key}, \text{dim\_val}, \text{exam\_id})$$

- `rule_id`: Identifier of the detection rule (e.g., `"RULE-G"`). Rule version (`rule_version`) is recorded on individual evidence links, ensuring rule updates do not fracture an ongoing case.
- `dim_key`: Canonical primary dimension (`"resource_id"`, `"actor_id"`, `"device_id"`, `"session_id"`).
- `dim_val`: Normalized, lowercase, stripped string representation of the dimension value.
- `exam_id`: Optional examination UUID (or `"global"` if unassociated).

### Continuous Sliding-Window Correlation
Rather than slicing events by arbitrary clock hours, correlation operates across a **continuous 3600-second (1-hour) sliding window**:

```
Signal Arrival at T:
┌────────────────────────────────────────────────────────┐
│ Query Active Incidents:                                │
│   status IN ('TRIAGE', 'INVESTIGATING')                │
│   AND rule_id = :rule_id                               │
│   AND dim_key = :dim_key                               │
│   AND dim_val = :dim_val                               │
│   AND exam_id = :exam_id                               │
│   AND updated_at >= (T - 3600 seconds)                 │
└───────────────────────────┬────────────────────────────┘
                            │
              ┌─────────────┴─────────────┐
              ▼                           ▼
        [Match Found]               [No Match]
              │                           │
              ▼                           ▼
     [Attach Signal to            [Generate New dedup_key
      Existing Incident &          & INSERT New Incident]
      Refresh updated_at]
```

### Boundary-Crossing Behavior
When signals arrive across clock-hour boundaries (e.g., Event 1 at 11:59:59 and Event 2 at 12:00:01):
1. Event 1 creates Incident Case $A$ at 11:59:59.
2. Event 2 arrives at 12:00:01 (2 seconds later).
3. The continuous query checks: `updated_at >= (12:00:01 - 3600s) = 11:00:01`.
4. Incident Case $A$ matches! Event 2 attaches to Case $A$ as an `IncidentEvidenceLink`, and Case $A$'s `updated_at` is refreshed to 12:00:01.
5. **Result**: Zero artificial case fragmentation. Bounded correlation window is preserved continuously.

### Deterministic `dedup_key` Hashing
For database indexing and transaction safety, a deterministic hash is derived at incident creation:
$$\text{dedup\_key} = \text{SHA-256}(\text{rule\_id} \mathbin{\Vert} \text{dim\_key} \mathbin{\Vert} \text{dim\_val} \mathbin{\Vert} \text{exam\_id} \mathbin{\Vert} \text{time\_bucket} \mathbin{\Vert} \text{policy\_version})$$
where $\text{time\_bucket} = \lfloor \text{creation\_epoch\_seconds} / 3600 \rfloor$.

### Negative Invariants
- **No Sensitive Data**: `dedup_key` inputs NEVER include plaintext question content, answer keys, candidate responses, passwords, or cryptographic keys.
- **No IP Equivalence**: The engine NEVER assumes `same IP = same actor` or `same IP = same incident`.

---

## 10. Authoritative Transactional Deduplication vs. Worker LRU (Reconciling Finding 2)

Rev-03 explicitly formalizes the boundary between performance caching and authoritative database integrity:

$$\begin{aligned}
\text{Worker-Side LRU / Hash Deduplication} &= \textbf{Optimization Only (Process-Local, Non-Authoritative)} \\
\text{PostgreSQL Transactional Constraints} &= \textbf{Authoritative Duplicate-Prevention Boundary}
\end{aligned}$$

```
┌────────────────────────────────────────────────────────┐
│             WORKER PROCESS (Optimization)              │
│  Checks process-local LRU cache (`_dedup_cache`).      │
│  Filters rapid in-process duplicate messages.          │
│  * Non-authoritative; lost on crash or restart.        │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│         POSTGRESQL DATABASE (Authoritative)            │
│                                                        │
│  Partial Unique Index:                                 │
│    uq_active_incident_dedup                            │
│    WHERE status IN ('TRIAGE', 'INVESTIGATING')         │
│                                                        │
│  Concurrent INSERT ──► Catches UniqueViolation         │
│                    ──► Executes CATCH-AND-ATTACH       │
│                    ──► Links Evidence to Active Case   │
│                    ──► Zero Duplicate Incidents        │
│                    ──► Zero Last-Write-Wins Overwrites │
└────────────────────────────────────────────────────────┘
```

### Transactional Catch-and-Attach Workflow
When Worker 1 and Worker 2 concurrently receive signals for the same correlation context:
1. Worker 1 executes `INSERT INTO security_incidents ...` and commits.
2. Worker 2 attempts `INSERT INTO security_incidents ...` with the identical `dedup_key`.
3. PostgreSQL enforces `uq_active_incident_dedup` and raises `UniqueViolation` (`IntegrityError`).
4. Worker 2's transaction intercepts the error and executes the authoritative recovery path:
   ```sql
   SELECT id FROM security_incidents 
   WHERE dedup_key = :dedup_key AND status IN ('TRIAGE', 'INVESTIGATING') 
   FOR UPDATE;
   ```
5. Worker 2 inserts the new signal as an `IncidentEvidenceLink` attached to the locked incident.
6. Worker 2 updates `security_incidents.updated_at = NOW()`.
7. Worker 2 commits transaction.

### Guarantees
- **Zero Duplicate Incidents**: Multiple workers cannot create duplicate open cases for the same context.
- **No Last-Write-Wins**: Case attributes (`title`, `created_at`, `created_by`) are preserved; incoming signals append evidence without overwriting case state.
- **No Silent Merging**: Every incoming signal is explicitly linked in `incident_evidence_links` with cryptographic fingerprint and audit log entry.

---

## 11. Observational `CONTAINED` State Specification (Reconciling Finding 3)

Rev-03 explicitly establishes that **Phase 3C-5D performs ZERO containment**:

$$\text{Phase 3C-5D} = \textbf{Observational Case Management} \quad \Big| \quad \text{Phase 3C-5E} = \textbf{Policy-Governed Containment}$$

### Semantics of `CONTAINED`
The `CONTAINED` state is an **observational milestone** acknowledging that an authorized external containment action (e.g., via future Phase 3C-5E) was executed and verified by a human analyst. Phase 3C-5D does **NOT**:
- Revoke candidate examination sessions
- Block candidate accounts or lock credentials
- Block IP addresses or network CIDRs
- Block client devices or hardware fingerprints
- Quarantine examination questions or test forms
- Rotate or invalidate AWS KMS keys
- Cancel or halt live examination administrations
- Execute automated or autonomous containment scripts

### Minimum Required Reference Metadata
An incident may transition to `CONTAINED` **only** if the request supplies the following verified reference metadata:
1. `containment_reference_id`: Authoritative UUID of the external containment action (e.g., 5E containment execution ID, dual-custody approval UUID).
2. `authorization_principal`: The identity and role of the authority who authorized containment (must be `SUPER_ADMIN` or dual-custody authorization).
3. `containment_timestamp`: UTC timestamp of containment execution.
4. `containment_mechanism`: Bounded string identifier (`"SESSION_REVOCATION"`, `"QUARANTINE_SEAL"`, `"CREDENTIAL_LOCK"`, `"EXAM_HALT"`).
5. `audit_event_reference`: The UUID of the corresponding `audit_logs` record proving that the containment action was sealed into PostgreSQL audit persistence.

If any of these five reference fields is missing or cannot be verified against the audit log, the transition to `CONTAINED` is **rejected with HTTP 422 Unprocessable Entity**.

---

## 12. Evidence Reference Architecture (Reconciling Finding 5)

Rev-03 enforces the tri-partite evidence separation:

$$\text{Evidence Reference} \neq \text{Evidence Payload} \neq \text{Evidence Ownership}$$

```
┌────────────────────────────────────────────────────────┐
│                   SecurityIncident                     │
│  id: "e7c8b412-98e3-4f28-b8d1-123456789abc"           │
│  incident_number: "INC-2026-00042"                     │
└───────────────────────────┬────────────────────────────┘
                            │ 1 : N
                            ▼
┌────────────────────────────────────────────────────────┐
│                IncidentEvidenceLink                    │
│  id: "link_uuid_789"                                   │
│  evidence_type: "AUDIT_LOG" | "DETECTION_SIGNAL" ...   │
│  evidence_id: "audit_log_uuid_123"                     │
│  evidence_hash: "sha256_hash_of_source_record"         │
│  source_subsystem: "audit_logs"                        │
│  status: "AVAILABLE" | "UNAVAILABLE" | "CONFLICTING"   │
│  linked_at: "2026-09-15T12:00:00Z"                     │
│  linked_by: "user_uuid_security_officer"               │
└────────────────────────────────────────────────────────┘
```

### Principles of Evidence Immutability
1. **Immutable References**: Evidence links are stored as immutable records in `incident_evidence_links`.
2. **Persistence During Source Unavailability**: If the underlying source event is later archived, partitioned, or deleted under retention policies, the `IncidentEvidenceLink` **must NOT be deleted**.
   - The link status transitions to `evidence_state = "UNAVAILABLE"`.
   - The incident case and forensic linkage remain 100% intact.
3. **Cryptographic Source Fingerprinting**: When an evidence link is created, the system computes `evidence_hash = SHA-256(source_record_canonical_bytes)`.
   - Subsequent verifications compare active source content against `evidence_hash`.
   - If the source record has been altered, the link status transitions to `CONFLICTING`.
4. **Zero Payload Duplication**: Incident records never duplicate raw event payloads. The authoritative audit chain (`audit_logs`) remains the single source of truth for audit evidence.

---

## 13. Evidence Access Control

Evidence visibility is strictly decoupled from incident case summaries:
- **Least Privilege**: Users authorized to view incident triage lists (`EXAM_AUTHORITY`) are **not** permitted to inspect raw security evidence records.
- **Access Authorization Matrix**:
  - `SUPER_ADMIN`: Full evidence inspection.
  - `SECURITY_OFFICER`: Full evidence inspection.
  - `AUDITOR`: Read-only evidence inspection and cryptographic verification.
  - `EXAM_AUTHORITY`, `CANDIDATE`, `INVIGILATOR`, `REVIEWER`: **ZERO** evidence access.
- **Forensic Audit Logging**: Every evidence retrieval API call (`GET /api/v1/incidents/{id}/evidence/{evidence_id}`) emits an `INCIDENT_EVIDENCE_VIEWED` Mode A audit event logging the accessing analyst, timestamp, and target evidence UUID.

---

## 14. RBAC Model & Repository Role Alignment

In strict compliance with repository reality (`backend/app/core/models.py` lines 25–45 and `backend/app/modules/auth/service.py` lines 250–310), all incident permissions map exclusively to existing roles:

| Incident Permission | Meaning | SUPER_ADMIN | SECURITY_OFFICER | AUDITOR | EXAM_AUTHORITY | All Other Roles* |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| `incidents:read` | View incident summaries & lists | **YES** | **YES** | **YES** | **YES** | NO |
| `incidents:create` | Manually initiate incident case | **YES** | **YES** | NO | NO | NO |
| `incidents:assign` | Assign/reassign case analyst | **YES** | **YES** | NO | NO | NO |
| `incidents:investigate` | Append comments & triage notes | **YES** | **YES** | NO | NO | NO |
| `incidents:view_evidence` | Inspect raw evidence pointers | **YES** | **YES** | **YES** | NO | NO |
| `incidents:resolve` | Document findings & mark resolved| **YES** | **YES** | NO | NO | NO |
| `incidents:close` | Perform final supervisory closure| **YES** | NO | NO | NO | NO |
| `incidents:reopen` | Reopen resolved/closed case | **YES** | **YES** | NO | NO | NO |

*\*Other Roles:* `CANDIDATE`, `QUESTION_SETTER`, `REVIEWER`, `MODERATOR`, `CENTRE_ADMIN`, `INVIGILATOR`, `RELEASE_AUTHORITY` have **zero** permissions on security incidents.

---

## 15. Analyst Assignment

- Incidents in `TRIAGE` may be assigned to any active user possessing the `SECURITY_OFFICER` or `SUPER_ADMIN` role.
- Self-assignment transitions the incident from `TRIAGE` to `INVESTIGATING`.
- Re-assignment requires logging `INCIDENT_REASSIGNED` with previous and new assignee IDs.

---

## 16. 6-Layer Defense-in-Depth Comment Confidentiality Model

Rev-03 explicitly establishes that keyword screening is a secondary safeguard and cannot guarantee detection of all sensitive examination content. Confidentiality is enforced across six layered barriers:

```
┌────────────────────────────────────────────────────────┐
│      LAYER 1: Operational Policy & Analyst Governance  │
│  Strict SOP prohibiting copy-pasting of exam content   │
├────────────────────────────────────────────────────────┤
│      LAYER 2: Structural Data Restrictions             │
│  Unstructured plain text only; no file uploads/blobs   │
├────────────────────────────────────────────────────────┤
│      LAYER 3: Payload Validation & Character Bounds    │
│  Max 2,000 chars; strict ASCII/UTF-8 alphanumeric check │
├────────────────────────────────────────────────────────┤
│      LAYER 4: Automated Pre-Commit Screening           │
│  Regex token analysis rejecting keys/JWTs/DEKs/passwords│
├────────────────────────────────────────────────────────┤
│      LAYER 5: Immutable Attribution & Audit Trail      │
│  Append-only persistence; every comment sealed in audit│
├────────────────────────────────────────────────────────┤
│      LAYER 6: Read-Side Masking & Redaction            │
│  Dynamic redaction of sensitive credentials on export  │
└────────────────────────────────────────────────────────┘
```

1. **Layer 1 — Operational Policy**: Security Officers operate under strict non-disclosure and operational protocols forbidding the entry of examination materials into investigation logs.
2. **Layer 2 — Structural Data Restrictions**: The API accepts only a single string field (`comment_body`). File attachments, binary payloads, and rich media uploads are strictly prohibited.
3. **Layer 3 — Payload Validation**: Max comment length is bounded to 2,000 characters. Null bytes, control characters, and unprintable sequences trigger immediate HTTP 422 rejection.
4. **Layer 4 — Automated Pre-Commit Screening (Secondary Safeguard)**: Evaluates input against high-entropy secrets, PEM private key headers (`-----BEGIN`), JWT signatures (`ey[A-Za-z0-9_-]+`), and known examination keywords. If matched, the comment is rejected with HTTP 422 Unprocessable Entity.
5. **Layer 5 — Immutable Attribution**: Comments are strictly append-only in `incident_comments`. Updates and deletions are blocked by schema and API design. Every comment emits an `INCIDENT_COMMENT_ADDED` audit event.
6. **Layer 6 — Read-Side Masking**: System masks potential credentials on UI presentation.

---

## 17. Concurrency Strategy & OCC

- **Optimistic Concurrency Control (OCC)**:
  - Every `SecurityIncident` row maintains an integer `version` column, initialized to `1`.
  - Update operations must include the client's current `version`.
  - SQL update execution:
    ```sql
    UPDATE security_incidents
    SET status = :new_status, version = version + 1, updated_at = :now
    WHERE id = :id AND version = :client_version;
    ```
  - If rows affected equals `0`, the server raises `HTTP 409 Conflict` ("Incident modified by another analyst. Refresh required.").

---

## 18. Severity Model

Incident severity is decoupled from detection signal severity:
- A `HIGH` detection signal may be triaged to `LOW` if surrounding audit context proves an authorized maintenance drill.
- A `MEDIUM` signal may be escalated to `CRITICAL` if correlated with physical centre anomalies.
- **Escalation Policy**:
  - Severity values: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
  - Modification requires explicit rationale ($\ge 20$ chars) and emits `INCIDENT_SEVERITY_CHANGED` to the audit chain.

---

## 19. Incident Types

Bounded to 10 finite categories to eliminate metric label cardinality explosion:
1. `AUTHENTICATION_ABUSE`
2. `AUTHORIZATION_ABUSE`
3. `QUESTION_ACCESS_ANOMALY`
4. `BREAK_GLASS_MISUSE`
5. `KMS_CRYPTOGRAPHIC_FAILURE`
6. `AUDIT_CHAIN_INTEGRITY`
7. `RATE_LIMIT_EVASION`
8. `SEALER_DEGRADATION`
9. `CLOUDTRAIL_RECONCILIATION_FAILURE`
10. `OPERATIONAL_SECURITY_ANOMALY`

---

## 20. Incident Timeline

Chronological incident history is dynamically assembled from authoritative sources:
1. Creation event from `security_incidents.created_at`.
2. Evidence link timestamps from `incident_evidence_links`.
3. Transition history queried directly from `audit_logs` where `resource_id = incident_id`.
4. Comment timestamps from `incident_comments`.
5. Resolution and closure timestamps.

The timeline is reconstructed dynamically via queries; it does not duplicate the audit log.

---

## 21. Audit Integration

All incident operations integrate with the authoritative audit subsystem (`backend/app/modules/audit/service.py`):

| Operation | Audit Event Type | Mode | Payload Metadata |
| :--- | :--- | :---: | :--- |
| Create Incident | `INCIDENT_CREATED` | Mode A | `incident_id`, `incident_type`, `severity`, `dedup_key` |
| Assign Incident | `INCIDENT_ASSIGNED` | Mode A | `incident_id`, `assignee_id` |
| Change Status | `INCIDENT_STATUS_CHANGED` | Mode A | `incident_id`, `old_status`, `new_status`, `rationale`, `version` |
| Link Evidence | `INCIDENT_EVIDENCE_LINKED` | Mode A | `incident_id`, `evidence_type`, `evidence_id`, `evidence_hash` |
| View Evidence | `INCIDENT_EVIDENCE_VIEWED` | Mode A | `incident_id`, `evidence_type`, `evidence_id` |
| Add Comment | `INCIDENT_COMMENT_ADDED` | Mode A | `incident_id`, `comment_id` |
| Resolve Incident | `INCIDENT_RESOLVED` | Mode A | `incident_id`, `resolution_category`, `resolution_notes` |
| Close Incident | `INCIDENT_CLOSED` | Mode A | `incident_id`, `closed_by` |
| Reopen Incident | `INCIDENT_REOPENED` | Mode A | `incident_id`, `reason` |

---

## 22. Database Schema Proposal (Reconciling Findings 1–4)

```sql
-- 1. Security Incidents Table
CREATE TABLE security_incidents (
    id VARCHAR(36) PRIMARY KEY,                                -- Authoritative incident_id (UUIDv4)
    incident_number VARCHAR(32) NOT NULL UNIQUE,               -- Human display reference (INC-YYYY-XXXXX)
    incident_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    initial_severity VARCHAR(20) NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'TRIAGE',
    title VARCHAR(255) NOT NULL,
    summary TEXT,
    dedup_key VARCHAR(64) NOT NULL,
    policy_version VARCHAR(50) NOT NULL DEFAULT 'BSEA-INCIDENT-v1',
    created_by VARCHAR(36) NOT NULL REFERENCES users(id),
    assigned_to VARCHAR(36) REFERENCES users(id),
    duplicate_of_incident_id VARCHAR(36) REFERENCES security_incidents(id) ON DELETE RESTRICT,
    exam_id VARCHAR(36) REFERENCES exams(id),
    centre_id VARCHAR(36) REFERENCES centres(id),
    version INTEGER NOT NULL DEFAULT 1,                        -- Optimistic Concurrency Control
    resolution_category VARCHAR(50),
    resolution_notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMPTZ,
    closed_at TIMESTAMPTZ,
    CONSTRAINT chk_incident_severity CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT chk_incident_status CHECK (status IN (
        'TRIAGE', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE', 'DUPLICATE', 'CLOSED'
    )),
    CONSTRAINT chk_no_self_duplicate CHECK (duplicate_of_incident_id != id)
);

-- Partial Unique Index for Concurrency-Safe Deduplication
CREATE UNIQUE INDEX uq_active_incident_dedup 
ON security_incidents (dedup_key) 
WHERE status IN ('TRIAGE', 'INVESTIGATING');

-- 2. Incident Evidence Links Table
CREATE TABLE incident_evidence_links (
    id VARCHAR(36) PRIMARY KEY,
    incident_id VARCHAR(36) NOT NULL REFERENCES security_incidents(id) ON DELETE RESTRICT,
    evidence_type VARCHAR(50) NOT NULL,
    evidence_id VARCHAR(64) NOT NULL,
    evidence_timestamp TIMESTAMPTZ NOT NULL,
    source_subsystem VARCHAR(50) NOT NULL,
    evidence_hash VARCHAR(64) NOT NULL,                        -- SHA-256 fingerprint of source record
    status VARCHAR(30) NOT NULL DEFAULT 'AVAILABLE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(36) NOT NULL REFERENCES users(id),
    CONSTRAINT chk_evidence_status CHECK (status IN ('AVAILABLE', 'UNAVAILABLE', 'UNRESOLVED', 'CONFLICTING'))
);

CREATE INDEX idx_inc_evidence_incident ON incident_evidence_links(incident_id);

-- 3. Incident Analyst Comments Table (Append-Only)
CREATE TABLE incident_comments (
    id VARCHAR(36) PRIMARY KEY,
    incident_id VARCHAR(36) NOT NULL REFERENCES security_incidents(id) ON DELETE RESTRICT,
    author_id VARCHAR(36) NOT NULL REFERENCES users(id),
    comment_body TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_inc_comments_incident ON incident_comments(incident_id, created_at ASC);
```

---

## 23. Constraints and Indexes

- `chk_no_self_duplicate`: Prohibits self-referencing duplicate loops.
- `ON DELETE RESTRICT`: Prohibits accidental deletion of parent incidents or evidence records.
- Composite indexes on `(status, severity)` optimize triage queue filtering.

---

## 24. Retention and Deletion Policy

- **No Hard Deletes**: Direct `DELETE` queries on `security_incidents` are blocked by foreign key constraints and application RBAC.
- **No Soft Delete Column**: The entity does not implement `is_deleted`. Decommissioning an incident occurs exclusively through the `CLOSED` terminal state.
- **Legal Hold**: Closed incidents retain immutable links to audit records indefinitely.

---

## 25. API Architecture

1. `POST /api/v1/incidents/` (Create manual case) — `SECURITY_OFFICER`, `SUPER_ADMIN`
2. `GET /api/v1/incidents/` (List triage cases) — `SECURITY_OFFICER`, `SUPER_ADMIN`, `AUDITOR`, `EXAM_AUTHORITY`
3. `GET /api/v1/incidents/{incident_id}` (Retrieve case details) — Authorized roles (resolves on `incident_id`)
4. `POST /api/v1/incidents/{incident_id}/assign` (Assign/reassign analyst) — `SECURITY_OFFICER`, `SUPER_ADMIN`
5. `POST /api/v1/incidents/{incident_id}/status` (Execute state transition with OCC version) — `SECURITY_OFFICER`, `SUPER_ADMIN`
6. `GET /api/v1/incidents/{incident_id}/evidence` (List linked evidence) — `SECURITY_OFFICER`, `SUPER_ADMIN`, `AUDITOR`
7. `POST /api/v1/incidents/{incident_id}/comments` (Append analyst note) — `SECURITY_OFFICER`, `SUPER_ADMIN`
8. `POST /api/v1/incidents/{incident_id}/resolve` (Document findings & resolve) — `SECURITY_OFFICER`, `SUPER_ADMIN`
9. `POST /api/v1/incidents/{incident_id}/close` (Administrative supervisory closure) — `SUPER_ADMIN` ONLY
10. `POST /api/v1/incidents/{incident_id}/reopen` (Action reopening closed/resolved case) — `SECURITY_OFFICER`, `SUPER_ADMIN`

---

## 26. Frontend / Analyst UI Architecture

- **Triage Queue**: Displays `incident_number` (display only; links resolve to `incident_id`), severity, elapsed time, and affected exam.
- **Investigation Workspace**: Safe summary, interactive evidence explorer with cryptographic integrity indicators, chronological notes log, and OCC conflict banner.

---

## 27. Failure Semantics

- **PostgreSQL Unavailable**: Incident creation fails; detection signals remain buffered in SQS Standard Queue; candidate examination delivery continues 100% unaffected.
- **Audit Service Unavailable**: Incident status transitions abort; incident state cannot change without sealed audit recording.
- **Analyst Session Expiry**: API returns HTTP 401; examination traffic continues unaffected.

---

## 28. 5D vs 5E Boundary

| Dimension | Phase 3C-5D (Incident Management) | Phase 3C-5E (Policy-Governed Containment) |
| :--- | :--- | :--- |
| **Primary Goal** | Human investigation, triage, case tracking | Active threat containment & intervention |
| **System Interaction** | Read-only analysis & advisory case management | Active intervention on sessions, keys, and exams |
| **Autonomous Action** | **ZERO autonomous containment** | Policy-evaluated containment with dual custody |
| **Session Impact** | Candidates are NEVER terminated or blocked | Authoritative session revocation with dual authorization |
| **Quarantine Impact** | No quarantine actions | Dual-custody audit/content quarantine |
| **Status Semantics** | `CONTAINED` is an observational milestone | Active execution of containment mechanisms |

---

## 29. 5D vs 5F Boundary

- **Phase 3C-5D**: Self-contained internal incident case management.
- **Phase 3C-5F**: Enterprise SIEM integration (AWS Security Lake, OpenSearch, Splunk, PagerDuty, external webhooks). 5D does not implement external SOC connectors.

---

## 30. Legacy SecurityService Coexistence & Deprecation Plan

1. `backend/app/modules/security/service.py` remains frozen and untouched.
2. The modern incident management subsystem will be implemented cleanly in `backend/app/modules/incident/`.
3. The legacy endpoint `POST /api/v1/incidents/{incident_id}/action` (which allows unilateral user locking and session revoking) is formally bypassed and marked for deprecation in 5D, to be fully decommissioned in Phase 3C-5E in favor of dual-custody policy containment.

---

## 31. Security Invariants for 5D

1. Incident management must never degrade or weaken candidate examination security.
2. Incident management must never modify immutable audit history (`AuditLog`, `AuditChainLink`, `AuditEpochSeal`).
3. Incident management must never mutate KMS key state or bypass KMS policies.
4. Plaintext examination content must never be stored in incidents, evidence links, or analyst comments.
5. Evidence records must utilize immutable UUID references rather than duplicated event payloads.
6. All incident status transitions must be role-authorized and immediately logged to the authoritative audit chain.
7. Concurrency collisions must be prevented via optimistic concurrency control; last-write-wins is forbidden.
8. Detection signals remain advisory observations until a qualified human analyst establishes a formal incident conclusion.
9. Total failure of the incident management subsystem must have zero effect on candidate login, exam delivery, autosave, or audit recording.
10. Zero autonomous containment may be executed by Phase 3C-5D.
11. High-cardinality identifiers must never be utilized as metric label dimensions.
12. Incident records are protected against unauthorized physical and soft deletion.

---

## 32. Future Test Matrix (T01–T20)

- **T01**: Incident creation authorization (`SECURITY_OFFICER` & `SUPER_ADMIN`).
- **T02**: Unauthorized role rejection (`CANDIDATE`, `INVIGILATOR`, `REVIEWER` rejected with HTTP 403).
- **T03**: Signal-to-incident reference integrity and metadata preservation.
- **T04**: Continuous sliding-window deduplication across time-boundary edges.
- **T05**: Valid status transition lifecycle flow (`TRIAGE` $\to$ `INVESTIGATING` $\to$ `RESOLVED` $\to$ `CLOSED`).
- **T06**: Invalid status transition rejection (e.g., direct `TRIAGE` $\to$ `CLOSED` rejected).
- **T07**: Optimistic concurrency control (concurrent updates return HTTP 409).
- **T08**: Concurrent incident creation race handling (catch-and-attach verification).
- **T09**: Observational `CONTAINED` verification (requires valid external containment reference metadata).
- **T10**: Sensitive exam content screening (6-layer defense on comments).
- **T11**: Audit event generation across all status transitions.
- **T12**: Severity modification authorization and audit trail.
- **T13**: Resolution documentation enforcement ($\ge 20$ chars required).
- **T14**: Action-based incident reopening semantics (`CLOSED` $\to$ `INVESTIGATING`).
- **T15**: Duplicate incident linking and circular reference rejection.
- **T16**: Database outage isolation (exam traffic continues during DB incident error).
- **T17**: Detection outage isolation (incidents can be created manually during detection lag).
- **T18**: Candidate traffic independence (zero candidate session disruption).
- **T19**: Physical deletion restriction (enforces `ON DELETE RESTRICT`).
- **T20**: 5E containment boundary enforcement (zero autonomous containment).

---

## 33. Prototype vs Production

| Component | Prototype / CI Baseline | Production Target (AWS) |
| :--- | :--- | :--- |
| **Database** | Local PostgreSQL 16 on Docker | Amazon RDS PostgreSQL 16 Multi-AZ + RDS Proxy |
| **Queue Dispatch** | In-process `asyncio.Queue` | Amazon SQS Standard Queue with KMS SSE |
| **RBAC** | FastAPI dependency injection | Enterprise IAM with OIDC / GovID SAML 2.0 |
| **Audit Sealing** | Local mock KMS with SHA-256 HMAC | AWS KMS Custom Key Store (CloudHSM) |
| **Monitoring** | In-memory `MetricRegistry` | Amazon CloudWatch + Prometheus Remote Write |

---

## 34. Architectural Risks

1. **Alert Fatigue**: Flooding the triage queue with low-severity signals.  
   *Mitigation*: Automated triage batching restricted to `HIGH`/`CRITICAL` rules and clustering thresholds.
2. **Analyst Collision**: Multiple analysts attempting simultaneous case triage.  
   *Mitigation*: Enforced optimistic concurrency control via integer `version` field.
3. **Data Leakage in Analyst Notes**: Analysts copying question text into investigation notes.  
   *Mitigation*: 6-layer Defense-in-Depth Confidentiality Model screens comments prior to persistence.
4. **Scope Creep**: Attempting to implement active containment in 5D.  
   *Mitigation*: Strict architectural boundary: 5D is read-only case management; 5E handles containment.

---

## 35. Required Decisions Reconciliation

All fundamental architectural decisions are resolved in Rev-03:
- **Decision A (Deduplication Semantics)**: Continuous sliding window across canonical correlation identity; clock-boundary crossing handled seamlessly.
- **Decision B (Authoritative Deduplication)**: Worker LRU is optimization only; PostgreSQL partial unique index and transactional catch-and-attach enforce authoritative uniqueness.
- **Decision C (Observational `CONTAINED` State)**: Milestone only; mandatory external containment reference metadata required; zero autonomous containment.
- **Decision D (Clean Lifecycle Model)**: 7 persistent states; `REOPENED` modeled as an auditable transition returning to `INVESTIGATING`; circular duplicate prevention via acyclic rules.
- **Decision E (`incident_id` vs `incident_number`)**: Full decoupling of authorization principal (UUIDv4) from human display reference.
- **Decision F (Comment Confidentiality)**: 6-layer Defense-in-Depth model with keyword screening recognized as secondary safeguard.

---

## 36. Proposed Implementation File List

Upon future implementation authorization:
1. `backend/alembic/versions/xxxx_phase3c5d_security_incidents.py` (New Migration)
2. `backend/app/modules/incident/__init__.py` (New Module)
3. `backend/app/modules/incident/models.py` (New Models)
4. `backend/app/modules/incident/service.py` (New Incident Service)
5. `backend/app/modules/incident/triage.py` (Signal Ingestion & Dedup Engine)
6. `backend/app/api/v1/incidents_v2.py` or updated `incidents.py` (API Endpoints)
7. `backend/tests/security/test_phase3c5d_incidents.py` (T01–T20 Test Suite)

---

## 37. Explicit Implementation Preconditions

Before implementation of Phase 3C-5D can begin:
1. User must formally review and approve Architecture Review Rev-03.
2. Baseline regression must continue reporting 240 passed, 5 skipped, 0 failed.
3. Git status must remain strictly verified on commit `7683dd6`.
4. User must provide explicit implementation authorization.

---

## 38. Final Architecture Verdict

**ARCHITECTURE APPROVED FOR IMPLEMENTATION PENDING USER REVIEW**

*(Implementation is NOT authorized. Awaiting your explicit review and authorization).*
