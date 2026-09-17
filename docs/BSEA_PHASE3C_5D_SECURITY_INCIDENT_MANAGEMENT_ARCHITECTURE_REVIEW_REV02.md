# B-SEA Phase 3C-5D — Security Incident Management Foundation
## Forensic Architecture & Design Review (Rev-02)

**System:** Bharat Secure Examination Architecture (B-SEA)  
**Milestone:** Phase 3C-5D — Security Incident Management Foundation  
**Status:** ARCHITECTURE REVIEW REV-02 (READ-ONLY ARCHITECTURAL DESIGN)  
**Document Revision:** Rev-02 (Reconciled against Rev-01 Forensic Review Findings 1–7)  
**Baseline Commit:** `7683dd6` (`feat: implement Phase 3C-5C detection correlation foundation`)  
**Baseline Verification:** `HEAD == origin/main` | Regression: 240 passed, 5 skipped, 0 failed  
**Governing Security Boundary:** Observational and Human-Managed Incident Case Workflow. **ZERO Autonomous Containment.**  

---

## 1. Executive Summary

Phase 3C-5D establishes the **Security Incident Management Foundation** for the Bharat Secure Examination Architecture. Where Phase 3C-5C delivered an observational, non-intrusive stream of deterministic, versioned advisory signals, Phase 3C-5D establishes the auditable, human-managed incident case lifecycle that ingests, triages, investigates, and resolves those signals.

### Revision Summary (Rev-01 to Rev-02 Reconciliation)
Rev-02 rigorously resolves the seven architectural reconciliation findings identified during the Rev-01 forensic review:
1. **Existing RBAC Role Alignment**: Grounded strictly in the authoritative repository RBAC implementation (`backend/app/core/models.py` lines 25–45 and `backend/app/modules/auth/service.py` lines 250–310). Proves that `SUPER_ADMIN`, `SECURITY_OFFICER`, `AUDITOR`, and `EXAM_AUTHORITY` are confirmed existing roles. Eliminates hypothetical future roles.
2. **Comment Sensitive-Data Protection**: Replaces naive keyword screening with a 6-layer Defense-in-Depth Confidentiality Model. Formally documents that keyword filtering is a secondary automated safeguard and not a substitute for strict payload structural restrictions, size constraints, and operational policy.
3. **Deterministic `dedup_key` Definition**: Formally specifies the canonical input tuple, deterministic normalization, SHA-256 hashing, 3600-second bounded window, and collision/race-condition handling via partial unique indexing and transactional catch-and-attach logic. Excludes raw exam content and forbids naive IP-based assumptions.
4. **`incident_id` vs. `incident_number` Separation**: Explicitly decouples the immutable internal authorization identifier (`incident_id`, UUIDv4) from the human-readable case display reference (`incident_number`). Enforces that `incident_number` is never trusted as an authorization principal or security boundary.
5. **Evidence Immutability & Availability Lifecycle**: Formally distinguishes $\text{Evidence Reference} \neq \text{Evidence Payload} \neq \text{Evidence Ownership}$. Establishes immutable link records that persist even if underlying evidence becomes unavailable (`UNAVAILABLE` state), backed by cryptographic source fingerprints.
6. **Finalized Incident Lifecycle & Semantics**: Defines explicit transition matrices across 8 justified states (`TRIAGE`, `INVESTIGATING`, `CONTAINED`*, `RESOLVED`, `FALSE_POSITIVE`, `DUPLICATE`, `CLOSED`, `REOPENED`). Clarifies that `CLOSED` is an administrative sign-off (not deletion), `REOPENED` is an auditable transition, and `CONTAINED` is strictly an observational milestone recording external action without autonomous containment.
7. **Incident Creation Concurrency & Tri-Partite Model**: Formally delineates `Signal Deduplication` vs. `Incident Creation` vs. `Incident Merging`. Specifies transactional race handling preventing duplicate incident creation without arbitrary last-write-wins overwrites.

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

## 3. Existing Architecture Inspection

A rigorous code-level inspection of the repository establishes the existing architectural foundation:

1. **RBAC Source of Truth (`backend/app/core/models.py` & `backend/app/modules/auth/service.py`)**:
   - `UserRoleEnum` explicitly enumerates:
     - `SUPER_ADMIN`
     - `EXAM_AUTHORITY`
     - `QUESTION_SETTER`
     - `REVIEWER`
     - `MODERATOR`
     - `SECURITY_OFFICER`
     - `RELEASE_AUTHORITY`
     - `CENTRE_ADMIN`
     - `INVIGILATOR`
     - `CANDIDATE`
     - `AUDITOR`
   - `ROLE_PERMISSIONS` in `auth/service.py` already provisions:
     - `SECURITY_OFFICER`: `"security:read"`, `"security:manage"`, `"incidents:create"`, `"incidents:manage"`, `"audit:read"`
     - `SUPER_ADMIN`: `"security:manage"`, `"incidents:manage"`, `"audit:read"`, `"system:admin"`
     - `AUDITOR`: `"audit:read"`, `"security:read"`, `"exams:read"`, `"questions:read_metadata"`, `"break_glass:view"`
     - `EXAM_AUTHORITY`: `"exams:create"`, `"exams:read"`, `"exams:update"`, `"blueprint:read"`, `"candidates:read"`
   - *Rev-02 Finding 1 Resolution*: No hypothetical roles are assumed. All 5D operations map directly to existing roles.

2. **Audit Subsystem (`backend/app/modules/audit/service.py`)**:
   - Authoritative dual-mode ingestion: Mode A (business-atomic, caller transaction) and Mode B (security-isolated, autonomous commit).
   - *Rev-02 Finding 5 Resolution*: Incident case mutations must log to `AuditService.log` in Mode A. Unauthorized access attempts log to `log_security_event` in Mode B. 5D never maintains an independent audit log.

3. **Detection Subsystem (`backend/app/modules/detection/`)**:
   - `SecuritySignal`: Output of Phase 3C-5C. Advisory dataclass containing `signal_id`, `rule_id`, `rule_version`, `detected_at`, `severity`, `confidence`, `mode="shadow"`, `correlation_keys`, and `evidence_references`.
   - *Rev-02 Finding 3 Resolution*: Signals are the primary ingestion trigger for automated triage batching.

4. **Legacy Security Subsystem (`backend/app/modules/security/service.py` & `models.py`)**:
   - Legacy `incidents` table and legacy endpoint `POST /api/v1/incidents/{id}/action`.
   - *Rev-02 Finding 6 Resolution*: The legacy endpoint contains un-audited unilateral containment actions (`LOCK_USER`, `REVOKE_SESSION`). Rev-02 specifies that 5D bypasses and formally deprecates these legacy actions, replacing them with modern, purely observational incident management in `backend/app/modules/incident/`.

---

## 4. 5C → 5D Boundary

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
- A detection signal is an advisory mathematical assertion of anomaly.
- A security incident is a human-managed investigative container.
- An incident only reaches a confirmed finding through explicit analyst investigation.
- Detection failures cannot disrupt candidate examination workflows. Incident management failures cannot disrupt candidate examination workflows.

---

## 5. Incident Domain Model (Reconciling Finding 4)

Rev-02 establishes a strict distinction between internal security identifiers and human-readable references:

### `incident_id` vs. `incident_number` Separation

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
- `policy_version`: Policy definition governing triage (e.g., `BSEA-INCIDENT-v1`).
- `created_by`: Foreign key to `users.id` (or designated system user for automated triage).
- `assigned_to`: Foreign key to `users.id` (nullable; restricted to `SECURITY_OFFICER` or `SUPER_ADMIN`).
- `exam_id`: Optional foreign key to `exams.id`.
- `centre_id`: Optional foreign key to `centres.id`.
- `created_at`: UTC timezone-aware timestamp.
- `updated_at`: UTC timezone-aware timestamp.
- `resolved_at`: UTC timestamp of resolution (nullable).
- `closed_at`: UTC timestamp of administrative sign-off (nullable).
- `resolution_category`: Bounded resolution classification.
- `resolution_notes`: Analytical summary of findings.
- `version`: Integer column for Optimistic Concurrency Control (OCC).

---

## 6. Incident Lifecycle (Reconciling Finding 6)

The Phase 3C-5D incident lifecycle models qualified human investigation while strictly prohibiting autonomous intervention:

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
                      ▼
           ┌─────────────────────┐
           │      REOPENED       │
           └─────────────────────┘
```

### Lifecycle State Definitions
1. **`TRIAGE`**: Initial state upon automated creation or signal clustering. Pending priority assessment and analyst assignment.
2. **`INVESTIGATING`**: Formally assigned to a Security Officer actively reviewing evidence and audit logs.
3. **`CONTAINED`\***: Informational milestone recording that authorized external or manual containment (e.g., via future Phase 3C-5E) was completed and verified by an analyst. **Phase 3C-5D executes zero containment actions.**
4. **`RESOLVED`**: Analytical determination reached; remediation and investigative conclusions documented.
5. **`FALSE_POSITIVE`**: Confirmed to be benign activity, operational retry, or system glitch.
6. **`DUPLICATE`**: Redundant case linked to an existing primary incident.
7. **`CLOSED`**: Terminal administrative sign-off by a Super Admin. **`CLOSED` means administrative closure after resolution, NOT database deletion.**
8. **`REOPENED`**: Formally re-activated investigation following subsequent related signals or verifier failures.

---

## 7. State Transition Matrix (Reconciling Finding 6)

Every state transition requires strict role authorization, mandatory preconditions, OCC version verification, and immediate Mode A audit logging:

| From Status | To Status | Authorized Roles | Required Preconditions | Reversible? | Audit Event |
| :--- | :--- | :--- | :--- | :---: | :--- |
| `TRIAGE` | `INVESTIGATING` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Analyst assignment non-null | Yes | `INCIDENT_STATUS_CHANGED` |
| `TRIAGE` | `FALSE_POSITIVE` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Rationale documented ($\ge 20$ chars) | Yes | `INCIDENT_STATUS_CHANGED` |
| `TRIAGE` | `DUPLICATE` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Primary incident reference specified | Yes | `INCIDENT_STATUS_CHANGED` |
| `INVESTIGATING` | `CONTAINED` | `SECURITY_OFFICER`, `SUPER_ADMIN` | External containment reference documented | Yes | `INCIDENT_STATUS_CHANGED` |
| `INVESTIGATING` | `RESOLVED` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Resolution category & summary documented | No | `INCIDENT_RESOLVED` |
| `INVESTIGATING` | `FALSE_POSITIVE` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Rationale documented ($\ge 20$ chars) | Yes | `INCIDENT_STATUS_CHANGED` |
| `CONTAINED` | `RESOLVED` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Resolution category & summary documented | No | `INCIDENT_RESOLVED` |
| `RESOLVED` | `CLOSED` | `SUPER_ADMIN` ONLY | Supervisory review completed | No | `INCIDENT_CLOSED` |
| `RESOLVED` | `REOPENED` | `SECURITY_OFFICER`, `SUPER_ADMIN` | New evidence reference documented | Yes | `INCIDENT_REOPENED` |
| `CLOSED` | `REOPENED` | `SUPER_ADMIN` ONLY | Super Admin formal justification | Yes | `INCIDENT_REOPENED` |

### Forbidden Transitions
- Direct `TRIAGE` $	o$ `RESOLVED` (bypassing investigation is strictly prohibited).
- Direct `TRIAGE` $	o$ `CLOSED` (bypassing resolution and supervisory review is strictly prohibited).
- Direct `INVESTIGATING` $	o$ `CLOSED` (resolution documentation is a mandatory prerequisite for closure).
- Any transition performed by unauthorized roles (`CANDIDATE`, `INVIGILATOR`, `REVIEWER`, `CENTRE_ADMIN`).

---

## 8. Signal-to-Incident Relationship

Advisory detection signals from Phase 3C-5C transition into incident cases via policy-controlled triage:

```
┌────────────────────────────────────────────────────────┐
│                   PHASE 3C-5C SIGNALS                  │
│                                                        │
│  [RULE-E, RULE-F, RULE-H, RULE-J] ──► Auto Triage Case │
│  (High / Critical Rules)                               │
│                                                        │
│  [RULE-A, RULE-B, RULE-C, RULE-D] ──► Threshold Cluster│
│  (Medium / Low Rules)                 (>= 3 in 30m)    │
│                                                        │
│  [Isolated Advisory Signals]     ──► Analyst Manual    │
│                                      Promotion         │
└────────────────────────────────────────────────────────┘
```

1. **Automatic Direct Triage**:
   - Signals from high-assurance detection rules (`RULE-E` Scope Misuse, `RULE-F` Audit Anomaly, `RULE-H` Tampering, `RULE-J` Sealer Degradation) or any signal with severity `CRITICAL` automatically spawn an incident in `TRIAGE` or attach to an existing active case matching `dedup_key`.
2. **Threshold-Based Clustering**:
   - Isolated `LOW` or `MEDIUM` signals remain advisory records in detection storage.
   - If $\ge 3$ advisory signals share the same correlation context within 30 minutes, an automated triage case is opened.
3. **Manual Promotion**:
   - Qualified Security Officers may manually promote any advisory signal to a formal incident case via `POST /api/v1/incidents/promote`.

---

## 9. Incident Deduplication Strategy (Reconciling Finding 3 & 7)

### Canonical `dedup_key` Specification
To prevent alert fatigue and redundant incident creation during security event bursts (e.g., 50 KMS failure events triggering 50 signals for a single key):

$$\text{dedup\_key} = \text{SHA-256}(\text{rule\_id} \mathbin{\Vert} \text{dim\_key} \mathbin{\Vert} \text{dim\_val} \mathbin{\Vert} \text{time\_bucket} \mathbin{\Vert} \text{policy\_version})$$

### Canonical Input Elements
1. `rule_id`: String (e.g., `"RULE-G"`, `"RULE-A"`).
2. `dim_key`: Canonical primary dimension (`"resource_id"`, `"actor_id"`, `"device_id"`, `"session_id"`, `"exam_id"`).
3. `dim_val`: Normalized, lowercase, stripped string representation of the dimension value.
4. `time_bucket`: Monotonic 3600-second (1-hour) integer window:
   $$\text{time\_bucket} = \lfloor \text{timestamp\_epoch\_seconds} / 3600 \rfloor$$
5. `policy_version`: Policy string (`"BSEA-INCIDENT-v1"`).

### Deterministic Serialization
```python
raw_bytes = f"{rule_id}:{dim_key}:{dim_val}:{time_bucket}:{policy_version}".encode("utf-8")
dedup_key = hashlib.sha256(raw_bytes).hexdigest()
```

### Negative Invariants
- **No Sensitive Data**: `dedup_key` inputs NEVER include plaintext question content, answer keys, candidate responses, passwords, or cryptographic keys.
- **No IP Equivalence**: The engine NEVER assumes `same IP = same actor` or `same IP = same incident`. Network-level correlations use `ip_hash` only as a secondary dimension and require explicit actor corroboration.

---

## 10. Evidence Reference Architecture (Reconciling Finding 5)

Rev-02 establishes an explicit, fundamental architectural distinction:

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
1. **Immutable References**: Evidence links are stored as immutable pointers in `incident_evidence_links`.
2. **Persistence During Source Unavailability**: If the underlying source event is later archived, partitioned, or deleted under retention policies, the `IncidentEvidenceLink` **must NOT be deleted**.
   - The link status transitions to `evidence_state = "UNAVAILABLE"`.
   - The incident case and forensic linkage remain 100% intact.
3. **Cryptographic Source Fingerprinting**: When an evidence link is created, the system computes `evidence_hash = SHA-256(source_record_canonical_bytes)`.
   - Subsequent verifications compare active source content against `evidence_hash`.
   - If the source record has been altered, the link status transitions to `CONFLICTING`.
4. **Zero Payload Duplication**: Incident records never duplicate raw event payloads. The authoritative audit chain (`audit_logs`) remains the single source of truth for audit evidence.

---

## 11. Evidence Access Control (Reconciling Finding 1 & 5)

Evidence visibility is decoupled from high-level incident case summaries:
- **Least Privilege**: Users authorized to view incident triage lists (`EXAM_AUTHORITY`) are **not** permitted to inspect raw security evidence records.
- **Access Authorization Matrix**:
  - `SUPER_ADMIN`: Full evidence inspection.
  - `SECURITY_OFFICER`: Full evidence inspection.
  - `AUDITOR`: Read-only evidence inspection and cryptographic verification.
  - `EXAM_AUTHORITY`, `CANDIDATE`, `INVIGILATOR`, `REVIEWER`: **ZERO** evidence access.
- **Forensic Audit Logging**: Every evidence retrieval API call (`GET /api/v1/incidents/{id}/evidence/{evidence_id}`) emits an `INCIDENT_EVIDENCE_VIEWED` Mode A audit event logging the accessing analyst, timestamp, and target evidence UUID.

---

## 12. RBAC Model (Reconciling Finding 1)

### Mapping to Authoritative Repository Roles
In strict compliance with Finding 1, incident management permissions map exclusively to roles currently implemented in `backend/app/core/models.py` (`UserRoleEnum`) and `backend/app/modules/auth/service.py` (`ROLE_PERMISSIONS`):

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

## 13. Analyst Assignment

- Incidents in `TRIAGE` may be assigned to any active user possessing the `SECURITY_OFFICER` or `SUPER_ADMIN` role.
- Self-assignment is supported and transitions the incident from `TRIAGE` to `INVESTIGATING`.
- Re-assignment requires logging `INCIDENT_REASSIGNED` with previous and new assignee IDs.

---

## 14. Analyst Comments / Notes (Reconciling Finding 2)

### 6-Layer Defense-in-Depth Confidentiality Model
Rev-02 explicitly establishes that keyword screening is a secondary safeguard and cannot guarantee detection of all sensitive examination content. Confidentiality is enforced across six layered barriers:

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

## 15. Concurrency Strategy (Reconciling Finding 7)

Phase 3C-5D establishes a formal tri-partite concurrency model:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   TRI-PARTITE CONCURRENCY MODEL                        │
│                                                                        │
│  1. Signal Deduplication  ──► Drops duplicate SQS/Worker messages via   │
│                               process-local LRU & idempotency hash     │
│                                                                        │
│  2. Incident Creation     ──► Prevents duplicate incident creation via  │
│                               Partial Unique Index & Catch-and-Attach  │
│                                                                        │
│  3. Incident Modification ──► Prevents concurrent analyst collisions   │
│                               via Optimistic Concurrency Control (OCC) │
└────────────────────────────────────────────────────────────────────────┘
```

### 1. Signal Deduplication (Worker Layer)
- Dropping identical duplicate signals at the correlation/worker layer via signal idempotency hash.

### 2. Incident Creation Concurrency (Database Layer)
- **Partial Unique Index**:
  ```sql
  CREATE UNIQUE INDEX uq_active_incident_dedup 
  ON security_incidents (dedup_key) 
  WHERE status IN ('TRIAGE', 'INVESTIGATING');
  ```
- **Concurrent Creation Race Handling (Catch-and-Attach)**:
  - If Process A and Process B attempt to create an incident for the same `dedup_key` simultaneously:
    - Process A's `INSERT` succeeds.
    - Process B's `INSERT` raises `UniqueViolation` (`IntegrityError`).
    - Process B's transaction catches the exception, queries the existing active incident by `dedup_key`, attaches the signal as a new `IncidentEvidenceLink`, and updates `updated_at`.
    - **Guaranteed Result**: Zero duplicate incidents created; all evidence safely consolidated.

### 3. Incident Modification Concurrency (OCC Layer)
- Every `SecurityIncident` row maintains an integer `version` column, initialized to `1`.
- State transitions, assignments, and resolution updates must supply the client's current `version`:
  ```sql
  UPDATE security_incidents
  SET status = :new_status, version = version + 1, updated_at = :now
  WHERE id = :id AND version = :client_version;
  ```
- If rows updated equals `0`, the server raises `HTTP 409 Conflict` ("Incident has been modified concurrently by another analyst. Please refresh."). Last-write-wins is strictly prohibited.

---

## 16. Severity Model

Incident severity is decoupled from detection signal severity:
- A `HIGH` detection signal may be triaged to `LOW` if surrounding audit context proves an authorized maintenance drill.
- A `MEDIUM` signal may be escalated to `CRITICAL` if correlated with physical centre anomalies.
- **Escalation Policy**:
  - Severity values: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
  - Modification requires explicit rationale ($\ge 20$ chars) and emits `INCIDENT_SEVERITY_CHANGED` to the audit chain.

---

## 17. Incident Types

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

## 18. Incident Timeline

Chronological incident history is dynamically assembled from authoritative sources:
1. Creation event from `security_incidents.created_at`.
2. Evidence link timestamps from `incident_evidence_links`.
3. Transition history queried directly from `audit_logs` where `resource_id = incident_id`.
4. Comment timestamps from `incident_comments`.
5. Resolution and closure timestamps.

The timeline is reconstructed dynamically via queries; it does not duplicate the audit log.

---

## 19. Audit Integration

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

## 20. Database Schema Proposal (Reconciling Finding 4 & 7)

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
        'TRIAGE', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE', 'DUPLICATE', 'CLOSED', 'REOPENED'
    ))
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

## 21. Constraints and Indexes

- Foreign keys to `users.id`, `exams.id`, and `centres.id` enforce relational integrity.
- `ON DELETE RESTRICT` on evidence links and comments strictly prevents accidental cascading deletion.
- Composite indexes on `(status, severity)` and `(assigned_to)` optimize triage queue queries.

---

## 22. Retention and Deletion Policy

- **No Hard Deletes**: Direct `DELETE` queries on `security_incidents` are blocked by foreign key constraints and application RBAC.
- **No Soft Delete Column**: The entity does not implement `is_deleted`. Decommissioning an incident occurs exclusively through the `CLOSED` terminal state.
- **Legal Hold**: Closed incidents retain immutable links to audit records indefinitely.

---

## 23. API Architecture

All endpoints enforce authorization, OCC version verification, and Mode A audit logging:

1. `POST /api/v1/incidents/` (Create manual case) — `SECURITY_OFFICER`, `SUPER_ADMIN`
2. `GET /api/v1/incidents/` (List triage cases) — `SECURITY_OFFICER`, `SUPER_ADMIN`, `AUDITOR`, `EXAM_AUTHORITY`
3. `GET /api/v1/incidents/{incident_id}` (Retrieve case details) — Authorized roles (resolves on `incident_id`)
4. `POST /api/v1/incidents/{incident_id}/assign` (Assign/reassign analyst) — `SECURITY_OFFICER`, `SUPER_ADMIN`
5. `POST /api/v1/incidents/{incident_id}/status` (Execute state transition with OCC version) — `SECURITY_OFFICER`, `SUPER_ADMIN`
6. `GET /api/v1/incidents/{incident_id}/evidence` (List linked evidence) — `SECURITY_OFFICER`, `SUPER_ADMIN`, `AUDITOR`
7. `POST /api/v1/incidents/{incident_id}/comments` (Append analyst note) — `SECURITY_OFFICER`, `SUPER_ADMIN`
8. `POST /api/v1/incidents/{incident_id}/resolve` (Document findings & resolve) — `SECURITY_OFFICER`, `SUPER_ADMIN`
9. `POST /api/v1/incidents/{incident_id}/close` (Administrative supervisory closure) — `SUPER_ADMIN` ONLY

---

## 24. Frontend / Analyst UI Architecture

Conceptual layout for the Security Operations Console:
- **Triage Queue**: Filterable by status and severity, displaying `incident_number`, title, and elapsed time.
- **Investigation Workspace**:
  - Display Header: `incident_number` (display only; links resolve to `incident_id`).
  - Evidence Explorer: Visualizes link status (`AVAILABLE`, `UNAVAILABLE`, `CONFLICTING`).
  - Append-Only Log: Chronological notes.
  - OCC Conflict Banner: Informs analyst if incident was updated concurrently.

---

## 25. Failure Semantics

- **PostgreSQL Unavailable**: Incident creation fails; detection signals remain safely buffered in SQS Standard Queue; candidate examination delivery continues 100% unaffected.
- **Audit Service Unavailable**: Incident status transitions abort; incident state cannot change without sealed audit recording.
- **Analyst Session Expiry**: API returns HTTP 401; examination traffic continues unaffected.

---

## 26. 5D vs 5E Boundary

| Dimension | Phase 3C-5D (Incident Management) | Phase 3C-5E (Policy-Governed Containment) |
| :--- | :--- | :--- |
| **Primary Goal** | Human investigation, triage, case tracking | Active threat containment & intervention |
| **System Interaction** | Read-only analysis & advisory case management | Active intervention on sessions, keys, and exams |
| **Autonomous Action** | **ZERO autonomous containment** | Policy-evaluated containment with dual custody |
| **Session Impact** | Candidates are NEVER terminated or blocked | Authoritative session revocation with dual authorization |
| **Quarantine Impact** | No quarantine actions | Dual-custody audit/content quarantine |
| **Status Semantics** | `CONTAINED` is an informational milestone | Active execution of containment mechanisms |

---

## 27. 5D vs 5F Boundary

- **Phase 3C-5D**: Self-contained internal incident case management.
- **Phase 3C-5F**: Enterprise SIEM integration (AWS Security Lake, OpenSearch, Splunk, PagerDuty, external webhooks). 5D does not implement external SOC connectors.

---

## 28. Legacy SecurityService Coexistence

1. `backend/app/modules/security/service.py` remains frozen and untouched.
2. The modern incident management subsystem will be implemented cleanly in `backend/app/modules/incident/`.
3. The legacy endpoint `POST /api/v1/incidents/{incident_id}/action` (which allows unilateral user locking and session revoking) is formally bypassed and marked for deprecation in 5D, to be fully removed in 5E in favor of dual-custody policy containment.

---

## 29. Security Invariants for 5D

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

## 30. Future Test Matrix (T01–T20)

- **T01**: Incident creation authorization (`SECURITY_OFFICER` & `SUPER_ADMIN`).
- **T02**: Unauthorized role rejection (`CANDIDATE`, `INVIGILATOR`, `REVIEWER` rejected with HTTP 403).
- **T03**: Signal-to-incident reference integrity and metadata preservation.
- **T04**: Signal deduplication into active triage incident via `dedup_key`.
- **T05**: Valid status transition lifecycle flow (`TRIAGE` $	o$ `INVESTIGATING` $	o$ `RESOLVED` $	o$ `CLOSED`).
- **T06**: Invalid status transition rejection (e.g., direct `TRIAGE` $	o$ `CLOSED` rejected).
- **T07**: Optimistic concurrency control (concurrent updates return HTTP 409).
- **T08**: Concurrent incident creation race handling (catch-and-attach verification).
- **T09**: Evidence linking and access authorization.
- **T10**: Sensitive exam content screening (6-layer defense on comments).
- **T11**: Audit event generation across all status transitions.
- **T12**: Severity modification authorization and audit trail.
- **T13**: Resolution documentation enforcement ($\ge 20$ chars required).
- **T14**: Incident reopening semantics and privilege check (`SUPER_ADMIN` required for closed case).
- **T15**: Duplicate incident linking and resolution closure.
- **T16**: Database outage isolation (exam traffic continues during DB incident error).
- **T17**: Detection outage isolation (incidents can be created manually during detection lag).
- **T18**: Candidate traffic independence (zero candidate session disruption).
- **T19**: Physical deletion restriction (enforces `ON DELETE RESTRICT`).
- **T20**: 5E containment boundary enforcement (zero autonomous containment).

---

## 31. Prototype vs Production

| Component | Prototype / CI Baseline | Production Target (AWS) |
| :--- | :--- | :--- |
| **Database** | Local PostgreSQL 16 on Docker | Amazon RDS PostgreSQL 16 Multi-AZ + RDS Proxy |
| **Queue Dispatch** | In-process `asyncio.Queue` | Amazon SQS Standard Queue with KMS SSE |
| **RBAC** | FastAPI dependency injection | Enterprise IAM with OIDC / GovID SAML 2.0 |
| **Audit Sealing** | Local mock KMS with SHA-256 HMAC | AWS KMS Custom Key Store (CloudHSM) |
| **Monitoring** | In-memory `MetricRegistry` | Amazon CloudWatch + Prometheus Remote Write |

---

## 32. Architectural Risks

1. **Alert Fatigue**: Flooding the triage queue with low-severity signals.  
   *Mitigation*: Automated triage batching restricted to `HIGH`/`CRITICAL` rules and clustering thresholds.
2. **Analyst Collision**: Multiple analysts attempting simultaneous case triage.  
   *Mitigation*: Enforced optimistic concurrency control via integer `version` field.
3. **Data Leakage in Analyst Notes**: Analysts copying question text into investigation notes.  
   *Mitigation*: 6-layer Defense-in-Depth Confidentiality Model screens comments prior to persistence.
4. **Scope Creep**: Attempting to implement active containment in 5D.  
   *Mitigation*: Strict architectural boundary: 5D is read-only case management; 5E handles containment.

---

## 33. Required Decisions Reconciliation

All fundamental architectural decisions are resolved in Rev-02:
- **Decision A (RBAC Alignment)**: Strict mapping to existing repository roles (`SUPER_ADMIN`, `SECURITY_OFFICER`, `AUDITOR`, `EXAM_AUTHORITY`).
- **Decision B (Comment Confidentiality)**: 6-layer Defense-in-Depth model. Keyword screening recognized as secondary.
- **Decision C (`dedup_key` Definition)**: Canonical normalization, SHA-256 hash across rule, dimension, 1-hour time bucket, and policy version.
- **Decision D (`incident_id` vs `incident_number`)**: Full decoupling of authorization principal (UUIDv4) from human display reference.
- **Decision E (Evidence Lifecycle)**: Immutable link records persistence (`UNAVAILABLE` state) with cryptographic source fingerprints.
- **Decision F (Lifecycle Semantics)**: 8 justified states. `CLOSED` is administrative sign-off; `CONTAINED` is observational only.
- **Decision G (Creation Concurrency)**: Tri-partite model with partial unique indexing and transactional catch-and-attach handling.

---

## 34. Proposed Implementation File List

Upon future implementation authorization:
1. `backend/alembic/versions/xxxx_phase3c5d_security_incidents.py` (New Migration)
2. `backend/app/modules/incident/__init__.py` (New Module)
3. `backend/app/modules/incident/models.py` (New Models)
4. `backend/app/modules/incident/service.py` (New Incident Service)
5. `backend/app/modules/incident/triage.py` (Signal Ingestion & Dedup Engine)
6. `backend/app/api/v1/incidents_v2.py` or updated `incidents.py` (API Endpoints)
7. `backend/tests/security/test_phase3c5d_incidents.py` (T01–T20 Test Suite)

---

## 35. Explicit Implementation Preconditions

Before implementation of Phase 3C-5D can begin:
1. User must formally review and approve Architecture Review Rev-02.
2. Baseline regression must continue reporting 240 passed, 5 skipped, 0 failed.
3. Git status must remain strictly verified on commit `7683dd6`.
4. User must provide explicit implementation authorization.

---

## 36. Final Architecture Verdict

**ARCHITECTURE APPROVED FOR IMPLEMENTATION PENDING USER REVIEW**

*(Implementation is NOT authorized. Awaiting your explicit review and authorization).*
