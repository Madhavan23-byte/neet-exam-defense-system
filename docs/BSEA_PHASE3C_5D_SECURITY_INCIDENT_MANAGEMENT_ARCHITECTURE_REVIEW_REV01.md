# B-SEA Phase 3C-5D — Security Incident Management Foundation
## Architecture Review Rev-01 — Strict Architecture Document

**System:** Bharat Secure Examination Architecture (B-SEA)  
**Milestone:** Phase 3C-5D — Security Incident Management Foundation  
**Status:** ARCHITECTURE REVIEW REV-01 (READ-ONLY ARCHITECTURAL DESIGN)  
**Baseline Commit:** `7683dd6` (`feat: implement Phase 3C-5C detection correlation foundation`)  
**Baseline Verification:** `HEAD == origin/main` | Regression: 240 passed, 5 skipped, 0 failed  
**Governing Security Boundary:** Observational and Human-Managed Incident Case Workflow. **ZERO Autonomous Containment.**  

---

## 1. Executive Summary

Phase 3C-5D introduces the **Security Incident Management Foundation** for the Bharat Secure Examination Architecture. Where Phase 3C-5C established an observational, non-intrusive stream of deterministic, versioned advisory signals, Phase 3C-5D establishes the formal, auditable, and human-managed incident case lifecycle that ingests, triages, investigates, and resolves those signals.

### Fundamental Principle: Preserving Epistemic Uncertainty
In a mission-critical, high-assurance examination ecosystem, a detection signal is an **advisory observation**, not a confirmed breach. Phase 3C-5D explicitly enforces the epistemic distinction:
$$\text{Security Event} \neq \text{Detection Signal} \neq \text{Confirmed Incident} \neq \text{Examination Leak}$$

A detection signal emitted by Phase 3C-5C represents an anomaly or rule match. Phase 3C-5D introduces an evidence-backed case construct—the **Security Incident**—managed by qualified human analysts (Security Officers and Super Admins). Under no circumstances does Phase 3C-5D execute automated containment, candidate session termination, account suspension, IP bans, or exam cancellation. Autonomous and dual-custody containment is strictly deferred to Phase 3C-5E.

---

## 2. Repository Baseline

- **Current Repository Commit:** `7683dd6` (`feat: implement Phase 3C-5C detection correlation foundation`)
- **Branch Tracking:** `HEAD == origin/main` (Clean working tree on all tracked files)
- **Regression Suite Baseline:** 240 passed, 5 skipped, 0 failed in 110s
- **Phase 3C-5C Status:** Implemented, verified, and locked in SHADOW MODE
- **Active Schema State:** PostgreSQL 16 schema at revision `f1a2b3c4d5e6` (Phase 3C-5A poison quarantine)
- **Metric Series Baseline:** 646 base series (520 from 5B + 126 from 5C), 1,516 expanded Prometheus series

---

## 3. Existing Architecture Inspection

A comprehensive read-only audit of the repository reveals the following structural touchpoints:

1. **Audit Subsystem (`backend/app/modules/audit/`)**:
   - `AuditLog`: Immutable, append-only business and security events.
   - `AuditChainLink` & `AuditEpochSeal`: SHA-256 HMAC and KMS asymmetric sealing with strict chronological sequences.
   - `AuditService`: Implements Mode A (business-atomic) and Mode B (security-critical isolated session) logging.
   - *5D Implication*: All incident operations (creation, assignment, status change, evidence review, resolution) must log to `AuditService` in Mode A or B. 5D must never create a secondary audit log.

2. **Detection Subsystem (`backend/app/modules/detection/`)**:
   - `SecuritySignal`: Advisory detection payload containing `signal_id`, `rule_id`, `rule_version`, `detected_at`, `severity`, `confidence`, `mode="shadow"`, `correlation_keys`, and `evidence_references`.
   - `engine.py`: Emits advisory signals to memory/SQS; strictly observational.
   - *5D Implication*: Signals provide the primary ingest trigger for automated triage batching and analyst investigation.

3. **Legacy Security Subsystem (`backend/app/modules/security/service.py` & `models.py`)**:
   - Legacy `SecurityEvent`: Early prototype table storing un-audited risk scores.
   - Legacy `Incident`: Basic prototype table (`title`, `severity`, `status`, `exam_id`, `description`, `actions_taken`, `resolution`).
   - Legacy API (`backend/app/api/v1/incidents.py`): Contains a prototype endpoint `POST /api/v1/incidents/{id}/action` implementing unilateral, un-audited actions (`LOCK_USER`, `REVOKE_SESSION`).
   - *5D Implication*: The legacy `Incident` table and endpoint lack formal state machine guarantees, optimistic locking, immutable evidence links, and audit sealing. 5D must define a modern, normalized domain model while providing a safe migration/coexistence plan.

4. **RBAC & Authorization (`backend/app/core/models.py`)**:
   - Roles in `UserRoleEnum`: `SUPER_ADMIN`, `EXAM_AUTHORITY`, `QUESTION_SETTER`, `REVIEWER`, `MODERATOR`, `SECURITY_OFFICER`, `RELEASE_AUTHORITY`, `CENTRE_ADMIN`, `INVIGILATOR`, `CANDIDATE`, `AUDITOR`.
   - *5D Implication*: Incident investigation must be restricted exclusively to `SECURITY_OFFICER` and `SUPER_ADMIN`, with read-only supervisory access for `AUDITOR` and high-level summaries for `EXAM_AUTHORITY`.

---

## 4. 5C → 5D Boundary

The boundary between Detection (5C) and Incident Management (5D) is strictly unidirectional and decoupled:

```
┌────────────────────────────────────────────────────────┐
│               PHASE 3C-5C: DETECTION                   │
│                                                        │
│  [Event] ──► [Correlation] ──► [Rules A-J] ──► [Signal] │
│                                            (Shadow Mode)
└───────────────────────────┬────────────────────────────┘
                            │ Advisory Signal Delivery
                            │ (SQS Standard / In-Memory)
                            ▼
┌────────────────────────────────────────────────────────┐
│         PHASE 3C-5D: INCIDENT MANAGEMENT               │
│                                                        │
│  [Advisory Signal]                                     │
│         │                                              │
│         ▼                                              │
│  [Policy Triage & Dedup] ──► [Security Incident]       │
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

- **5C Responsibility**: Observe, normalize, correlate, evaluate, and emit advisory signals.
- **5D Responsibility**: Ingest advisory signals, aggregate duplicates, create structured incident cases, record analyst evidence links and comments, track investigation state, and log resolutions to the audit chain.
- **Strict Boundary**: Detection failure does not affect exam delivery. Incident management failure does not affect exam delivery.

---

## 5. Incident Domain Model

The proposed core entity is the **SecurityIncident**, representing a formal security case:

### Conceptual Entity Attributes
- `incident_id`: UUIDv4 primary identifier.
- `incident_number`: Human-readable monotonic reference (e.g., `INC-2026-00042`).
- `incident_type`: Bounded enumeration classifying the threat vector.
- `severity`: Current triage severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- `initial_severity`: Severity at creation (preserved for escalation tracking).
- `status`: Current lifecycle state.
- `title`: Sanitized, safe summary (max 255 characters).
- `summary`: Detailed contextual description (sanitized of exam content).
- `dedup_key`: SHA-256 hash used for clustering recurring signals.
- `policy_version`: Policy definition under which triage occurred (e.g., `BSEA-INCIDENT-v1`).
- `created_by`: Foreign key to `users.id` (or `SYSTEM_DETECTION_WORKER`).
- `assigned_to`: Foreign key to `users.id` (nullable).
- `exam_id`: Associated examination reference (nullable).
- `centre_id`: Associated examination centre reference (nullable).
- `created_at`: UTC timestamp of creation.
- `updated_at`: UTC timestamp of last modification.
- `resolved_at`: UTC timestamp of resolution (nullable).
- `closed_at`: UTC timestamp of administrative sign-off (nullable).
- `resolution_category`: Bounded resolution classification.
- `resolution_notes`: Analytical summary of resolution.
- `version`: Monotonic integer for optimistic concurrency control.

### Critical Sanitization Boundary
Under no circumstances may a `SecurityIncident` store:
- Plaintext examination questions (`question_text`)
- Plaintext answer keys (`answer_key`)
- Candidate responses or essay bodies
- Decryption keys, DEKs, KEKs, session keys
- Passwords, JWTs, or session tokens

---

## 6. Incident Lifecycle

The incident lifecycle models human analytical investigation while strictly preserving uncertainty:

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

*\*Note on `CONTAINED`: In Phase 3C-5D, `CONTAINED` is an informational milestone recording that authorized external or manual containment (e.g., via Phase 3C-5E) was confirmed by an analyst. Phase 3C-5D does not itself execute containment.*

### Lifecycle State Definitions
1. **`TRIAGE`**: Initial state upon ingestion. Pending analyst review and priority assignment.
2. **`INVESTIGATING`**: Formally assigned to a Security Officer actively reviewing evidence.
3. **`CONTAINED`**: Containment verified by human analyst through external/future Phase 5E controls.
4. **`RESOLVED`**: Analytical determination reached and documented.
5. **`FALSE_POSITIVE`**: Confirmed to be benign activity, system glitch, or normal operational retry.
6. **`DUPLICATE`**: Identified as redundant; linked to an existing primary incident.
7. **`CLOSED`**: Final administrative sign-off by a Super Admin or Security Lead.
8. **`REOPENED`**: Re-activated following subsequent related security signals or verifier failure.

---

## 7. State Transition Matrix

Every transition requires explicit role authorization, documented rationale, and immediate audit chain recording:

| Current Status | Target Status | Authorized Roles | Required Preconditions | Audit Event Emitted |
| :--- | :--- | :--- | :--- | :--- |
| `TRIAGE` | `INVESTIGATING` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Analyst assignment non-null | `INCIDENT_STATUS_CHANGED` |
| `TRIAGE` | `FALSE_POSITIVE` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Rationale documented ($\ge 20$ chars) | `INCIDENT_STATUS_CHANGED` |
| `TRIAGE` | `DUPLICATE` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Primary incident reference specified | `INCIDENT_STATUS_CHANGED` |
| `INVESTIGATING` | `CONTAINED` | `SECURITY_OFFICER`, `SUPER_ADMIN` | External containment reference documented | `INCIDENT_STATUS_CHANGED` |
| `INVESTIGATING` | `RESOLVED` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Resolution category and summary documented | `INCIDENT_RESOLVED` |
| `INVESTIGATING` | `FALSE_POSITIVE` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Rationale documented | `INCIDENT_STATUS_CHANGED` |
| `CONTAINED` | `RESOLVED` | `SECURITY_OFFICER`, `SUPER_ADMIN` | Remediation documented | `INCIDENT_RESOLVED` |
| `RESOLVED` | `CLOSED` | `SUPER_ADMIN` | Supervisory review completed | `INCIDENT_CLOSED` |
| `RESOLVED` | `REOPENED` | `SECURITY_OFFICER`, `SUPER_ADMIN` | New evidence reference documented | `INCIDENT_REOPENED` |
| `CLOSED` | `REOPENED` | `SUPER_ADMIN` | Super Admin justification documented | `INCIDENT_REOPENED` |

---

## 8. Signal-to-Incident Relationship

### Triage Policy
Not every detection signal warrants a standalone incident. A high-assurance platform must protect analysts from alert fatigue:

1. **High / Critical Direct Triage**:
   - Signals from `RULE-E` (Break-Glass Misuse), `RULE-F` (Audit Anomaly), `RULE-H` (Audit Tampering), or `RULE-J` (Sealer Degradation) automatically create a `TRIAGE` incident or cluster into an existing open incident within a 1-hour window.
2. **Medium / Low Clustering**:
   - Isolated `LOW` or `MEDIUM` signals remain advisory signals in detection storage.
   - If $\ge 3$ advisory signals share the same correlation context within 30 minutes, an automated `TRIAGE` incident is opened.
3. **Manual Promotion**:
   - A Security Officer inspecting advisory signals can manually promote any signal to an incident.

---

## 9. Incident Deduplication

To prevent duplicate incidents for a single underlying event burst (e.g., 50 KMS failure events triggering 50 signals for one key):

### Deduplication Key Specification
$$\text{dedup\_key} = \text{SHA-256}(\text{rule\_id} \mathbin{\Vert} \text{dimension\_key} \mathbin{\Vert} \text{dimension\_value} \mathbin{\Vert} \text{time\_bucket})$$

- `time_bucket`: Monotonic integer representing a 3600-second (1-hour) window:
  $$\text{time\_bucket} = \lfloor \text{epoch\_seconds} / 3600 \rfloor$$
- **Behavior on Match**:
  - If an active incident (`TRIAGE` or `INVESTIGATING`) exists with the identical `dedup_key`, the new signal is attached as an additional `IncidentEvidence` link, and the incident's `updated_at` timestamp is refreshed.
  - No duplicate incident is created.
- **Negative Invariant**: Never infer `same IP == same incident` without corroborating actor or session evidence.

---

## 10. Evidence Reference Architecture

Incidents must reference authoritative evidence without duplicating sensitive payload content:

```
┌────────────────────────────────────────────────────────┐
│                   SecurityIncident                     │
│  incident_id: "inc_001"                                │
│  severity: "HIGH"                                      │
└───────────────────────────┬────────────────────────────┘
                            │ 1 : N
                            ▼
┌────────────────────────────────────────────────────────┐
│                IncidentEvidenceLink                    │
│  link_id: "link_999"                                   │
│  evidence_type: "AUDIT_LOG" | "DETECTION_SIGNAL" ...   │
│  evidence_id: "audit_log_uuid_123"                     │
│  evidence_hash: "sha256_hash_of_source_record"         │
│  status: "AVAILABLE" | "UNAVAILABLE" | "CONFLICTING"   │
└────────────────────────────────────────────────────────┘
```

### Supported Evidence Types
1. `AUDIT_LOG`: Authoritative UUID from `audit_logs.id`.
2. `DETECTION_SIGNAL`: Advisory signal ID from Phase 3C-5C.
3. `CLOUDTRAIL_EVENT`: RequestId from AWS CloudTrail KMS API management events.
4. `BREAK_GLASS_REQUEST`: Request ID from `break_glass_requests.id`.
5. `VERIFIER_RESULT`: Sealer/verifier result record.

### Evidence States
- `AVAILABLE`: Source record exists, is immutable, and hash matches.
- `UNAVAILABLE`: Source record is archived, deleted, or unreadable.
- `UNRESOLVED`: Evidence is within transport latency window.
- `CONFLICTING`: Source record hash does not match recorded evidence hash.

---

## 11. Evidence Access Control

Evidence access must be strictly separated from incident summary visibility:
- **Separation of Concerns**: A user authorized to view the incident list is not automatically authorized to decrypt or inspect raw audit event details.
- **Audit Requirement**: Every access to underlying evidence (`GET /api/v1/incidents/{id}/evidence/{evidence_id}`) must log an `INCIDENT_EVIDENCE_VIEWED` event to PostgreSQL audit persistence.

---

## 12. RBAC Model

Incident operations must follow strict least-privilege:

| Permission | Description | SUPER_ADMIN | SECURITY_OFFICER | AUDITOR | EXAM_AUTHORITY | Other Roles |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| `incident:read` | View incident list & safe summaries | **YES** | **YES** | **YES** | **YES** | NO |
| `incident:create` | Manually initiate an incident | **YES** | **YES** | NO | NO | NO |
| `incident:assign` | Assign/reassign analyst | **YES** | **YES** | NO | NO | NO |
| `incident:investigate`| Update triage notes, add comments | **YES** | **YES** | NO | NO | NO |
| `incident:view_evidence`| Inspect linked evidence records | **YES** | **YES** | **YES** | NO | NO |
| `incident:resolve` | Mark incident as resolved | **YES** | **YES** | NO | NO | NO |
| `incident:close` | Perform final administrative closure| **YES** | NO | NO | NO | NO |
| `incident:reopen` | Reopen resolved/closed incident | **YES** | **YES** | NO | NO | NO |

---

## 13. Analyst Assignment

- Incidents in `TRIAGE` may be assigned to any active user possessing the `SECURITY_OFFICER` or `SUPER_ADMIN` role.
- Self-assignment is permitted and transitions the incident from `TRIAGE` to `INVESTIGATING`.
- Re-assignment requires logging `INCIDENT_REASSIGNED` with previous and new assignee IDs.

---

## 14. Analyst Comments / Notes

Analysts require the ability to record qualitative notes during an investigation:
- **Append-Only Immutability**: Comments are strictly append-only. No `UPDATE` or `DELETE` API operations exist.
- **Sanitization Check**: Comment submission executes regex screening against `EXAM_CONTENT_FORBIDDEN_KEYS`. If an analyst attempts to paste plaintext questions, answers, or tokens into comments, the request is rejected with HTTP 422 Unprocessable Entity.
- **Audit Trail**: Every comment creation emits an `INCIDENT_COMMENT_ADDED` audit event.

---

## 15. Concurrency Strategy

To prevent race conditions where Analyst A and Analyst B submit conflicting status updates simultaneously:
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

## 16. Severity Model

Incident severity must be decoupled from detection signal severity:
- A `HIGH` detection signal may be triaged to `LOW` if surrounding audit context shows an authorized maintenance drill.
- A `MEDIUM` signal may be escalated to `CRITICAL` if correlated with a concurrent network anomaly.
- **Escalation / De-escalation Policy**:
  - Analysts may adjust severity between `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL`.
  - Adjusting severity requires an explicit rationale string ($\ge 20$ chars) and emits `INCIDENT_SEVERITY_CHANGED` to the audit log.

---

## 17. Incident Types

To prevent high-cardinality label explosion, incident categories are bounded to 10 finite types:
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

An incident case must present a deterministic, chronological event timeline reconstructed from:
1. Creation record
2. Linked evidence timestamps
3. Status transition history from `AuditLog`
4. Analyst comment timestamps
5. Resolution and closure timestamps

The timeline is dynamically reconstructed via query; it does not duplicate the audit log.

---

## 19. Audit Integration

All incident operations must integrate with the existing authoritative audit chain (`backend/app/modules/audit/service.py`):

| Incident Operation | Audit Event Type | Audit Mode | Payload Metadata |
| :--- | :--- | :---: | :--- |
| Create Incident | `INCIDENT_CREATED` | Mode A | `incident_id`, `incident_type`, `severity`, `exam_id` |
| Assign Incident | `INCIDENT_ASSIGNED` | Mode A | `incident_id`, `assignee_id` |
| Change Status | `INCIDENT_STATUS_CHANGED` | Mode A | `incident_id`, `old_status`, `new_status`, `rationale` |
| View Evidence | `INCIDENT_EVIDENCE_VIEWED` | Mode A | `incident_id`, `evidence_type`, `evidence_id` |
| Add Comment | `INCIDENT_COMMENT_ADDED` | Mode A | `incident_id`, `comment_id` |
| Resolve Incident | `INCIDENT_RESOLVED` | Mode A | `incident_id`, `resolution_category` |
| Close Incident | `INCIDENT_CLOSED` | Mode A | `incident_id`, `closed_by` |
| Reopen Incident | `INCIDENT_REOPENED` | Mode A | `incident_id`, `reason` |

---

## 20. Database Schema Proposal

In the future implementation phase, a dedicated Alembic migration will introduce the normalized incident tables:

```sql
-- 1. Security Incidents Table
CREATE TABLE security_incidents (
    id VARCHAR(36) PRIMARY KEY,
    incident_number VARCHAR(32) NOT NULL UNIQUE,
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
    version INTEGER NOT NULL DEFAULT 1,
    resolution_category VARCHAR(50),
    resolution_notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMPTZ,
    closed_at TIMESTAMPTZ
);

-- 2. Incident Evidence Links Table
CREATE TABLE incident_evidence_links (
    id VARCHAR(36) PRIMARY KEY,
    incident_id VARCHAR(36) NOT NULL REFERENCES security_incidents(id) ON DELETE RESTRICT,
    evidence_type VARCHAR(50) NOT NULL,
    evidence_id VARCHAR(64) NOT NULL,
    evidence_timestamp TIMESTAMPTZ NOT NULL,
    source_subsystem VARCHAR(50) NOT NULL,
    evidence_hash VARCHAR(64),
    status VARCHAR(30) NOT NULL DEFAULT 'AVAILABLE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(36) NOT NULL REFERENCES users(id)
);

-- 3. Incident Analyst Comments Table
CREATE TABLE incident_comments (
    id VARCHAR(36) PRIMARY KEY,
    incident_id VARCHAR(36) NOT NULL REFERENCES security_incidents(id) ON DELETE RESTRICT,
    author_id VARCHAR(36) NOT NULL REFERENCES users(id),
    comment_body TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

---

## 21. Constraints and Indexes

### Check Constraints
- `chk_incident_severity`: `severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')`
- `chk_incident_status`: `status IN ('TRIAGE', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE', 'DUPLICATE', 'CLOSED', 'REOPENED')`
- `chk_evidence_status`: `status IN ('AVAILABLE', 'UNAVAILABLE', 'UNRESOLVED', 'CONFLICTING')`

### Indexes
- `idx_sec_incidents_status_severity`: `(status, severity)`
- `idx_sec_incidents_assigned`: `(assigned_to)`
- `idx_sec_incidents_dedup`: `(dedup_key)`
- `idx_sec_incidents_created`: `(created_at DESC)`
- `idx_inc_evidence_incident`: `(incident_id)`
- `idx_inc_comments_incident`: `(incident_id, created_at ASC)`

---

## 22. Retention and Deletion Policy

- **No Hard Deletes**: Physical deletion (`DELETE FROM security_incidents`) is strictly prohibited by database foreign key constraints (`ON DELETE RESTRICT`) and application RBAC.
- **No Soft Delete Column**: The entity does not implement `is_deleted`. Decommissioning an incident occurs exclusively through the `CLOSED` terminal status.
- **Legal Hold**: Incidents associated with criminal inquiries or testing integrity challenges remain frozen in `CLOSED` status with all evidence links intact.

---

## 23. API Architecture

Proposed REST API surface (prefix `/api/v1/incidents`):

1. `POST /api/v1/incidents/` (Create manual incident case)
   - *Auth*: `SECURITY_OFFICER`, `SUPER_ADMIN`
2. `GET /api/v1/incidents/` (List incidents with pagination, status, and severity filters)
   - *Auth*: `SECURITY_OFFICER`, `SUPER_ADMIN`, `AUDITOR`, `EXAM_AUTHORITY`
3. `GET /api/v1/incidents/{id}` (Get incident details and safe summary)
   - *Auth*: `SECURITY_OFFICER`, `SUPER_ADMIN`, `AUDITOR`, `EXAM_AUTHORITY`
4. `POST /api/v1/incidents/{id}/assign` (Assign or reassign analyst)
   - *Auth*: `SECURITY_OFFICER`, `SUPER_ADMIN`
5. `POST /api/v1/incidents/{id}/status` (Execute state transition with OCC version)
   - *Auth*: `SECURITY_OFFICER`, `SUPER_ADMIN`
6. `GET /api/v1/incidents/{id}/evidence` (List linked evidence records)
   - *Auth*: `SECURITY_OFFICER`, `SUPER_ADMIN`, `AUDITOR`
7. `POST /api/v1/incidents/{id}/comments` (Append analyst note)
   - *Auth*: `SECURITY_OFFICER`, `SUPER_ADMIN`
8. `POST /api/v1/incidents/{id}/resolve` (Document findings and resolve)
   - *Auth*: `SECURITY_OFFICER`, `SUPER_ADMIN`
9. `POST /api/v1/incidents/{id}/close` (Administrative supervisory closure)
   - *Auth*: `SUPER_ADMIN`

---

## 24. Frontend / Analyst UI Architecture

Conceptual layout for the Security Operations Console:
- **Triage Queue**: Sortable by severity and SLA urgency.
- **Investigation Workspace**:
  - Safe Incident Summary
  - Case Metadata & Assignment Selector
  - Chronological Timeline
  - Evidence Reference Explorer (UUIDs with one-click audit verification)
  - Append-Only Analyst Log
  - State Transition Controls with OCC conflict banner

---

## 25. Failure Semantics

- **Database Failure**: If PostgreSQL is unavailable, incident creation fails. Detection signals remain buffered in SQS Standard Queue; core candidate examination traffic continues unaffected.
- **Audit Service Failure**: If audit sealing or ingestion fails, incident status transitions are rejected. Incident state cannot mutate without an accompanying sealed audit record.
- **Analyst Session Expiry**: Session invalidation aborts status updates; candidate traffic continues unaffected.

---

## 26. 5D vs 5E Boundary

| Dimension | Phase 3C-5D (Incident Management) | Phase 3C-5E (Policy-Governed Containment) |
| :--- | :--- | :--- |
| **Primary Goal** | Human investigation, triage, and case tracking | Policy-governed active threat containment |
| **System Interaction** | Read-only analysis & advisory case management | Active intervention on sessions, keys, and exams |
| **Autonomous Action** | **ZERO autonomous containment** | Policy-evaluated containment with dual custody |
| **Session Impact** | Candidates are NEVER terminated or blocked | Authoritative session revocation with dual authorization |
| **Quarantine Impact** | No quarantine actions | Dual-custody audit/content quarantine |
| **Status Semantics** | `CONTAINED` is a historical record of external action | Contains active state execution mechanisms |

---

## 27. 5D vs 5F Boundary

- **Phase 3C-5D**: Self-contained internal incident management within the B-SEA boundary.
- **Phase 3C-5F**: Enterprise SIEM integration (AWS Security Lake, OpenSearch, Splunk, PagerDuty, webhook delivery). 5D does not implement outbound SOC connectors.

---

## 28. Legacy SecurityService Coexistence

### Current State
`backend/app/modules/security/service.py` contains a legacy `SecurityService` class with a prototype risk scoring method. The database currently contains a prototype `incidents` table and legacy containment endpoint in `backend/app/api/v1/incidents.py`.

### Coexistence & Evolution Plan
1. **Phase 3C-5D Implementation**:
   - The legacy `SecurityService` in `backend/app/modules/security/service.py` remains frozen and untouched.
   - The modern incident management subsystem will be implemented cleanly in `backend/app/modules/incident/`.
   - The legacy endpoint `POST /api/v1/incidents/{incident_id}/action` (which allows unilateral user locking and session revoking) will be formally deprecated and bypassed by the modern API surface.
2. **Phase 3C-5E Transition**:
   - Unilateral containment actions from the legacy endpoint will be fully removed in 5E in favor of policy-governed dual-custody containment.

---

## 29. Security Invariants for 5D

1. Incident management must never degrade or weaken candidate examination security.
2. Incident management must never modify immutable audit history (`AuditLog`, `AuditChainLink`, `AuditEpochSeal`).
3. Incident management must never mutate KMS key state or bypass KMS policies.
4. Plaintext examination content (questions, answers, candidate responses) must never be stored in incidents, evidence links, or analyst comments.
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

Planned verification suite for Phase 3C-5D implementation:
- **T01**: Incident creation authorization (Security Officer & Super Admin).
- **T02**: Unauthorized role rejection (Candidate, Invigilator, Reviewer rejected with HTTP 403).
- **T03**: Signal-to-incident reference integrity and metadata preservation.
- **T04**: Signal deduplication into active triage incident via `dedup_key`.
- **T05**: Valid status transition lifecycle flow (`TRIAGE` $	o$ `INVESTIGATING` $	o$ `RESOLVED` $	o$ `CLOSED`).
- **T06**: Invalid status transition rejection (e.g., direct `TRIAGE` $	o$ `CLOSED` rejected).
- **T07**: Optimistic concurrency control (concurrent updates return HTTP 409).
- **T08**: Analyst assignment authorization and reassignment tracking.
- **T09**: Evidence linking and access authorization.
- **T10**: Sensitive exam content stripping from incident summary and comments.
- **T11**: Audit event generation across all status transitions.
- **T12**: Severity modification authorization and audit trail.
- **T13**: Resolution documentation enforcement ($\ge 20$ chars required).
- **T14**: Incident reopening semantics and privilege check.
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
   - *Mitigation*: Automated triage batching restricted to `HIGH`/`CRITICAL` rules and clustering thresholds.
2. **Analyst Collision**: Multiple analysts attempting simultaneous case triage.
   - *Mitigation*: Enforced optimistic concurrency control via integer `version` field.
3. **Data Leakage in Analyst Notes**: Analysts copying question text into investigation notes.
   - *Mitigation*: Content sanitization engine screens analyst comments prior to persistence.
4. **Scope Creep**: Attempting to implement active containment in 5D.
   - *Mitigation*: Strict architectural boundary: 5D is read-only case management; 5E handles containment.

---

## 33. Required Decisions

All fundamental architectural decisions have been resolved in Rev-01:
- **Decision A (Schema Strategy)**: Implement dedicated normalized tables (`security_incidents`, `incident_evidence_links`, `incident_comments`).
- **Decision B (Containment Scope)**: Zero containment in 5D. `CONTAINED` status is observational only.
- **Decision C (Concurrency)**: Optimistic locking with integer `version` column.
- **Decision D (Deduplication)**: SHA-256 hash across rule, dimension, and 1-hour time bucket.
- **Decision E (Sanitization)**: Enforce regex scrubbing on comments and incident text.

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
1. User must formally review and approve Architecture Review Rev-01.
2. Baseline regression must continue reporting 240 passed, 5 skipped, 0 failed.
3. Git status must remain strictly verified on commit `7683dd6`.
4. User must provide explicit implementation authorization.

---

## 36. Final Architecture Verdict

**ARCHITECTURE APPROVED FOR IMPLEMENTATION PENDING USER REVIEW**

*(Implementation is NOT authorized. Awaiting explicit user review and authorization).*
