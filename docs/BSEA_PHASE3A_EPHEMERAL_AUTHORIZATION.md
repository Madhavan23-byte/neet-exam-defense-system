# B-SEA Phase 3A: Dynamic & Ephemeral Question Access Control

## 1. Executive Summary

Phase 3A implements **Dynamic & Ephemeral Question Access Control** for the Bharat Secure Examination Architecture (B-SEA). While Phase 2 established **Compartmentalized Review / Question Sharding** (restricting normal reviewers strictly to assigned questions), Phase 3A ensures that possessing an active assignment is **necessary but never sufficient** for question operations.

All high-assurance question operations require an explicit, time-bounded, session-bound **Ephemeral Access Grant** (`QuestionAccessGrant`). Access grants enforce the principle of least privilege, strict compartmentalization, deterministic expiration, and transactional cascade invalidation upon reassignment or review completion.

---

## 2. Core Invariants Preserved

1. **Strict Assignment Boundary:** No actor can request or obtain a grant without an underlying active `QuestionAssignment`.
2. **Grant ID is Never Sufficient:** Submitting a valid `grant_id` alone never grants access. Every protected operation re-validates the full 4-factor security context:
   $$\text{Actor} \cap \text{Session (JWT JTI)} \cap \text{Question/Exam} \cap \text{Active Assignment} \cap \text{Operation & Purpose}$$
3. **No IP Binding:** In compliance with B-SEA network specifications, grants are bound to authenticated session identity (JWT JTI) rather than ephemeral network IPs (preventing roaming disconnects and NAT spoofing).
4. **No `CONSUMED` Grant State:** The grant lifecycle is strictly:
   $$\text{GRANTED} \longrightarrow \text{ACTIVE} \longrightarrow \text{EXPIRED} \text{ / } \text{REVOKED}$$
   A grant remains usable for its declared operation within its validity window until explicitly revoked, timed out, or invalidated by assignment state transitions.
5. **No Arbitrary Thresholds:** Expiration TTLs and risk bounds are deterministic and explicit.
6. **Hard Authorization Priority:** Risk evaluation functions purely as an anomaly detector and restrictive hook; risk scores can *never* override hard authorization failures.
7. **Answer Key Complete Isolation:** Answer keys remain stored in dedicated isolated tables (`answer_keys`) with cryptographic separation and are never returned across review or grant APIs.

---

## 3. Database Architecture & Schema

### 3.1 New Enumerations

- **`QuestionOperation`**:
  - `VIEW`: Retrieve question text, options, diagrams, equations.
  - `REVIEW`: Initiate review session (`ACTIVE` $\rightarrow$ `IN_REVIEW`), update draft remarks.
  - `APPROVE`: Moderator approval triggering Ed25519 signing and AES-256-GCM encryption.
  - `REJECT`: Return question to setter with mandatory defect justification.

- **`AccessGrantStatus`**:
  - `GRANTED`: Issued after multi-factor context validation; pending first operational use.
  - `ACTIVE`: Activated upon first authorized operation.
  - `EXPIRED`: Validity TTL elapsed, evaluated lazily on authorization attempt or during audit sweeps.
  - `REVOKED`: Invalidated explicitly, via assignment reassignment, or upon assignment completion.

### 3.2 `QuestionAccessGrant` Table Definition

| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `VARCHAR(36)` | PK, UUID | Unique grant identifier |
| `question_id` | `VARCHAR(36)` | FK $\rightarrow$ `questions.id` (CASCADE), Indexed | Target question |
| `exam_id` | `VARCHAR(36)` | FK $\rightarrow$ `exams.id` (CASCADE), Indexed | Parent examination |
| `reviewer_id` | `VARCHAR(36)` | FK $\rightarrow$ `users.id` (CASCADE), Indexed | Grantee user |
| `assignment_id` | `VARCHAR(36)` | FK $\rightarrow$ `question_assignments.id` (CASCADE), Indexed | Source assignment |
| `purpose` | `ENUM(ReviewPurpose)` | NOT NULL | Evaluation purpose |
| `operation` | `ENUM(QuestionOperation)` | NOT NULL | Permitted operation |
| `status` | `ENUM(AccessGrantStatus)` | NOT NULL, Default `GRANTED` | Grant state |
| `issued_at` | `TIMESTAMP WITH TIME ZONE` | NOT NULL | Issuance timestamp |
| `activated_at` | `TIMESTAMP WITH TIME ZONE` | Nullable | Timestamp of first operation |
| `expires_at` | `TIMESTAMP WITH TIME ZONE` | Nullable | Deterministic expiration boundary |
| `revoked_at` | `TIMESTAMP WITH TIME ZONE` | Nullable | Revocation timestamp |
| `revocation_reason` | `VARCHAR(255)` | Nullable | Audit reason for revocation |
| `session_id` | `VARCHAR(64)` | Nullable | Bound JWT `jti` |
| `created_by` | `VARCHAR(36)` | FK $\rightarrow$ `users.id` | Requesting actor |
| `correlation_id` | `VARCHAR(64)` | Indexed | Request correlation tracking |

### 3.3 Partial Unique Index & Race Protection

```sql
CREATE UNIQUE INDEX uix_active_grant_assignment_operation
ON question_access_grants (assignment_id, operation)
WHERE status IN ('GRANTED', 'ACTIVE');
```

This ensures at most one active grant exists per assignment and operation, eliminating concurrent duplicate grant creation while permitting historical revoked/expired grants.

---

## 4. Centralized Entitlement Policy Matrix

The engine enforces $\text{Role} \cap \text{Purpose} \cap \text{Permission}$ intersection rules:

| Role | Review Purpose | Allowed Operations |
| :--- | :--- | :--- |
| `REVIEWER` | `TECHNICAL_REVIEW` | `VIEW`, `REVIEW` |
| `REVIEWER` | `SYLLABUS_REVIEW` | `VIEW`, `REVIEW` |
| `REVIEWER` | `LANGUAGE_REVIEW` | `VIEW`, `REVIEW` |
| `REVIEWER` | `DISTRACTOR_REVIEW` | `VIEW`, `REVIEW` |
| `REVIEWER` | `KEY_VERIFICATION` | `VIEW`, `REVIEW` |
| `MODERATOR` | *(Any valid purpose)* | `VIEW`, `REVIEW`, `APPROVE`, `REJECT` |
| `QUESTION_SETTER` | *(None)* | Denied (Conflict of interest / Separation of Duties) |

---

## 5. Two-Phase Authorization Engine

### Phase A: `request_question_access()`
1. Authenticates actor and resolves question, exam, and assignment.
2. Checks author conflict-of-interest (setters cannot review own questions).
3. Verifies assignment status is `ACTIVE` or `IN_REVIEW`.
4. Enforces purpose consistency (requested purpose must match assigned purpose).
5. Validates entitlement against the central policy matrix.
6. Invokes deterministic risk hook (`evaluate_access_risk`).
7. Checks for existing active grant; if expired, lazily updates status to `EXPIRED`.
8. Atomically creates `QuestionAccessGrant` in `GRANTED` status with session ID binding.

### Phase B: `authorize_question_operation()`
1. Requires `grant_id`.
2. Verifies grant existence and fetches associated assignment and question.
3. Enforces grant status is `GRANTED` or `ACTIVE`.
4. Evaluates lazy expiration: if `now >= grant.expires_at`, transitions grant to `EXPIRED`, logs `ACCESS_EXPIRED`, and rejects.
5. Validates actor binding (`grant.reviewer_id == actor.id`).
6. Validates session binding (`grant.session_id == session_id`).
7. Validates resource binding (`grant.question_id == question_id` and `grant.exam_id == question.exam_id`).
8. Validates operation binding (`grant.operation == requested_operation`).
9. Verifies underlying assignment is not `REVOKED` or `COMPLETED`.
10. Validates exam status is active.
11. Transitions status from `GRANTED` $\rightarrow$ `ACTIVE` on first authorized use.
12. Logs structured audit record `OPERATION_AUTHORIZED`.

---

## 6. Atomic Reassignment & Cascading Revocation

When an administrative user reassigns a question via `POST /assignments/{assignment_id}/reassign`:
1. Row lock (`with_for_update`) is acquired on the existing assignment.
2. Existing assignment is transitioned to `REVOKED`.
3. All `GRANTED` and `ACTIVE` grants for that assignment are atomically transitioned to `REVOKED` with reason `"Cascading revocation: question reassigned"`.
4. Replacement assignment is created for the new reviewer.
5. All actions commit in a single PostgreSQL transaction.

---

## 7. Audit Ledger Integration

Phase 3A integrates with the B-SEA audit service (`audit_events`):
- `ACCESS_REQUESTED`: Grant requested by reviewer.
- `ACCESS_GRANTED`: Grant issued.
- `ACCESS_ACTIVATED`: First operation authorized using grant.
- `OPERATION_AUTHORIZED`: Protected operation allowed.
- `ACCESS_REVOKED`: Explicit revocation or cascading reassignment revocation.
- `ACCESS_EXPIRED`: Lazy expiration detection.
- `ACCESS_DENIED`: Authorization failure with detailed security reason.
