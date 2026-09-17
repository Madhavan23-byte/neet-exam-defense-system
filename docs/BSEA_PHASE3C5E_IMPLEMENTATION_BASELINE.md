# B-SEA Phase 3C-5E: Implementation Step 0 — Repository & Baseline Verification Report

**Document Reference**: `BSEA-BASE-3C5E-STEP0`  
**Status**: VERIFIED IMPLEMENTATION BASELINE (READ-ONLY INSPECTION)  
**Date**: 2026-09-16  
**Target Subsystem**: `backend/app/modules/containment/`  
**Authoritative Architecture Baseline**: `docs/BSEA_PHASE3C5E_ARCHITECTURE_REV04_1.md`  
**Baseline Git Commit**: `7683dd6f8d67f5289cc8cc86da3112a8aaade6ec`  
**Database Migration Head**: `a1b2c3d4e5f6` (Phase 3C-5D Security Incident Foundation)  
**Verification Verdict**: IMPLEMENTATION STEP 0 — READY FOR STEP 1  

---

## 1. Executive Summary & Verification Objective

This document establishes the verified, read-only baseline for **Phase 3C-5E: Policy-Governed Security Containment Subsystem**. 

All repository components, database models, cryptographic interfaces, audit pipelines, and boundary contracts have been systematically inspected to ensure that:
1. The repository is in a known, stable, and deterministic state.
2. The frozen Phase 3C-5D Incident Management Foundation is intact and passing all regression tests.
3. The cryptographic abstractions and audit chaining mechanisms can be seamlessly reused without creating duplicate chains or breaking existing immutability guarantees.
4. The exact scope and technical boundaries of Phase 3C-5E are catalogued prior to writing any implementation code.

---

## 2. Git State Verification

A thorough inspection of Git status and tracking branches was conducted:

| Git Attribute | Current Value | Verification Assessment |
| :--- | :--- | :--- |
| **Current Branch** | `main` | Correct authoritative development branch. |
| **HEAD Commit** | `7683dd6f8d67f5289cc8cc86da3112a8aaade6ec` | Commit message: `feat: implement Phase 3C-5C detection correlation foundation`. |
| **Upstream Tracking** | `origin/main` | In sync (`Your branch is up to date with 'origin/main'`). |
| **Staged Files** | *None* | Zero staged changes. |
| **Unstaged Tracked Changes** | 2 files | See detailed analysis below. |
| **Untracked Files** | 22 files/directories | Expected Phase 3C-5D implementation artifacts and architecture documents. |

### Analysis of Unstaged Tracked Changes:
1. `backend/app/core/models.py`:
   - Contains the append-only definitions of Phase 3C-5D models (`SecurityIncident`, `IncidentEvidenceLink`, `IncidentComment`) and supporting enums.
   - All legacy models (`Incident`, `SecurityEvent`, `AuditLog`, `User`, etc.) remain completely unmodified.
2. `backend/tests/security/test_phase3c4a_database_immutability.py`:
   - Updated downgrade target in `test_13` and `test_14` to explicitly pin revision `99c8ce339dd4` (the quarantine foundation). This ensures deterministic downgrade testing without colliding with downstream migrations.

### Untracked Files Status:
- `backend/alembic/versions/a1b2c3d4e5f6_phase3c5d_security_incident_foundation.py`: Migration implementing Phase 3C-5D foundation tables and append-only triggers.
- `backend/app/modules/incidents/`: The complete Phase 3C-5D incident service implementation (`identity.py`, `models.py`, `service.py`, `exceptions.py`).
- `backend/tests/security/test_phase3c5d_database_foundation.py`: 13 database foundation tests (all passing).
- `backend/tests/security/test_phase3c5d_service_correlation.py`: 18 service lifecycle and correlation tests (all passing).
- `docs/BSEA_PHASE3C5E_ARCHITECTURE_REV04_1.md`: The approved architecture baseline.

---

## 3. Phase 3C-5D Baseline Verification

### A. Database Migration Head
- **Alembic Script Directory Head**: `a1b2c3d4e5f6`
- **PostgreSQL Database Current Revision**: `a1b2c3d4e5f6`
- The database schema is fully aligned with the migration scripts.

### B. Verified 5D Model Schemas (`backend/app/core/models.py`)
1. **`SecurityIncident`**:
   - Primary key: `id` (`UUID` / `String(36)`).
   - Identity: `threat_vector_key` (`String(64)`), `generation` (`Integer`).
   - Lifecycle: `status` (`SecurityIncidentStatus` enum: `TRIAGE`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `CLOSED`, `FALSE_POSITIVE`, `DUPLICATE`).
   - Correlation: `correlation_status` (`OPEN` / `CLOSED`), `latest_signal_at`.
   - Concurrency: `version` (`Integer` for OCC CAS updates).
   - Observational Containment Fields:
     - `containment_reference_id` (`String(128)`)
     - `authorization_principal` (`String(128)`)
     - `containment_timestamp` (`DateTime(timezone=True)`)
     - `containment_mechanism` (`String(64)`)
     - `audit_event_reference` (`String(128)`)
     - `seal_verification_status` (`SealVerificationStatus`: defaults to `UNCONTAINED`, advances to `PENDING_SEAL`)
2. **`IncidentEvidenceLink`**:
   - Append-only association between incidents and authoritative audit events.
   - Enforced by PostgreSQL trigger `trg_no_update_incident_evidence_links` and `trg_no_delete_incident_evidence_links`.
3. **`IncidentComment`**:
   - Append-only investigative notes.
   - Enforced by PostgreSQL trigger `trg_no_update_incident_comments` and `trg_no_delete_incident_comments`.

### C. Verified `SecurityIncidentService` Capabilities
Located in `backend/app/modules/incidents/service.py`:
1. **Threat Vector Identity**: Implements RFC 8785 JSON Canonicalization Scheme (JCS) hashing over canonical rule ID, normalized dimensions, exam ID, and policy version (`identity.py`).
2. **PostgreSQL Advisory Lock Protocol**: Uses `pg_advisory_xact_lock` on the 64-bit integer hash of `threat_vector_key` to serialize concurrent signal processing and race-free generation rollover.
3. **3600-Second Correlation Window**: Rolling inactivity correlation window with strictly monotonic next-generation allocation ($N ightarrow N+1$).
4. **Human Lifecycle State Machine**: Enforces strict transitions across the 7 approved states. Reopening an incident preserves `correlation_status = 'CLOSED'`.
5. **Optimistic Concurrency Control (OCC)**:
   ```sql
   UPDATE security_incidents
   SET status = :target_status,
       version = :expected_version + 1,
       ...
   WHERE id = :incident_id AND version = :expected_version;
   ```
   Throws `OptimisticLockError` if `rowcount == 0`.
6. **Observational Containment Hook**:
   The service's `transition_status` method natively supports receiving `containment_data`:
   ```python
   if target_status == SecurityIncidentStatus.CONTAINED and containment_data:
       c_ref_id = containment_data.get("containment_reference_id")
       c_mech = containment_data.get("containment_mechanism")
       c_prin = containment_data.get("authorization_principal") or actor_id
       c_time = containment_data.get("containment_timestamp") or datetime.now(timezone.utc)
       c_audit = containment_data.get("audit_event_reference")
       seal_status = SealVerificationStatus.PENDING_SEAL
   ```
7. **Baseline Automated Tests**:
   - `tests/security/test_phase3c5d_database_foundation.py`: 13 tests PASSED.
   - `tests/security/test_phase3c5d_service_correlation.py`: 18 tests PASSED.
   - **Total 5D Baseline: 31 passed in 24.37s, 0 failed.**

---

## 4. Existing Audit Architecture Verification

The audit subsystem (`backend/app/modules/audit/`) was inspected to ensure that Phase 3C-5E containment actions integrate into the single, unbroken audit chain without creating a secondary or fragmented log.

### A. Core Audit Components
1. **`AuditService` (`backend/app/modules/audit/service.py`)**:
   - `log(...)`: Mode A transaction-coupled audit logging. Receives `session: Optional[AsyncSession]` to commit within the caller's transaction.
   - `log_security_event(...)`: Mode B isolated security audit logging. Opens its own independent database session and commits immediately, ensuring audit trail survival even if the caller's transaction rolls back.
   - `risk_score`: Fully supported in `AuditLog` model as a native `Float` column ($0.0 \le s \le 1.0$).
2. **Canonical Hashing & JCS (`backend/app/modules/audit/canonical.py`)**:
   - `build_canonical_event_payload()`: Structures audit payloads with strictly ordered fields.
   - `serialize_canonical_event()`: RFC 8785 JCS deterministic serialization.
   - `compute_event_hash()`: SHA-256 hash calculation.
   - `compute_canonical_chain_hash()`: Computes $H_i = 	ext{SHA-256}(H_{i-1} \parallel E_i)$.
3. **Audit Epoch Sealer (`backend/app/modules/audit/sealer.py`)**:
   - `AuditSealer`: Performs periodic sealing of audit blocks into immutable epochs.
   - Builds Merkle tree roots from `audit_chain_links`.
   - Digitally signs epoch manifests using KMS Ed25519 signing keys.
   - Writes sealed manifests to `audit_epoch_seals`.
4. **Poison Quarantine (`backend/app/modules/audit/quarantine.py`)**:
   - Manages `audit_poison_quarantine` table to isolate tampered or corrupt audit events without halting system-wide auditing.

### B. 5E Integration Rule (Single Chain Invariant)
$$\mathbf{ZERO\ SECONDARY\ AUDIT\ CHAINS}$$
Phase 3C-5E must strictly route all audit events through `AuditService`:
- **Pre-dispatch intent and policy evaluations**: Recorded via `AuditService.log(..., session=session)` (Mode A) or `AuditService.log_security_event(...)` (Mode B).
- **Emergency overrides**: Recorded via `AuditService.log_security_event(event_type='CONTAINMENT_EMERGENCY_OVERRIDE', risk_score=1.0)`.
- All containment audit events immediately enter `audit_logs` and `audit_chain_links`, ensuring they are sealed into standard epoch seals by `AuditSealer`.

---

## 5. Existing Cryptographic Abstractions Verification

Inspection of `backend/app/crypto/kms_interface.py`:

| Component | Implementation | Capabilities | 5E Reusability |
| :--- | :--- | :--- | :--- |
| **`KMSInterface`** | Abstract Base Class | `encrypt`, `decrypt`, `sign`, `verify`, `derive_session_key`, `rotate_key` | Core contract for all crypto. |
| **`MockKMS`** | Python `cryptography` | HKDF SHA-256 key derivation, AES-256-GCM authenticated encryption, Ed25519 digital signatures | Fully reusable for 5E testing & prototype. |
| **`EncryptedBlob`** | Value Object | `iv`, `ciphertext`, `tag`, `context`, `key_version` | Standard container for encrypted payloads. |
| **`SignedPayload`** | Value Object | `payload`, `signature`, `key_id`, `algorithm`, `timestamp` | Standard container for signed authorizations. |
| **`AWSKMSProvider`** | AWS Boto3 KMS | Hardware Security Module (HSM) backing in AWS cloud | Production target provider. |

### Cryptographic Configuration (`backend/app/core/config.py`):
- `KMS_MASTER_KEY`: Master encryption secret.
- `KMS_SIGNING_KEY`: Master audit signing key.
- Prototype uses `MockKMS` automatically when running in non-production environments.

---

## 6. Existing Infrastructure Verification

| Infrastructure Layer | Prototype / Local Status | Production Architecture Target |
| :--- | :--- | :--- |
| **PostgreSQL Database** | PostgreSQL 16 on `localhost:5432/bsea`. Single instance. | AWS RDS PostgreSQL 16 Multi-AZ with PgBouncer connection pooler. |
| **Redis Cache & KV** | Redis 7 Alpine on `localhost:6379/0`. Append-only enabled. | AWS ElastiCache Redis Cluster (Multi-AZ with auto-failover). |
| **Object Storage** | MinIO on `localhost:9000`. Buckets: `bsea-questions`, `bsea-configs`, `bsea-audit`. | AWS S3 with Object Lock (WORM immutability) and KMS encryption. |
| **Asynchronous Queues** | In-process asyncio tasks & test harnesses. | Amazon SQS (Dead Letter Queues, FIFO for containment actions). |
| **Background Workers** | In-process daemon routines. | Dedicated ECS Fargate background worker tasks. |
| **Hardware Tokens / FIDO2** | In-memory cryptographic signature verification using Ed25519. | Hardware WebAuthn Relying Party server (YubiKey / Titan FIDO2). |

---

## 7. Security Boundaries & Module Capability Mapping

Inspection of repository modules and identification of actual capabilities vs. prototype abstractions:

| Subsystem / Boundary | Existing Module Location | Current Implementation Status | 5E Interaction |
| :--- | :--- | :--- | :--- |
| **Authentication** | `app/modules/auth/service.py` | Full JWT authentication, Argon2id/bcrypt passwords, TOTP MFA. | Provides verified caller identity (`requester_id`, `approver_id`). |
| **Role-Based Access Control**| `app/core/models.py` (`UserRoleEnum`) | 6 roles: `CANDIDATE`, `INVIGILATOR`, `EXAM_AUTHORITY`, `SECURITY_OFFICER`, `SUPER_ADMIN`, `SYSTEM_AUDITOR`. | Governs policy evaluation and Dual-Control authorization rules. |
| **FIDO2 / WebAuthn** | *Not present as a native library* | Prototype uses cryptographic Ed25519 signature challenge abstraction. | Prototype must implement a clean `FIDO2AssertionVerifier` interface. |
| **Session Management** | `app/core/models.py` (`CandidateSession`) | Tracks exam session tokens, IP hashes, device IDs. | Target for `ACT_CAND_SESSION_TERM`. |
| **Question Management** | `app/modules/questions/service.py` | Question authoring, review, blueprinting, and risk scoring. | Target for `ACT_Q_PREVENT_ASSIGN`. |
| **Centre Management** | `app/core/models.py` (`Centre`) | Tracks exam centres, capacity, status. | Target for `ACT_CENTRE_RESTRICT` / `ACT_CENTRE_SUSPEND`. |
| **Form Management** | `app/core/models.py` (`ExamForm`) | Form variants and paper delivery allocations. | Target for `ACT_FORM_SUSPEND`. |
| **Cryptographic Keys** | `app/crypto/kms_interface.py` | Key derivation, AES-GCM, Ed25519 signatures. | Target for `ACT_CRYPTO_REVOKE_MASTER`. |
| **Incident Management (5D)** | `app/modules/incidents/service.py` | Threat vector correlation, 7-state lifecycle, append-only evidence/comments. | Frozen upstream boundary; accepts `status=CONTAINED`. |
| **Containment (5E)** | *To be implemented in Step 1* | Does not exist yet. | New isolated module: `backend/app/modules/containment/`. |

---

## 8. Frozen Phase 3C-5D Boundary Contract

Phase 3C-5E must respect the frozen 5D boundary with absolute strictness:

### What 5E MAY Do:
1. **Read 5D Incident State**: Inspect `SecurityIncident` records (`id`, `threat_vector_key`, `generation`, `status`, `severity`, `correlation_status`, `version`, etc.).
2. **Evaluate Containment Policies**: Pass incident attributes into the 5E Policy Engine to determine permitted containment actions.
3. **Persist Containment Intent & Requests**: Record containment intents, requests, authorizations, execution outcomes, and verification proofs in dedicated 5E database tables.
4. **Execute Authorized Mitigations**: Dispatch network mutations to subsystem adapters (Redis, IdP, Delivery, Question Pool).
5. **Independently Verify Ground Truth**: Inspect target subsystems out-of-band to confirm physical containment.
6. **Request Observational Status Transition**: Upon successful independent verification, call:
   ```python
   await security_incident_service.transition_status(
       incident_id=incident_id,
       new_status=SecurityIncidentStatus.CONTAINED,
       expected_version=expected_version,
       actor_id=approver_id,
       actor_role=actor_role,
       containment_data={
           "containment_reference_id": request_id,
           "containment_mechanism": "AUTOMATED_POLICY" | "EMERGENCY_BREAK_GLASS",
           "authorization_principal": approver_id,
           "containment_timestamp": verified_at,
           "audit_event_reference": audit_event_id,
       },
   )
   ```

### What 5E MAY NOT Do:
1. **Directly Mutate 5D Records**: 5E is strictly forbidden from executing raw SQL `UPDATE` statements against `security_incidents`.
2. **Bypass 5D State Machine**: 5E cannot transition an incident that is not in `INVESTIGATING` status.
3. **Bypass OCC CAS Query**: 5E cannot update an incident without passing the expected `version`. If concurrent rollover occurred, 5E must abort.
4. **Reopen Correlation Windows**: 5E cannot modify `correlation_status` or manipulate `latest_signal_at`.
5. **Alter Generation Lineage**: 5E cannot create or modify incident generations.
6. **Alter Evidence or Comments**: 5E cannot modify or delete rows in `incident_evidence_links` or `incident_comments`.

---

## 9. Implementation Gaps & Component Categorization

```
+─────────────────────────────────────────────────────────────────────────────+
|                         COMPONENT STATUS & 5E GAPS                          |
+─────────────────────────────────────────────────────────────────────────────+
| A. Verified Existing Capabilities:                                          |
|    - 5D Incident Model, Lifecycle State Machine, OCC CAS, Inactivity Rollover|
|    - AuditService Mode A (coupled) and Mode B (isolated) security event logging|
|    - RFC 8785 JCS canonical hashing and Merkle tree epoch sealing            |
|    - MockKMS AES-256-GCM encryption and Ed25519 digital signatures           |
|    - PostgreSQL advisory lock infrastructure (`pg_advisory_xact_lock`)      |
+-----------------------------------------------------------------------------+
| B. Missing Capabilities (To Be Built in Phase 3C-5E):                       |
|    - 5E Containment Database Models & Migration (Requests, Approvals, Leases)|
|    - Dual-Pipeline Policy Engine (Standard vs. Break-Glass Crisis Pipeline)  |
|    - Two-Person Control Quorum Authorization Service                         |
|    - Single-Use BreakGlassToken Coordinator with FIDO2 Challenge Abstraction |
|    - Bounded Execution Lease Coordinator (60s lease, atomic consumption)     |
|    - Subsystem Execution Adapters (Redis, IdP, Question Pool, Delivery)      |
|    - Independent Verification Daemons & Verification Proof Generator         |
|    - Post-Dispatch Database Failure Reconciliation Daemon                    |
|    - Emergency Containment Quarantine Queue for Inconclusive Outcomes        |
+-----------------------------------------------------------------------------+
| C. Reusable Components (Zero Modifications Required):                       |
|    - `backend/app/modules/audit/service.py` (`AuditService`)                 |
|    - `backend/app/modules/audit/canonical.py` (JCS Serialization)            |
|    - `backend/app/crypto/kms_interface.py` (`MockKMS`, `KMSInterface`)       |
|    - `backend/app/core/database.py` (`AsyncSessionLocal`, `engine`)          |
+-----------------------------------------------------------------------------+
| D. Frozen Components (Strictly Read-Only / Inviolable):                     |
|    - Phase 3C-4A/4B Audit Tables (`audit_logs`, `audit_chain_links`, etc.)   |
|    - Phase 3C-5D Tables (`security_incidents`, `evidence_links`, `comments`) |
|    - Phase 3C-5D Service (`SecurityIncidentService`)                         |
|    - Existing Alembic Migrations (`a1b2c3d4e5f6` and earlier)                |
+─────────────────────────────────────────────────────────────────────────────+
```

---

## 10. Security-Sensitive Implementation Risks & Mitigations

1. **Risk: False Assumption of Rollback for External Mutations**:
   - *Threat*: PostgreSQL rollback assumed to undo an external Redis session revocation.
   - *Mitigation*: Rev-04.1 Pre-Dispatch Safety Invariant ensures intent is committed before socket open; Forensic Completeness Invariant uses Reconciliation Daemon to resolve state discrepancies.
2. **Risk: Duplicate Destructive Execution on Network Retries**:
   - *Threat*: Two administrators requesting termination of the same compromised session cause multiple disruptive calls.
   - *Mitigation*: 4-tier identity decoupling (`IntentKey` independent of `RequesterID`) and PostgreSQL advisory locks serialize requests.
3. **Risk: Break-Glass Scope Escalation**:
   - *Threat*: Malicious or compromised super-admin submits a break-glass request targeting multiple candidates or an entire centre.
   - *Mitigation*: Hard mathematical firewall enforces `scope.max_allowed_entities == 1`. Any multi-entity target causes immediate rejection.
4. **Risk: Replay of Expired or Consumed Break-Glass Tokens**:
   - *Threat*: Attacker captures an emergency token and replays it after the incident is resolved.
   - *Mitigation*: Database unique constraint on `token_nonce` ensures atomic, single-use consumption; 60s execution lease strictly bounds execution window.

---

## 11. Recommended Phase 3C-5E Implementation Plan

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 1: Database Foundation & Schema Migration                              │
│ - Create containment tables: `containment_intents`, `containment_requests`, │
│   `containment_authorizations`, `break_glass_tokens`, `containment_proofs`. │
│ - Add unique constraints on nonces and composite indexes on IntentKey.      │
│ - Implement migration and write isolated database unit tests.               │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 2: Dual Policy Engine & Two-Person Authorization Subsystem             │
│ - Implement Standard Policy Pipeline (`ALLOW`, `DENY`, `REQUIRE_SECOND_AUTH`)│
│ - Implement Break-Glass Emergency Pipeline (`BG_ALLOWED`, `BG_DENIED`).      │
│ - Implement Two-Person Control Quorum logic with self-approval firewall.     │
│ - Write policy rule evaluation and authorization unit tests.                │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 3: Execution Coordinator, Adapters & Independent Verification Engine    │
│ - Implement Bounded Execution Lease (60s lease, atomic token consumption).   │
│ - Implement Subsystem Execution Adapters with deterministic idempotency.    │
│ - Implement Independent Verifiers querying target ground truth out-of-band. │
│ - Connect verified outcome to 5D `transition_status(status=CONTAINED)`.     │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 4: Reconciliation Daemon, Quarantine Queue & Emergency Break-Glass     │
│ - Implement Reconciliation Process for DB failures post external mutation.   │
│ - Implement Emergency Containment Quarantine Queue for Inconclusive outcomes.│
│ - Implement FIDO2 assertion verifier abstraction and rate-limiting daemons. │
│ - Connect Mode B audit logging for all 8 mandatory lifecycle events.        │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 5: End-to-End Security Audit & Acceptance Gate Certification           │
│ - Execute all 35 architecture acceptance scenarios (TC-GATE-01 to 35).       │
│ - Run full repository regression suite to verify zero regressions.          │
│ - Produce Final Phase 3C-5E Verification & Security Certification Report.    │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 12. Final Baseline Verdict

# IMPLEMENTATION STEP 0 — READY FOR STEP 1

The repository baseline, Git tracking state, Phase 3C-5D incident foundations, audit chaining mechanisms, and cryptographic interfaces have been thoroughly verified through read-only inspection. The codebase is deterministic, all 31 baseline 5D tests pass without error, and the architecture contract is fully defined. 

**Implementation authorization is requested to proceed with Phase 3C-5E Step 1 (Database Foundation & Schema Migration).**
