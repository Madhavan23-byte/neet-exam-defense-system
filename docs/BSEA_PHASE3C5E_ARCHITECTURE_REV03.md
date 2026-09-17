# B-SEA Phase 3C-5E: Policy-Governed Security Containment Architecture Specification
## Architecture Review Rev-03 — Final Architecture Gate & Implementation Blueprint

**Document Reference**: `BSEA-ARCH-3C5E-REV03`  
**Status**: ARCHITECTURE SPECIFICATION (FINAL ARCHITECTURE GATE / READ-ONLY)  
**Date**: 2026-09-16  
**Baseline Git Commit**: `7683dd6f8d67f5289cc8cc86da3112a8aaade6ec` (Phase 3C-5D Frozen at Revision `a1b2c3d4e5f6`)  
**Supersedes**: `docs/BSEA_PHASE3C5E_ARCHITECTURE_REV02.md` and `docs/BSEA_PHASE3C5E_ARCHITECTURE_REV01.md`  
**Target Subsystem**: `backend/app/modules/containment/` (Deferred to Implementation Phase)  
**Review Status**: ARCHITECTURE READY FOR IMPLEMENTATION REVIEW  

---

## Executive Summary of Rev-03 Final Architecture Gate

Phase 3C-5E establishes the **Policy-Governed Security Containment Subsystem** for the Bharat Secure Examination Architecture (B-SEA). Following the broad architecture reconciliation in Rev-02, Rev-03 resolves all remaining targeted clarification points, establishing a fully mechanical, mathematically bounded, implementation-ready blueprint.

### Primary Rev-03 Additions & Authoritative Resolutions:
1. **Mechanical Break-Glass Protocol Specification**: Eliminates all ambiguity regarding emergency single-person containment for `HIGH` risk actions. Formulates exact eligibility, FIDO2/WebAuthn issuer requirements, single-use token binding, strict rate limits (max 2 per principal/hour, max 5 per exam), single-entity blast-radius constraints, and mandatory statutory Board review within 12 hours.
2. **Categorical Prohibition of Single-Person Bypass on CRITICAL Actions**: Re-affirms with absolute finality that `CRITICAL` actions (e.g., suspending an examination form, centre shutdown, or cryptographic key invalidation) can **never** be executed via break-glass. Two-person executive control is an inviolable mathematical invariant.
3. **Explicit Action Taxonomy & Tiers**: Normatively enumerates all actions classified as `CRITICAL` versus `HIGH`, detailing eligible scopes, dual-control requirements, executor adapters, independent verifiers, and reversibility protocols.
4. **Clarification of "Risk 1.0" Semantics**: Formally defines `risk_score = 1.0` within the B-SEA `AuditLog` schema as a normalized floating-point metric `[0.0, 1.0]`, indicating maximum security urgency and triggering immediate real-time broadcast alerts.
5. **Decoupled Multi-State Lifecycle Architecture**: Formally specifies 6 distinct state machines (Intent, Request, Authorization, Execution, Verification, and Break-Glass), rigorously isolating them from the 5D Incident Lifecycle.
6. **5D $\rightarrow$ 5E Integration Invariants**: Establishes an atomic CAS integration contract preventing cross-incident or cross-generation state corruption.
7. **Complete Security Invariant Matrix & Acceptance Gate**: Defines the 14 binding security invariants and 21 objective test scenarios required for final implementation acceptance.

---

## 1. Break-Glass Protocol — Final Normative Definition

The Emergency Break-Glass mechanism provides a deterministic, cryptographically bounded emergency override path for acute examination threats when a second authorizer is unavailable.

```
+─────────────────────────────────────────────────────────────────────────────+
|                     EMERGENCY BREAK-GLASS LIFECYCLE                         |
+─────────────────────────────────────────────────────────────────────────────+
| 1. Incident in 5D 'INVESTIGATING' (High Severity, Active Exam Window)       |
|                                     │                                       |
| 2. Standard Dual Control Attempted (Second Approver Unavailable)            |
|                                     │                                       |
| 3. SUPER_ADMIN Invokes Break-Glass with FIDO2 Hardware Token                |
|                                     │                                       |
| 4. Security Sidecar Issues Single-Use BreakGlassToken (bgt_xxx, TTL 15m)    |
|                                     │                                       |
| 5. Token Bounds: IntentKey + TargetURN + Scope (Max 1 Entity) + Nonce       |
|                                     │                                       |
| 6. Atomic Execution Dispatch (Consumes Nonce; Sets State EXECUTING)         |
|                                     │                                       |
| 7. Independent Verification Out-of-Band (Target State Asserts Mutation)     |
|                                     │                                       |
| 8. Audit Event Logged: CONTAINMENT_EMERGENCY_OVERRIDE (risk_score = 1.0)    |
|                                     │                                       |
| 9. Real-Time Webhook to Examination Oversight Board                         |
|                                     │                                       |
| 10. Mandatory Statutory Retrospective Review by Board within 12 Hours       |
+─────────────────────────────────────────────────────────────────────────────+
```

### A. Eligibility Requirements
A containment action is eligible for Emergency Break-Glass execution **only if all five conditions are simultaneously met**:
1. **Incident State**: The 5D incident must be in status `INVESTIGATING`.
2. **Incident Severity**: Incident severity must be `HIGH` or `CRITICAL`.
3. **Eligible Action Subset**: Strictly restricted to single-entity actions:
   - `ACT_CAND_SESSION_TERM` (Terminate compromised candidate session)
   - `ACT_ACCT_DISABLE` (Disable compromised candidate or invigilator account)
   - `ACT_Q_PREVENT_ASSIGN` (Flag question to prevent assignment in future slots)
   - *Categorically Ineligible*: `ACT_FORM_SUSPEND`, `ACT_CENTRE_RESTRICT`, `ACT_CENTRE_SUSPEND`, `ACT_CRYPTO_ROT_MASTER`.
4. **Target Scope**: Exactly one entity (`scope.max_allowed_entities == 1`). Wildcards or multi-entity targets are rejected.
5. **Operational Window**: Permitted strictly during active examination delivery hours (`EXAM_IN_PROGRESS`) where an active exfiltration or session hijacking attack is in progress.

### B. Break-Glass Issuer Specification
- **Authorized Role**: Strictly `SUPER_ADMIN`. `SECURITY_OFFICER` and all other roles are prohibited from issuing break-glass tokens.
- **Authentication**: Requires active primary credentials + FIDO2 WebAuthn Hardware Security Token (User Presence + User Verification PIN/Biometric).
- **Authorization Freshness**: The super-admin's authenticated session must have completed FIDO2 verification within the last **300 seconds**.
- **Requester vs. Issuer Coincidence**: In an emergency, the requesting `SUPER_ADMIN` may also act as the break-glass issuer. However, this single-person authorization is strictly counter-balanced by:
  - Single-entity scope restriction.
  - Non-reusable token constraint.
  - Automatic rate-limiting.
  - Immediate immutable audit broadcast (`risk_score = 1.0`).
  - Mandatory statutory post-execution review.

### C. Break-Glass Token Cryptographic Architecture
Every break-glass token (`BreakGlassToken`) is an ephemeral, cryptographically bound artifact:
- **Token Identifier**: `bgt_<uuidv4>` (e.g., `bgt_9f8e7d6c-5b4a-3210-fedc-ba9876543210`).
- **Cryptographic Nonce**: 256-bit cryptographically secure pseudorandom hex string (`token_nonce`).
- **Signed Payload Envelope**:
  $$\text{TokenDigest} = \text{SHA-256}(\text{CanonicalJCS}(\text{TokenEnvelope}))$$
  Where `TokenEnvelope` contains:
  ```json
  {
    "token_id": "bgt_9f8e7d6c-5b4a-3210-fedc-ba9876543210",
    "token_nonce": "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
    "incident_id": "8c5095b0-2b81-4c9d-8193-3e36297b0844",
    "incident_generation": 1,
    "intent_key": "4f9b2c3d8e7a1f0a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a",
    "canonical_target_urn": "urn:bsea:session:cand_9a8b7c6d",
    "target_scope_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "action_type": "ACT_CAND_SESSION_TERM",
    "policy_version": "POL-CONTAIN-2026-v02.1",
    "issuer_id": "usr_superadmin_01",
    "issued_at": "2026-09-16T12:00:00Z",
    "expires_at": "2026-09-16T12:15:00Z"
  }
  ```
- **Signature**: Ed25519 signature generated by the Security Sidecar using `KMS_BREAK_GLASS_SIGNING_KEY`.
- **Maximum TTL**: Exactly **15 minutes (900 seconds)** from `issued_at`.

### D. Single-Entity Scope Enforcement Rule
Break-glass execution enforces a hard mathematical ceiling:
$$\text{scope}.\text{max\_allowed\_entities} == 1$$
If a request contains `scope.max_allowed_entities > 1`, `target_id = "*"`, or targets a collection (e.g. an examination centre or form), the execution coordinator rejects the dispatch with `ERR_BREAK_GLASS_SCOPE_VIOLATION`.

### E. Token Non-Reuse & Consumption Rule
$$\mathbf{ONE\ TOKEN} \longrightarrow \mathbf{ONE\ CONTAINMENT\ INTENT} \longrightarrow \mathbf{ONE\ EXECUTION\ ATTEMPT}$$
1. When execution begins, the token's `token_nonce` is written to `containment_consumed_nonces` under an atomic database transaction.
2. If the execution fails due to a network timeout or adapter crash, the token is **permanently consumed** and cannot be used for a retry.
3. If a retry is necessary, the super-admin must generate a fresh Break-Glass Token with a new nonce, re-authenticating with FIDO2.

### F. Rate Limiting & Abuse Prevention
To prevent a compromised super-admin account from systematically dismantling an examination:
1. **Per-Principal Limit**: Maximum **2 break-glass actions per 60-minute window** per `SUPER_ADMIN`.
2. **Per-Incident Limit**: Maximum **1 break-glass action per incident generation**.
3. **Per-Examination Cohort Limit**: Maximum **5 break-glass actions across all super-admins** for a given examination slot.
4. **Target Cooldown**: A 300-second cooldown is enforced on any target entity previously affected by break-glass.
5. **Automatic Lockout**: If the 5-action examination ceiling is breached, all automated break-glass issuance is suspended; subsequent high-risk actions strictly mandate manual two-person authorization.

### G. Expiry & Timeout Semantics
- **Token Expires Before Execution**: If `NOW() > expires_at` when the execution coordinator attempts to acquire the advisory lock, the request transitions to `EXPIRED_BREAK_GLASS_TOKEN`. Zero mutation occurs.
- **Token Expires During Execution**: If execution dispatch began at $t = 899\text{s}$ and the token expires at $t = 900\text{s}$, execution completes under its acquired advisory lock. However, independent verification must complete within a 60-second grace period.
- **Token Expiry vs. Verification**: Token expiry does **not** invalidate verification. The Independent Verifier evaluates the physical state of the target subsystem, generating proof based on observed state.

### H. Break-Glass Token Revocation
A generated but unconsumed Break-Glass Token can be revoked immediately:
- By the issuing `SUPER_ADMIN`.
- By any distinct `SUPER_ADMIN`.
- By the automated Security Watchdog if anomalous telemetry is detected.
- Revocation inserts the `token_nonce` into `containment_revoked_nonces` with status `REVOKED`.

### I. Statutory Retrospective Review
**Core Invariant: Retrospective review is accountability and oversight; it is NEVER equivalent to authorization.**
1. **Reviewing Body**: Central Examination Oversight Board (statutory committee of 3 senior executive officials).
2. **Review Deadline**: Strictly within **12 hours** of examination slot termination (maximum statutory limit: 24 hours).
3. **Dossier Payload**: Automated cryptographic bundle containing:
   - 5D Incident record, rule ID, and evidence links.
   - Break-glass token metadata, issuer ID, and FIDO2 authentication log.
   - Policy evaluation record and decision hash.
   - Execution adapter logs, timestamps, and latency.
   - Independent verification proof object.
   - Complete Mode B audit log trail from `audit_logs`.
4. **Outcome States**:
   - `RATIFIED`: Board formally confirms the emergency action was lawful, necessary, and proportionate.
   - `RATIFIED_WITH_INQUIRY`: Action accepted as operationally valid, but procedural irregularities flagged for technical review.
   - `REJECTED_GOVERNANCE_BREACH`: Board determines the emergency action was unwarranted, negligent, or malicious.
5. **Enforcement on Rejection**:
   - Immediate administrative revocation of the issuing super-admin's credentials.
   - Referral to national law enforcement under the Public Examinations (Prevention of Unfair Means) Act.
   - Candidate scoring restoration or compensatory slot re-allocation initiated immediately.

---

## 2. Break-Glass Security Invariants

The following 14 invariants govern the emergency containment subsystem and are mathematically inviolable:

1. **Timeout Never Implies Authorization**: The expiration of a timer, failure of an approver to respond, or offline status can never automatically authorize an action.
2. **Zero Single-Person Bypass on CRITICAL**: Break-glass never applies to actions classified as `CRITICAL`.
3. **Rigid Scope Boundary**: Break-glass cannot expand target scope beyond $\text{max\_allowed\_entities} == 1$.
4. **Generation Binding**: Break-glass authorization signed for Generation $N$ cannot execute against Generation $N+1$.
5. **Zero Replay**: A consumed break-glass nonce cannot be submitted or executed a second time.
6. **One Token, One Intent, One Attempt**: One break-glass token cannot execute multiple containment intents or retries.
7. **Inviolable Target Fingerprint**: Break-glass cannot bypass target snapshot verification or URN validation.
8. **Inviolable Policy Governance**: Break-glass cannot bypass deterministic policy evaluation; policy engine must return `ALLOW` or `REQUIRE_SECOND_AUTHORIZER`.
9. **Inviolable Auditability**: Break-glass execution cannot commit without emitting Mode B audit records with `risk_score = 1.0`.
10. **Inviolable Independent Verification**: Break-glass execution cannot transition to `VERIFIED` without out-of-band verification proof from the independent verifier.
11. **Non-Recursive Authority**: A break-glass token cannot be used to issue another break-glass token or elevate privileges.
12. **Strict Attribution**: Every break-glass action is strictly attributable to one authenticated human `SUPER_ADMIN` with verified FIDO2 hardware proof.
13. **Statutory Non-Discretion**: Emergency break-glass actions automatically trigger statutory Board review without human intervention.
14. **Fail-Closed on Ambiguity**: Any database rollback, network partition, or token corruption during break-glass execution fails closed.

---

## 3. Normative Catalogue of CRITICAL Actions

Actions classified as `CRITICAL` carry catastrophic blast radius (affecting multiple centres, entire examination forms, or cohort integrity). They are governed by maximum operational safeguards:

```
+─────────────────────────────────────────────────────────────────────────────+
|                          CRITICAL ACTIONS CATALOGUE                         |
+─────────────────────────────────────────────────────────────────────────────+
| Action Identifier      | ACT_FORM_SUSPEND                                   |
| Action Name            | Suspend Examination Form Variant                   |
| Target Scope           | All candidates assigned to specific paper variant  |
| Max Blast Radius       | Entire Form Variant in Active Slot                 |
| Reversibility          | PARTIALLY REVERSIBLE                               |
| Normal Authorization   | Two-Person Control: Two Distinct SUPER_ADMINs       |
| Break-Glass Permitted? | NO (CATEGORICALLY PROHIBITED)                      |
| Execution Adapter      | ExamDeliveryAdapter                                |
| Independent Verifier   | ExamDeliveryVerifier (Asserts 0 candidate delivers)|
| Audit Events           | CONTAINMENT_REQUESTED, CONTAINMENT_AUTHORIZED,     |
|                        | CONTAINMENT_EXECUTED, CONTAINMENT_VERIFIED          |
+────────────────────────+────────────────────────────────────────────────────+
| Action Identifier      | ACT_CENTRE_SUSPEND                                 |
| Action Name            | Complete Operational Suspension of Exam Centre     |
| Target Scope           | All active candidates at physical centre           |
| Max Blast Radius       | Single Examination Centre Facility                 |
| Reversibility          | IRREVERSIBLE (Requires rescheduling)               |
| Normal Authorization   | Two-Person Control: Two Distinct SUPER_ADMINs       |
| Break-Glass Permitted? | NO (CATEGORICALLY PROHIBITED)                      |
| Execution Adapter      | CentreGatewayAdapter                               |
| Independent Verifier   | CentreGatewayVerifier (Asserts HTTP 403 / revoked) |
| Audit Events           | CONTAINMENT_REQUESTED, CONTAINMENT_AUTHORIZED,     |
|                        | CONTAINMENT_EXECUTED, CONTAINMENT_VERIFIED          |
+────────────────────────+────────────────────────────────────────────────────+
| Action Identifier      | ACT_CRYPTO_ROT_MASTER                              |
| Action Name            | Emergency Invalidation of Master Exam Package CMK  |
| Target Scope           | All decryption endpoints for examination slot      |
| Max Blast Radius       | National Exam Slot Decryption Key                  |
| Reversibility          | IRREVERSIBLE (Renders existing packages unreadable)|
| Normal Authorization   | Dual SUPER_ADMIN + Chief Technology Officer Signoff|
| Break-Glass Permitted? | NO (CATEGORICALLY PROHIBITED)                      |
| Execution Adapter      | KMSMasterKeyAdapter                                |
| Independent Verifier   | KMSKeyVerifier (Asserts KeyState == Disabled)      |
| Audit Events           | CONTAINMENT_REQUESTED, CONTAINMENT_AUTHORIZED,     |
|                        | CONTAINMENT_EXECUTED, CONTAINMENT_VERIFIED          |
+────────────────────────+────────────────────────────────────────────────────+
| Action Identifier      | ACT_EXAM_TERMINATE                                 |
| Action Name            | Immediate National Termination of Examination      |
| Target Scope           | Entire National Examination Cohort                 |
| Max Blast Radius       | Entire National Examination                        |
| Reversibility          | IRREVERSIBLE (Catastrophic national re-exam)       |
| Normal Authorization   | Board Statutory Quorum (Outside 5E Scope)          |
| Break-Glass Permitted? | NEVER (OUT OF SCOPE / BOARD STATUTORY PROTOCOL)    |
| Execution Adapter      | N/A (Manual Executive Directive)                   |
| Independent Verifier   | N/A (Statutory Commission Inquiry)                 |
| Audit Events           | DISASTER_RECOVERY_TERMINATION                      |
+─────────────────────────────────────────────────────────────────────────────+
```

---

## 4. Normative Catalogue of HIGH Actions

Actions classified as `HIGH` carry substantial operational impact (affecting a question across future slots, single centre delivery restrictions, or user account suspensions) but are strictly bounded to single targets:

```
+─────────────────────────────────────────────────────────────────────────────+
|                            HIGH ACTIONS CATALOGUE                           |
+─────────────────────────────────────────────────────────────────────────────+
| Action Identifier      | ACT_Q_PREVENT_ASSIGN                               |
| Action Name            | Prevent Question Assignment in Blueprint Pool      |
| Target Scope           | Single Question Object (URN: urn:bsea:question:xxx)|
| Max Blast Radius       | Future Slot Blueprint Allocations (Max 1 Entity)   |
| Reversibility          | REVERSIBLE (Re-enable question in blueprint)       |
| Normal Authorization   | Two-Person Control: SEC_OFFICER + SUPER_ADMIN      |
| Break-Glass Permitted? | YES (Single SUPER_ADMIN + FIDO2 Break-Glass Token) |
| Execution Adapter      | QuestionPoolAdapter                                |
| Independent Verifier   | QuestionPoolVerifier (Asserts is_assignable=FALSE) |
| Emergency Restriction  | Single question object only; max 1 per generation  |
+────────────────────────+────────────────────────────────────────────────────+
| Action Identifier      | ACT_CENTRE_RESTRICT                                |
| Action Name            | Restrict Centre Outbound Delivery Dispatch         |
| Target Scope           | Single Centre (URN: urn:bsea:centre:xxx)           |
| Max Blast Radius       | Single Centre Dispatch Pipeline (Max 1 Entity)     |
| Reversibility          | PARTIALLY REVERSIBLE (Can lift restriction)        |
| Normal Authorization   | Two-Person Control: SEC_OFFICER + SUPER_ADMIN      |
| Break-Glass Permitted? | NO (Centre restriction requires normal dual auth)  |
| Execution Adapter      | CentreDispatchAdapter                              |
| Independent Verifier   | CentreDispatchVerifier (Asserts routing throttled) |
| Emergency Restriction  | Ineligible for single-person emergency bypass      |
+────────────────────────+────────────────────────────────────────────────────+
| Action Identifier      | ACT_ACCT_DISABLE                                   |
| Action Name            | Disable High-Privilege Account (Invigilator/Admin)  |
| Target Scope           | Single User Account (URN: urn:bsea:user:xxx)       |
| Max Blast Radius       | Single System User Account (Max 1 Entity)          |
| Reversibility          | REVERSIBLE (Account re-enablement via supervisor)   |
| Normal Authorization   | Two-Person Control: SEC_OFFICER + SUPER_ADMIN      |
| Break-Glass Permitted? | YES (Single SUPER_ADMIN + FIDO2 Break-Glass Token) |
| Execution Adapter      | UserAccountAdapter                                 |
| Independent Verifier   | UserAccountVerifier (Asserts is_active=FALSE)      |
| Emergency Restriction  | Single user account only; max 2 per hour           |
+─────────────────────────────────────────────────────────────────────────────+
```

---

## 5. Risk Score / "Risk 1.0" Semantics & Schema Definition

In Rev-01 and Rev-02, the term "risk 1.0 audit log" was referenced without full mathematical definition. Rev-03 formally specifies its schema, valid ranges, and operational semantics.

### A. Database Schema Definition
In the canonical B-SEA database model (`backend/app/core/models.py`), the `audit_logs` table defines:
```sql
risk_score FLOAT NOT NULL DEFAULT 0.0 CHECK (risk_score >= 0.0 AND risk_score <= 1.0)
```

### B. Normative Risk Score Tiering:

| Risk Score Range | Classification Tier | Operational Meaning & Automated Actions |
| :--- | :--- | :--- |
| `0.00` – `0.20` | **INFORMATIONAL** | Routine operational actions (login, normal signal logging, policy read). Standard ingestion. |
| `0.21` – `0.50` | **LOW RISK** | Minor anomalies, single session terminations (`ACT_CAND_SESSION_TERM`). Logged without high-priority alerting. |
| `0.51` – `0.75` | **MEDIUM RISK** | Account disablement (`ACT_ACCT_DISABLE`), repeated authentication failures. Logged; routed to security analyst console. |
| `0.76` – `0.95` | **HIGH RISK** | Standard Two-Person authorized actions (`ACT_Q_PREVENT_ASSIGN`, `ACT_CENTRE_RESTRICT`). High-priority alert to SOC. |
| `1.00` (Exact) | **CRITICAL OVERRIDE**| **Emergency Break-Glass Execution / Imminent Examination Threat**. Bypasses aggregation queues; triggers immediate synchronous SMS/Webhook broadcast to Examination Board. |

### C. Invariant:
The value `risk_score = 1.0` is strictly reserved for:
1. `CONTAINMENT_EMERGENCY_OVERRIDE` (Emergency Break-Glass dispatches).
2. `CONTAINMENT_REPLAY_ATTACK_DETECTED` (Active cryptographic tampering detected).
3. `CONTAINMENT_VERIFICATION_DISCREPANCY` (Target state mismatch after reported execution).
4. `DISASTER_RECOVERY_TERMINATION` (Executive national-scale crisis actions).

---

## 6. Phase 3C-5D $\rightarrow$ Phase 3C-5E Integration Interface

The integration between Phase 3C-5D (Incident Core) and Phase 3C-5E (Containment Subsystem) is governed by an explicit atomic contract:

```
+─────────────────────────────────────────────────────────────────────────────+
|               5D <-> 5E ATOMIC CAS STATE INTEGRATION CONTRACT               |
+─────────────────────────────────────────────────────────────────────────────+
| 1. Incident Ingress Query:                                                  |
|    5E reads 5D Incident ensuring:                                           |
|    - status == 'INVESTIGATING'                                              |
|    - correlation_status == 'OPEN'                                           |
|    - generation == expected_generation                                      |
|    - version == expected_version                                            |
|                                                                             |
| 2. Execution & Independent Verification in 5E:                              |
|    5E coordinates execution, verifies target state out-of-band, and logs    |
|    CONTAINMENT_VERIFIED to audit_logs (returns audit_event_reference).      |
|                                                                             |
| 3. Atomic Observational Update to 5D:                                       |
|    5E invokes SecurityIncidentService.transition_status() with:             |
|    - incident_id: UUID                                                      |
|    - new_status: SecurityIncidentStatus.CONTAINED                           |
|    - expected_version: expected_version                                     |
|    - actor_id: approver_id                                                  |
|    - actor_role: UserRoleEnum.SUPER_ADMIN                                   |
|    - containment_data: {                                                    |
|        containment_reference_id: request.id,                                |
|        containment_mechanism: request.action_type,                          |
|        authorization_principal: approver_id,                                |
|        containment_timestamp: verified_at,                                  |
|        audit_event_reference: audit_event_reference                         |
|      }                                                                      |
+─────────────────────────────────────────────────────────────────────────────+
```

### Stale Generation & Concurrency Rejection:
- The update in 5D executes under an atomic Compare-and-Swap (CAS) query:
  ```sql
  UPDATE security_incidents
  SET status = 'CONTAINED',
      containment_reference_id = :containment_reference_id,
      containment_mechanism = :containment_mechanism,
      authorization_principal = :authorization_principal,
      containment_timestamp = :containment_timestamp,
      audit_event_reference = :audit_event_reference,
      seal_verification_status = 'PENDING_SEAL',
      version = :expected_version + 1,
      updated_at = NOW()
  WHERE id = :incident_id
    AND generation = :expected_generation
    AND version = :expected_version
    AND correlation_status = 'OPEN';
  ```
- If the incident experienced an inactivity rollover ($N \rightarrow N+1$) during 5E processing, rowcount is `0`.
- 5D raises `StaleGenerationError`. 5E immediately rolls back, logs `CONTAINMENT_STALE_GEN_REJECTED`, and halts. **Generation $N+1$ remains untouched.**

---

## 7. Final Containment State Model

To eliminate architectural coupling, Rev-03 defines **6 distinct state models**, completely decoupled from the 5D Incident Lifecycle:

```
+─────────────────────────────────────────────────────────────────────────────+
|                    THE 6 DECOUPLED STATE ARCHITECTURES                      |
+─────────────────────────────────────────────────────────────────────────────+
| 1. Incident Lifecycle (5D) | TRIAGE -> INVESTIGATING -> CONTAINED ->        |
|                            | RESOLVED -> CLOSED -> FALSE_POS -> DUPLICATE   |
+────────────────────────────+────────────────────────────────────────────────+
| 2. Containment Intent (5E) | REGISTERED -> IN_PROGRESS -> CONTAINED ->      |
|                            | EXPIRED -> FAILED                              |
+────────────────────────────+────────────────────────────────────────────────+
| 3. Containment Request (5E)| REQUESTED -> POLICY_EVALUATED ->               |
|                            | AWAITING_AUTHORIZATION -> AUTHORIZED ->        |
|                            | EXECUTING -> EXECUTED -> VERIFYING_PENDING ->  |
|                            | VERIFIED -> FAILED -> EXPIRED -> CANCELLED     |
+────────────────────────────+────────────────────────────────────────────────+
| 4. Authorization (5E)      | PENDING_APPROVAL -> APPROVED_DUAL ->           |
|                            | APPROVED_BREAK_GLASS -> REJECTED -> EXPIRED    |
+────────────────────────────+────────────────────────────────────────────────+
| 5. Execution (5E)          | PENDING -> DISPATCHED -> COMPLETED ->          |
|                            | TIMED_OUT -> FAILED                            |
+────────────────────────────+────────────────────────────────────────────────+
| 6. Independent Verification| PENDING -> VERIFIED -> DISCREPANCY ->          |
|                            | INCONCLUSIVE                                   |
+────────────────────────────+────────────────────────────────────────────────+
| 7. Break-Glass Token (5E)  | ISSUED -> CONSUMED -> EXPIRED -> REVOKED ->   |
|                            | UNDER_REVIEW -> RATIFIED -> BREACH_DECLARED    |
+─────────────────────────────────────────────────────────────────────────────+
```

### State Decoupling Invariant:
An execution failure in 5E does **not** transition the 5D Incident to `FAILED` or `CLOSED`. The 5D Incident remains in `INVESTIGATING`, enabling analysts to re-evaluate evidence, review adapter error codes, and submit alternative containment strategies.

---

## 8. Final Security Invariant Matrix

The following comprehensive matrix details the 14 foundational security invariants, the specific threats they eliminate, their enforcement layers, failure behaviors, and audit evidence:

| # | Invariant | Threat Prevented | Enforcement Layer | Failure Behavior | Audit Evidence Generated |
| :- | :--- | :--- | :--- | :--- | :--- |
| **I-01** | **Requester / Approver Separation** | Rogue officer unilateral execution; credential abuse. | Policy & Auth Coordinator | Rejects self-approval with `DualControlSelfApprovalError`. | `CONTAINMENT_AUTH_REJECTED` |
| **I-02** | **Executor / Verifier Separation** | Executor lying about successful execution; adapter compromise.| Execution & Verification Daemons | Decoupled modules; verifier uses read-only pool. | `CONTAINMENT_VERIFICATION_FAILED` |
| **I-03** | **Generation Binding** | Action authorized for Gen 1 mutating Gen 2 after rollover. | PostgreSQL CAS Query (`WHERE gen = :expected`) | Rollback with `StaleGenerationError`. | `CONTAINMENT_STALE_GEN_REJECTED` |
| **I-04** | **Target URN & Snapshot Binding** | Confused deputy; target substitution in flight. | Execution Coordinator (Hash check) | Recomputes target hash; halts on mismatch. | `TARGET_SUBSTITUTION_ATTACK_DETECTED` |
| **I-05** | **Policy Fingerprint Binding** | Executing action under superseded/revoked policy. | Policy Engine & Execution Coordinator | Checks `policy_fingerprint == active_catalog`. | `CONTAINMENT_POLICY_SUPERSEDED` |
| **I-06** | **Strict Scope Ceiling** | Accidental escalation from single session to entire exam. | Anti-Escalation Scope Firewall | Rejects wildcard targets or `max_entities > 1`. | `CONTAINMENT_SCOPE_VIOLATION` |
| **I-07** | **Replay Protection** | Capturing and resubmitting valid authorization signatures. | Database Unique Constraint on `token_nonce` | DB throws unique violation; rejects request. | `CONTAINMENT_REPLAY_ATTACK_DETECTED` |
| **I-08** | **Idempotency Invariance** | Network retries triggering duplicate destructive actions. | PostgreSQL Advisory Lock on `IntentKey` | Serializes; returns cached verified result. | `CONTAINMENT_DUPLICATE_SUPPRESSED` |
| **I-09** | **Dual Authorization on High/Critical**| Unilateral administrative destruction of exam assets. | Authorization Service Quorum Logic | Rejects single-person dispatch for High/Critical.| `CONTAINMENT_INSUFFICIENT_AUTH` |
| **I-10** | **Break-Glass CRITICAL Prohibition** | Single-person shutdown of national exam forms/centres. | Hardcoded Policy Evaluator Validator | Categorically rejects break-glass for CRITICAL. | `BREAK_GLASS_CRITICAL_PROHIBITED` |
| **I-11** | **Out-of-Band Independent Verification**| False completion claims by failed/mock adapters. | Independent Verification Engine | Directly queries target data store; flags mismatch.| `CONTAINMENT_VERIFIED` / `FAILED` |
| **I-12** | **Fail-Closed on Ambiguity** | Execution timeout mistakenly treated as success. | Execution Coordinator State Machine | Transitions to `VERIFYING_PENDING`; no success. | `CONTAINMENT_EXECUTION_TIMEOUT` |
| **I-13** | **Immutable Audit Attribution** | Unattributable actions; tampering with incident history. | Canonical `AuditService` Mode B Transaction | Aborts entire containment if audit write fails. | Canonical `audit_logs` row |
| **I-14** | **Observational 5D Boundary** | Containment subsystem corrupting incident detection core.| Strict Service Contract (`transition_status`) | Rejects unauthorized column updates via triggers. | `INCIDENT_STATUS_CHANGED` |

---

## 9. Final Implementation Acceptance Gate

Phase 3C-5E implementation will be certified complete only when all 21 automated architecture test scenarios pass genuinely against PostgreSQL:

| Test ID | Test Category | Specific Invariant & Scenario Tested | Mandatory Expected Outcome |
| :--- | :--- | :--- | :--- |
| `TC-GATE-01` | Idempotency | Parallel concurrent requests with identical `IntentKey`. | Advisory lock serializes; exactly 1 execution; 2nd returns cached result. |
| `TC-GATE-02` | Idempotency | Different requesters submit request for same target session. | Resolves to identical `IntentKey`; second requester attached as observer. |
| `TC-GATE-03` | Idempotency | Network retry after successful execution. | Detects `status == VERIFIED`; returns `200 OK` with existing proof. |
| `TC-GATE-04` | 5D Boundary | Generation rollover ($N \rightarrow N+1$) occurs during 5E execution. | 5D CAS query rejects update; 5E halts; Gen $N+1$ remains untouched. |
| `TC-GATE-05` | TOCTOU | Target session status modified between authorization and execution. | Recomputed snapshot hash mismatches; transaction aborts; zero mutation. |
| `TC-GATE-06` | Policy | Active policy catalog updated; request signed under superseded version. | Coordinator detects policy fingerprint mismatch; aborts with `EXPIRED`. |
| `TC-GATE-07` | Authorization | Requester attempts to sign as second approver for `HIGH` risk action. | Auth service raises `DualControlSelfApprovalError`. |
| `TC-GATE-08` | Authorization | Re-submission of consumed authorization signature. | Database unique constraint on `auth_nonce` throws 409 Conflict. |
| `TC-GATE-09` | Authorization | Valid authorization executed after 301 seconds (TTL 300s expired). | Request rejected with `ERR_AUTHORIZATION_EXPIRED`. |
| `TC-GATE-10` | Break-Glass | Attempt to invoke Break-Glass for `ACT_FORM_SUSPEND` (`CRITICAL`). | Policy engine categorically rejects with `BREAK_GLASS_CRITICAL_PROHIBITED`.|
| `TC-GATE-11` | Break-Glass | Break-Glass Token submitted with `scope.max_allowed_entities == 2`. | Coordinator rejects with `ERR_BREAK_GLASS_SCOPE_VIOLATION`. |
| `TC-GATE-12` | Break-Glass | Replay of consumed `BreakGlassToken` nonce. | Database unique constraint on `token_nonce` throws conflict. |
| `TC-GATE-13` | Break-Glass | Break-Glass Token executed after 901 seconds (TTL 900s expired). | Execution coordinator rejects with `ERR_BREAK_GLASS_TOKEN_EXPIRED`. |
| `TC-GATE-14` | Break-Glass | Super-admin attempts 3rd break-glass action within 60 minutes. | Rate limiter blocks issuance with `ERR_BREAK_GLASS_RATE_LIMIT_EXCEEDED`. |
| `TC-GATE-15` | Separation | Executor adapter attempts to call verification endpoint directly. | API gateway rejects with `403 Forbidden` (Executor cannot verify). |
| `TC-GATE-16` | Verification | Adapter reports HTTP 200, but target DB session remains `ACTIVE`. | Verifier detects discrepancy; transitions to `VERIFICATION_FAILED`. |
| `TC-GATE-17` | Failure | Execution adapter times out after 10 seconds. | Request set to `VERIFYING_PENDING`; verifier called; success NOT presumed. |
| `TC-GATE-18` | Failure | Target subsystem completely unreachable (network partition). | Fails closed with `ERR_TARGET_UNREACHABLE`; incident remains `INVESTIGATING`.|
| `TC-GATE-19` | Audit | Simulated DB failure during `AuditService.log_security_event()`. | Entire containment transaction rolls back; zero target mutation committed.|
| `TC-GATE-20` | Rollback | Rollback requested for `ACT_CAND_SESSION_TERM`. | Reversible compensation logged; candidate permitted to re-authenticate. |
| `TC-GATE-21` | Regression | Full repository test suite executed post-5E integration. | **All 271 baseline tests pass with zero regressions.** |

---

## 10. Final Architecture Verdict

### A. Architectural Decisions Reconfirmed:
1. **Mechanical Break-Glass Protocol**: Defined with single-use cryptographic tokens, FIDO2 issuer authentication, single-entity scope limits, and mandatory 12-hour Board review.
2. **Inviolable Dual Control on CRITICAL**: Zero single-person bypass permitted for `CRITICAL` risk actions under any circumstances.
3. **Decoupled 4-Tier Identity**: `IntentKey` strictly independent of `RequesterID`, eliminating duplicate execution races.
4. **Strict 5D / 5E Boundary**: Atomic CAS integration contract prevents cross-incident or cross-generation state mutation.
5. **Decoupled 6-Tier State Model**: Intent, Request, Authorization, Execution, Verification, and Break-Glass states are strictly separated from 5D Incident Lifecycle.
6. **Normative Action Scopes**: Formally categorized `CRITICAL` vs. `HIGH` actions with exact blast-radius limits.
7. **Explicit Risk 1.0 Semantics**: Defined as normalized floating-point maximum risk score in B-SEA audit schema, triggering real-time emergency broadcast.

### B. Final Verdict

# ARCHITECTURE READY FOR IMPLEMENTATION REVIEW

Phase 3C-5E Architecture Specification Rev-03 successfully resolves every targeted clarification point, eliminates all remaining ambiguities, and establishes an airtight, mathematically bounded specification. **Phase 3C-5E is certified ready for final human implementation authorization.**
