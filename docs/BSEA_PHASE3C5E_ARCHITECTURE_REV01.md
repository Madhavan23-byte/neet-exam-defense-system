# B-SEA Phase 3C-5E: Policy-Governed Security Containment Architecture Specification
## Architecture Review Rev-01 — Implementation Blueprint

**Document Reference**: `BSEA-ARCH-3C5E-REV01`  
**Status**: ARCHITECTURE SPECIFICATION (READ-ONLY / NO IMPLEMENTATION AUTHORIZED)  
**Date**: 2026-09-16  
**Baseline Git Commit**: `7683dd6f8d67f5289cc8cc86da3112a8aaade6ec` (Phase 3C-5D Frozen at Revision `a1b2c3d4e5f6`)  
**Target Subsystem**: `backend/app/modules/containment/` (Deferred to Implementation Phase)  
**Review Status**: ARCHITECTURE READY FOR REVIEW  

---

## 1. Executive Summary

Phase 3C-5E establishes the **Policy-Governed Security Containment Framework** for the Bharat Secure Examination Architecture (B-SEA). Following the successful verification and freeze of Phase 3C-5D (Incident Management Foundation), Phase 3C-5E transforms verified security incidents into authorized, targeted, policy-governed, and independently verifiable security containment actions.

In high-stakes national examinations, an uncontrolled autonomous containment system is as dangerous as the security threats it seeks to mitigate. A single false positive or compromised component must never trigger wide-scale examination disruption, premature question paper quarantine, or candidate mass disenfranchisement.

Phase 3C-5E establishes a strict pipeline:
$$\text{Verified Incident (5D)} \longrightarrow \text{Policy Evaluation (5E)} \longrightarrow \text{Authorization / Dual-Control (5E)} \longrightarrow \text{Idempotent Execution (5E)} \longrightarrow \text{Independent Verification (5E)} \longrightarrow \text{Immutable Audit (5A/5B)}$$

### Core Tenets:
1. **Separation of Concerns**: 5C (Detection) and 5D (Incident Management) remain strictly analytical and observational. They possess **zero execution authority**.
2. **Deterministic Policy Governance**: Every containment action requires explicit policy evaluation against immutable, versioned containment policies.
3. **Two-Person Control (Dual Authorization)**: High-risk and critical-risk containment actions (e.g., candidate account disabling, question quarantine, centre-level suspension) strictly require cryptographic dual authorization by distinct principals.
4. **Independent Verification**: Execution of containment is never presumed successful based on executor response alone; it requires out-of-band verification against the authoritative target subsystem state.
5. **Fail-Closed & Reversible Where Feasible**: Containment defaults to safe denial when ambiguity exists. Every action declares its reversibility and compensation protocols.

---

## 2. Design Goals

1. **Strict Defense-in-Depth**: Ensure that no single compromised credential, compromised analyst, rogue detection rule, or malicious API request can execute destructive or disruptive containment.
2. **Explicit Least-Privilege Execution**: Decouple the containment requester, the policy engine, the authorizer(s), and the execution adapter.
3. **Cryptographic Attribution**: Bind containment requests, policy decisions, authorizer approvals, and verification proofs into an unbroken, tamper-evident audit record logged via canonical `AuditService`.
4. **Idempotency & Replay Resistance**: Ensure that network retries, duplicate requests, worker restarts, or replay attacks cannot result in duplicate executions or unexpected state transitions.
5. **Bounded Blast Radius**: Enforce strict hierarchical constraints preventing local actions (e.g., terminating a single candidate session) from escalating into exam-wide or multi-centre disruptions without explicit policy re-evaluation and dual executive authorization.
6. **Zero-Trust Context Verification**: Re-evaluate the security context, incident generation validity, policy version, and authorizer freshness at the moment of execution, rejecting stale or TOCTOU-compromised requests.

---

## 3. Non-Goals

1. **No Autonomous Destructive Response**: 5E will not autonomously cancel examinations, invalidate entire question banks, or disconnect testing centres based purely on anomaly thresholds.
2. **No Enterprise SIEM / SOC Integration (Deferred to Phase 3C-5F)**: External syslog forwarding, Common Event Format (CEF) ingestion, Splunk/Elastic connectors, and SOC webhook dispatching belong strictly to Phase 3C-5F.
3. **No Network-Level Infrastructure Manipulation**: 5E does not configure AWS Security Groups, Border Gateway Protocol (BGP) routing, or physical data-center routers. Network containment operates at the application API and authentication layer.
4. **No Direct UI/Frontend Construction**: This specification defines the authoritative backend service contracts, state machines, and data models. UI presentation components are out of scope.
5. **No Production Hardware Security Module (HSM) Deployment in Phase 3C**: Production hardware HSM integration is an operational deployment control. Phase 3C continues to use the proven `MockKMS` prototype abstraction with production-ready cryptographic semantics.

---

## 4. Existing 5D Boundary

Phase 3C-5D is **FROZEN** under baseline `7683dd6f8d67f5289cc8cc86da3112a8aaade6ec` and Alembic revision `a1b2c3d4e5f6`. 

Phase 3C-5D guarantees:
- Stable threat-vector identity derived via RFC 8785 JCS canonicalization and SHA-256 (`threat_vector_key`).
- Strictly monotonic generation rollover based on a 3600-second rolling inactivity window (`generation`, `preceding_incident_id`).
- PostgreSQL transaction-scoped advisory locks (`pg_advisory_xact_lock`) guaranteeing zero race conditions and zero signal loss.
- Human lifecycle state machine with exactly 7 persistent states: `TRIAGE`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `CLOSED`, `FALSE_POSITIVE`, `DUPLICATE`.
- Observational `CONTAINED` state: In 5D, transitioning to `CONTAINED` merely documents observational containment metadata (`containment_reference_id`, `containment_mechanism`, `authorization_principal`, `containment_timestamp`, `audit_event_reference`, `seal_verification_status`). It leaves `correlation_status = 'OPEN'` and triggers **no active enforcement**.
- Append-only immutability triggers on evidence links and comments.

**5E Boundary Invariant**:
Phase 3C-5E consumes verified incidents from 5D. 5E **never modifies** 5D correlation keys, generation logic, or threat vector definitions. When 5E successfully executes and verifies containment, it calls the authoritative 5D `SecurityIncidentService.transition_status()` to record the observational metadata in the incident record.

---

## 5. 5E Architecture Overview

```
+─────────────────────────────────────────────────────────────────────────────+
|                         Phase 3C-5D Incident Layer                          |
|  SecurityIncident (Status: INVESTIGATING, Generation: N, Correlation: OPEN) |
+──────────────────────────────────────┬──────────────────────────────────────+
                                       │ 1. Request Containment Action
                                       ▼
+─────────────────────────────────────────────────────────────────────────────+
|                        Phase 3C-5E Containment Engine                       |
|                                                                             |
|   +─────────────────────────────────────────────────────────────────────+   |
|   | 1. Policy Evaluation Layer (Deterministic, Immutable Policy vX)     |   |
|   |    - Evaluates: Incident, Threat Vector, Target, Scope, Risk Level  |   |
|   |    - Outcome: ALLOW | DENY | REQUIRE_SECOND_AUTHORIZER              |   |
|   +──────────────────────────────────┬──────────────────────────────────+   |
|                                      │ 2. Policy Approved / Dual Req.       |
|                                      ▼                                      |
|   +─────────────────────────────────────────────────────────────────────+   |
|   | 2. Authorization & Dual-Control Layer                               |   |
|   |    - Requester Signature & Approver Signature (Distinct Principals) |   |
|   |    - Freshness Window Check (< 300s) & Token Replay Validation      |   |
|   +──────────────────────────────────┬──────────────────────────────────+   |
|                                      │ 3. Authorized Request Bound to Gen N |
|                                      ▼                                      |
|   +─────────────────────────────────────────────────────────────────────+   |
|   | 3. Execution Coordinator (PostgreSQL Advisory Lock Serialized)      |   |
|   |    - Target-Specific Adapters (Session, Account, Content, Exam)     |   |
|   |    - Idempotency & Replay Protection Check                          |   |
|   +──────────────────────────────────┬──────────────────────────────────+   |
|                                      │ 4. Invokes Subsystem Adapter         |
|                                      ▼                                      |
|   +─────────────────────────────────────────────────────────────────────+   |
|   | 4. Independent Verification Engine                                  |   |
|   |    - Queries Authoritative Target Subsystem Directly                |   |
|   |    - Confirms Target State Matches Containment Invariant            |   |
|   +──────────────────────────────────┬──────────────────────────────────+   |
|                                      │ 5. Verification Proof Generated      |
+──────────────────────────────────────┼──────────────────────────────────────+
                                       │
         ┌─────────────────────────────┴─────────────────────────────┐
         ▼ 6. Update Incident Observational State                    ▼ 7. Immutable Audit Log
+──────────────────────────────────+                       +──────────────────────────+
|      Phase 3C-5D Foundation      |                       |    Phase 3C-5A / 5B      |
| SecurityIncident.status =        |                       | Canonical AuditService   |
| 'CONTAINED' (Seal Pending)       |                       | (Dedicated Mode B Tx)    |
+──────────────────────────────────+                       +──────────────────────────+
```

---

## 6. Trust Boundaries

| Trust Zone | Components | Privileges & Responsibilities | Boundary Protection |
| :--- | :--- | :--- | :--- |
| **Zone 0: Ingestion / Detection** | Rule Engine, Normalizer, Advisory Signals | Computes anomaly signals, emits advisory alerts. **ZERO containment authority.** | Isolated by API gateway; cannot invoke containment adapters. |
| **Zone 1: Incident Operations** | `SECURITY_OFFICER`, Incident Service | Triages incidents, documents evidence, initiates containment requests. | Governed by RBAC; requests are unexecuted proposals. |
| **Zone 2: Containment Policy & Dual Auth**| Policy Engine, `SUPER_ADMIN`, Dual Authorizer | Validates policy eligibility, verifies authorization freshness, signs approvals. | Cryptographic signature binding; separation of requester and approver. |
| **Zone 3: Containment Execution** | Execution Coordinator, Subsystem Adapters | Executes authorized mutations against sessions, users, questions, forms. | Mutually authenticated internal service calls; advisory lock serialization. |
| **Zone 4: Independent Verification** | Verification Engine, Target State Oracles | Reads authoritative target state out-of-band to confirm state mutation. | Read-only access to subsystem databases; independent from execution adapters. |
| **Zone 5: Forensic Audit Record** | `AuditService`, PostgreSQL `audit_logs`, Sealer | Records immutable tamper-evident logs, seals epochs, preserves nonces. | Mode B transaction isolation; append-only triggers; KMS cryptographic sealing. |

---

## 7. Containment Action Catalogue

The containment action catalogue defines all potential containment actions across 6 functional domains. Every action is evaluated for its risk tier, blast radius, reversibility, and phase assignment.

| Action Identifier | Action Category | Description & Operational Impact | Max Blast Radius | Reversibility | Required Evidence | Dual Control | Target Phase |
| :--- | :--- | :--- | :--- | :--- | :--- | :---: | :---: |
| `ACT_CAND_SESSION_TERM` | A. Candidate Session | Terminate single active candidate exam session; candidate forced to re-authenticate. | Single Candidate Session | **REVERSIBLE** (Candidate can re-login if exam window open) | Active advisory signal matching session ID + IP mismatch or tampering event | **NO** (Single `SECURITY_OFFICER`) | **5E** |
| `ACT_CAND_SESSION_SUSP` | A. Candidate Session | Temporarily suspend session for proctor/security inspection; blocks exam timer progression. | Single Candidate Session | **REVERSIBLE** (Proctor/Officer un-suspends) | Biometric mismatch, dual-display detection, or proctor alert | **NO** (Single `SECURITY_OFFICER`) | **5E** |
| `ACT_CAND_REAUTH_REQ` | A. Candidate Session | Invalidate current JWT; force candidate biometric / MFA re-verification on next request. | Single Candidate Session | **REVERSIBLE** (Successful MFA re-authenticates) | Suspected credential sharing or token refresh anomaly | **NO** (Single `SECURITY_OFFICER`) | **5E** |
| `ACT_ACCT_DISABLE` | B. Account | Disable candidate or invigilator user account; revokes all active tokens; blocks login. | Single User Account | **REVERSIBLE** (Supervisory reinstatement) | Confirmed impersonation, credential leakage, or malicious insider alert | **YES** (`SECURITY_OFFICER` + `SUPER_ADMIN`) | **5E** |
| `ACT_ACCT_TOKEN_REVOKE` | B. Account | Revoke all active refresh tokens and session grants for a user account across all devices. | Single User Account | **REVERSIBLE** (Re-authentication) | Stolen token alert, concurrent session violation from distinct geographic IPs | **NO** (Single `SECURITY_OFFICER`) | **5E** |
| `ACT_CENTRE_RESTRICT` | C. Exam Centre | Restrict outbound question delivery to a specific test centre; hold in-flight submission verification. | Single Exam Centre | **PARTIALLY REVERSIBLE** (May delay exam delivery) | Centre-wide network exfiltration, mass proxy detection, or unauthorized LAN gateway | **YES** (`SECURITY_OFFICER` + `SUPER_ADMIN`) | **5E** |
| `ACT_CENTRE_SUSPEND` | C. Exam Centre | Complete operational shutdown of examination centre; cancels ongoing exam sessions for all candidates at centre. | All Candidates at Centre | **IRREVERSIBLE** (Requires exam reschedule) | Severe physical breach, widespread systemic paper leakage at centre | **YES** (Dual `SUPER_ADMIN` + Executive Auth) | **Deferred (Post-5E)** |
| `ACT_Q_QUARANTINE_OBJ` | D. Content / Question | Quarantine specific question object; replaces question in-flight with dynamically allocated reserve question. | Single Question Object across Exam | **PARTIALLY REVERSIBLE** (Reinstatement requires psychometric audit) | Cryptographic hash match with public leak, external plaintext match | **YES** (`SECURITY_OFFICER` + `SUPER_ADMIN`) | **5E** |
| `ACT_Q_PREVENT_ASSIGN` | D. Content / Question | Flag question in blueprint pool to prevent future assignment to subsequent exam slots. | Future Candidates in Exam | **REVERSIBLE** (Unflag question) | Question defect report, suspected item exposure prior to slot start | **NO** (Single `SECURITY_OFFICER`) | **5E** |
| `ACT_CRYPTO_KEY_INVAL` | E. Cryptographic | Invalidate ephemeral session encryption key; trigger immediate key renegotiation. | Single Candidate Session | **REVERSIBLE** (Renegotiate ECDH key) | Replay detection, nonce exhaustion, or payload integrity decryption failure | **NO** (Single `SECURITY_OFFICER`) | **5E** |
| `ACT_CRYPTO_ROT_MASTER`| E. Cryptographic | Rotate master exam package encryption CMK / asymmetric private key in KMS. | Entire Exam Slot | **HIGH RISK / IRREVERSIBLE** | Master key leakage, HSM authorization policy compromise | **YES** (Dual `SUPER_ADMIN` + Security Director) | **Deferred (Phase 4)** |
| `ACT_FORM_SUSPEND` | F. Exam Form | Suspend entire exam form / paper variant; halt new session starts using this form. | Candidates Assigned to Form | **PARTIALLY REVERSIBLE** | Verified form-wide leakage, systemic answer key compromise | **YES** (`SECURITY_OFFICER` + `SUPER_ADMIN`) | **5E** |
| `ACT_EXAM_TERMINATE` | F. Exam Form | Immediate termination of national examination across all centres and forms. | Entire Examination Cohort | **IRREVERSIBLE** | Catastrophic systemic compromise | **OUT OF SCOPE** (Board-Level Disaster Protocol) | **Never Autonomous** |

---

## 8. Risk Classification

The normative containment risk taxonomy establishes binding operational constraints for every action:

```
+-----------------------------------------------------------------------------------+
| RISK LEVEL | BLAST RADIUS      | REVERSIBILITY | AUTHORIZATION REQUIRED | DUAL?   |
+------------+-------------------+---------------+------------------------+---------+
| LOW        | Single Session    | Reversible    | SECURITY_OFFICER       | NO      |
| MEDIUM     | Single User Acct  | Reversible    | SECURITY_OFFICER       | NO      |
| HIGH       | Question / Centre | Partially Rev | SEC_OFFICER + SUPER    | YES     |
| CRITICAL   | Multi-Centre/Form | Irreversible  | DUAL SUPER_ADMIN       | YES     |
+-----------------------------------------------------------------------------------+
```

### Risk Level Definitions:
1. **`LOW` Risk**:
   - **Scope**: Confined to an individual candidate session or ephemeral session key.
   - **Reversibility**: 100% reversible with zero data loss (e.g., re-authentication, session resumption).
   - **Authorization**: Single `SECURITY_OFFICER` or `SUPER_ADMIN`.
   - **Verification**: Immediate automated check against Redis / session database.
2. **`MEDIUM` Risk**:
   - **Scope**: Affects a single user account across multiple sessions (e.g., candidate account disabling, invigilator credential suspension).
   - **Reversibility**: Reversible via supervisory administrative override without lasting examination integrity impact.
   - **Authorization**: Single `SECURITY_OFFICER` with documented investigative justification ($\ge 30$ chars).
   - **Verification**: Query against `users` table confirming `is_active = FALSE`.
3. **`HIGH` Risk**:
   - **Scope**: Multiple candidates, single exam centre restriction, or individual question quarantine.
   - **Reversibility**: Partially reversible; may require scoring compensation or reserve question allocation.
   - **Authorization**: **Mandatory Two-Person Control** (`SECURITY_OFFICER` request + `SUPER_ADMIN` cryptographic approval).
   - **Verification**: Dual-phase query confirming target subsystem quarantine flag and audit trail entry.
4. **`CRITICAL` Risk**:
   - **Scope**: Entire examination form, multi-centre network containment, or slot-wide operational halt.
   - **Reversibility**: Substantially irreversible; impacts exam scheduling and candidate cohort fairness.
   - **Authorization**: **Strict Two-Person Executive Control** (Two distinct `SUPER_ADMIN` principals, distinct MFA tokens, time-bounded to 15 minutes).
   - **Verification**: Independent verification engine queries multiple subsystem heads, validating complete form cessation and zero remaining active in-flight decryptions.

---

## 9. Policy Engine

The 5E Policy Engine evaluates containment requests deterministically against versioned, immutable policy specifications.

```
                          +──────────────────────────────+
                          |   Containment Request (5E)   |
                          +──────────────┬───────────────+
                                         │
                                         ▼
                     +────────────────────────────────────────+
                     |        Deterministic Evaluator         |
                     |                                        |
                     | Inputs:                                |
                     | 1. Incident Status == 'INVESTIGATING'  |
                     | 2. Incident Generation == Current OPEN |
                     | 3. Rule Confidence >= Policy Threshold |
                     | 4. Requester Role in Permitted Roles   |
                     | 5. Target Scope <= Max Blast Radius    |
                     | 6. Cooldown Period Expired             |
                     | 7. Target Not In Protected Allowlist   |
                     +───────────────────┬────────────────────+
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 ▼                                               ▼
         [All Rules Satisfied]                           [Rule Discrepancy]
                 │                                               │
                 ▼                                               ▼
+──────────────────────────────────+           +──────────────────────────────────+
| Decision:                        |           | Decision:                        |
| - ALLOW (Low/Med risk)           |           | - DENY (Policy Violation)        |
| - REQUIRE_SECOND_AUTHORIZER      |           | - REQUIRE_ADDITIONAL_EVIDENCE    |
|   (High/Critical risk)           |           | - CONFLICT (Incompatible Target) |
+──────────────────────────────────+           | - EXPIRED (Stale Generation)     |
                                               +──────────────────────────────────+
```

### Evaluation Invariants:
1. **Incident State Precondition**: Containment can only be requested for incidents in `INVESTIGATING` status. Requests for incidents in `TRIAGE`, `CONTAINED`, `RESOLVED`, `CLOSED`, `FALSE_POSITIVE`, or `DUPLICATE` are rejected with `DENY_INVALID_INCIDENT_STATE`.
2. **Generation Binding**: The policy engine verifies that `request.incident_generation == incident.generation` AND `incident.correlation_status == 'OPEN'`. If the generation has rolled over, the decision is strictly `EXPIRED_STALE_GENERATION`.
3. **Blast Radius Enforcer**: If the requested target scope exceeds the policy-configured maximum for the rule/incident severity (e.g. attempting to quarantine all questions for an alert with severity `LOW`), the engine returns `DENY_BLAST_RADIUS_EXCEEDED`.
4. **Target Allowlist**: Critical administrative accounts, root audit workers, and designated emergency infrastructure IPs are permanently allowlisted against containment execution (`DENY_TARGET_ALLOWLISTED`).
5. **Cooldown & Rate-Limiting**: Prevents rapid re-triggering of containment against the same target within a 300-second window unless explicitly escalated (`DENY_COOLDOWN_ACTIVE`).

### Policy Versioning:
- Policies are stored with unique, monotonically increasing version numbers (`policy_id`, `policy_version`, e.g., `POL-CONTAIN-2026-v01`).
- Every evaluation produces a cryptographic record containing:
  $$\text{EvaluationHash} = \text{SHA-256}(\text{PolicyID} \parallel \text{PolicyVersion} \parallel \text{IncidentID} \parallel \text{Generation} \parallel \text{Action} \parallel \text{Decision})$$
- Once a policy version has been used in an evaluation, its configuration is permanently immutable.

---

## 10. Authorization Model

Authorization in 5E strictly separates authentication, policy eligibility, and execution authority:

```
[Valid Credentials (MFA)]  -->  AUTHENTICATION
                                      │
[Role in RBAC Matrix]     -->  POLICY ELIGIBILITY
                                      │
[Evaluator Returns ALLOW] -->  POLICY AUTHORIZATION
                                      │
[Dual Signature Signed]   -->  EXECUTION AUTHORITY
```

### Separation of Duties Matrix:

| Operational Action | `SECURITY_OFFICER` | `SUPER_ADMIN` | System Worker | `AUDITOR` | `CANDIDATE` |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Request Containment** (`LOW` / `MEDIUM`) | **ALLOW** | **ALLOW** | DENY | DENY | DENY |
| **Request Containment** (`HIGH` / `CRITICAL`)| **ALLOW** | **ALLOW** | DENY | DENY | DENY |
| **Approve 2nd Authorizer** (`HIGH`) | DENY | **ALLOW** | DENY | DENY | DENY |
| **Approve 2nd Authorizer** (`CRITICAL`) | DENY | **ALLOW** (Distinct) | DENY | DENY | DENY |
| **Execute Containment Adapter** | System/Engine | System/Engine | System/Engine | DENY | DENY |
| **Execute Verification Query** | Verifier Engine | Verifier Engine | Verifier Engine| Read-Only | DENY |
| **Abort / Cancel Containment** | **ALLOW** (Pre-Exec)| **ALLOW** | DENY | DENY | DENY |
| **Initiate Rollback / Reversal** | Request Only | **ALLOW** | DENY | DENY | DENY |

### Authorization Freshness:
- Authorizations are granted a maximum Time-To-Live of **300 seconds (5 minutes)**.
- If an authorized request is not executed within 300 seconds, it transitions to `EXPIRED`. Re-execution requires fresh policy re-evaluation and fresh signatures.

---

## 11. Two-Person Control

Two-Person Control (Dual Authorization) is mathematically enforced for all `HIGH` and `CRITICAL` containment actions.

### Protocol Specification:
1. **Initiation**: Requester $P_1$ (`SECURITY_OFFICER` or `SUPER_ADMIN`) submits containment request $R$.
2. **Challenge Construction**:
   $$\text{AuthChallenge} = \text{SHA-256}(R.\text{id} \parallel R.\text{threat\_vector\_key} \parallel R.\text{generation} \parallel R.\text{action} \parallel R.\text{target\_id} \parallel R.\text{policy\_version} \parallel \text{nonce})$$
3. **First Authorization**: $P_1$ signs $\text{AuthChallenge}$ with session token + MFA challenge, generating $\text{Sig}_1$.
4. **Second Authorization Dispatch**: Request enters state `AWAITING_SECOND_AUTHORIZATION`. An audit alert is dispatched to all eligible second approvers.
5. **Approval Validation**: Second Approver $P_2$ reviews the evidence dossier, policy decision, and action parameters.
6. **Second Authorization**: $P_2$ signs $\text{AuthChallenge}$, generating $\text{Sig}_2$.
7. **Strict Non-Identity Constraint**:
   $$\text{Assert}(P_1.\text{principal\_id} \neq P_2.\text{principal\_id})$$
   $$\text{Assert}(P_1.\text{session\_id} \neq P_2.\text{session\_id})$$
   $$\text{Assert}(P_1.\text{ip\_address} \neq P_2.\text{ip\_address} \lor \text{PermittedProxyNet})$$
   If $P_1 == P_2$, the engine raises `DualControlSelfApprovalError` and revokes the request.

### Emergency Override Conditions (Strictly Constrained):
- Can `SUPER_ADMIN` ever bypass two-person control?
  - **LOW / MEDIUM**: Already single-authorizer by design.
  - **HIGH**: A single `SUPER_ADMIN` may invoke `EMERGENCY_OVERRIDE` **only** if:
    1. Active active-exam mode is `LIVE_CRITICAL_WINDOW`.
    2. No second authorizer has responded within 120 seconds.
    3. The action blast radius is strictly constrained to a single candidate or single exam centre.
    4. An immediate `CONTAINMENT_EMERGENCY_OVERRIDE` audit event is logged with risk score 1.0.
    5. A mandatory automated retrospective review ticket is dispatched to the Executive Examination Board.
  - **CRITICAL**: **Zero bypass permitted.** Two-person control is inviolable for `CRITICAL` risk actions under all circumstances.

---

## 12. Containment Request Model

The conceptual containment request model establishes an immutable, tamper-evident contract binding the incident context to the execution outcome:

```sql
-- Conceptual Schema (Architecture Specification Only — No Migration Generated)
CREATE TABLE containment_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_number VARCHAR(64) UNIQUE NOT NULL,       -- REQ-YYYYMMDD-XXXXXX
    incident_id UUID NOT NULL,                       -- FK to security_incidents.id
    incident_generation INTEGER NOT NULL,            -- Bound to specific 5D generation
    threat_vector_key VARCHAR(64) NOT NULL,          -- Bound to RFC 8785 threat key
    action_type VARCHAR(64) NOT NULL,                -- Enum: ACT_CAND_SESSION_TERM, etc.
    risk_level VARCHAR(32) NOT NULL,                 -- LOW, MEDIUM, HIGH, CRITICAL
    target_type VARCHAR(64) NOT NULL,                -- SESSION, USER, QUESTION, CENTRE, FORM
    target_id VARCHAR(128) NOT NULL,                 -- Canonical target identifier
    target_scope_json JSONB NOT NULL,                -- Bounded scope details
    idempotency_key VARCHAR(128) UNIQUE NOT NULL,    -- Deterministic idempotency hash
    
    -- Policy Binding
    policy_id VARCHAR(64) NOT NULL,
    policy_version VARCHAR(32) NOT NULL,
    policy_decision VARCHAR(32) NOT NULL,            -- ALLOW, REQUIRE_SECOND_AUTHORIZER
    policy_evaluation_hash VARCHAR(64) NOT NULL,
    
    -- State Machine
    status VARCHAR(32) NOT NULL,                     -- REQUESTED, AUTHORIZED, EXECUTED, VERIFIED...
    
    -- Two-Person Authorization Binding
    requester_id UUID NOT NULL,                      -- FK to users.id
    requester_role VARCHAR(32) NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL,
    approver_id UUID,                                -- FK to users.id (Distinct for Dual Control)
    approver_role VARCHAR(32),
    authorized_at TIMESTAMPTZ,
    authorization_signature VARCHAR(128),            -- Cryptographic binding
    authorization_expires_at TIMESTAMPTZ NOT NULL,
    
    -- Execution & Verification
    execution_started_at TIMESTAMPTZ,
    executed_at TIMESTAMPTZ,
    execution_reference VARCHAR(128),
    execution_error_code VARCHAR(64),
    
    verification_status VARCHAR(32) NOT NULL,        -- PENDING, VERIFIED, FAILED, INCONCLUSIVE
    verified_at TIMESTAMPTZ,
    verification_reference VARCHAR(128),
    verifier_id VARCHAR(64) NOT NULL,
    
    -- Audit References
    audit_event_reference VARCHAR(128) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    version INTEGER NOT NULL DEFAULT 1               -- Optimistic Concurrency Control
);
```

### Security Justification for Mandatory Fields:
- `incident_generation`: Strictly prevents an action authorized for Generation 1 from executing against Generation 2 following an inactivity rollover.
- `threat_vector_key`: Prevents confused-deputy redirection where an authorized action for threat $K_1$ is re-targeted to threat $K_2$.
- `idempotency_key`: Prevents replay and duplicate execution under network retries.
- `policy_evaluation_hash`: Guarantees non-repudiation of the exact policy rules that authorized containment.

---

## 13. Scope & Blast Radius

To prevent catastrophic escalation, every containment action must declare a formal scope object:

```json
{
  "target_type": "CANDIDATE_SESSION",
  "target_id": "sess_8f9a2b1c",
  "exam_id": "EXAM-2026-GATE-CSE",
  "centre_id": "CENTRE-DEL-042",
  "max_allowed_entities": 1,
  "wildcard_permitted": false
}
```

### Blast Radius Invariants:
1. **No Wildcard Targets**: `target_id = "*"` or `target_id = "ALL"` is strictly rejected by the parser for all `LOW`, `MEDIUM`, and `HIGH` actions.
2. **Exam Isolation**: Containment requests targeting an entity in Exam $A$ are cryptographically and logically prohibited from matching entities in Exam $B$ (`ck_containment_exam_isolation`).
3. **Escalation Firewall**:
   - If an analyst attempts to submit 5 individual `ACT_CAND_SESSION_TERM` requests for the same examination centre within 60 seconds, the rate-limiter flags a **Blast Radius Anomaly**.
   - Further individual requests are blocked; the policy engine mandates escalating to `ACT_CENTRE_RESTRICT` requiring Two-Person Control.

---

## 14. Idempotency & Replay Protection

Containment operations must be strictly idempotent:

### Canonical Idempotency Key Formulation:
$$\text{IdempotencyKey} = \text{SHA-256}(\text{IncidentID} \parallel \text{Generation} \parallel \text{ActionType} \parallel \text{TargetID} \parallel \text{RequesterID})$$

### Replay Defense Protocol:
1. When a containment request arrives, the system attempts to acquire an advisory lock on $\text{IdempotencyKey}$.
2. The database is checked for an existing record matching `idempotency_key`:
   - **Case A (Request In-Flight / `EXECUTING`)**: Subsequent requests block until the advisory lock releases, then return the existing execution state. No duplicate mutation occurs.
   - **Case B (Request Already `EXECUTED` or `VERIFIED`)**: Returns the existing result and verification proof immediately with HTTP `200 OK` (Idempotent Success). Zero re-execution.
   - **Case C (Request `FAILED` / Retryable)**: Permits retry **only if** `failure_is_retryable == TRUE` and authorization has not expired.
   - **Case D (Request `EXPIRED` or `CANCELLED`)**: Permanently rejects execution. Mandates creating a new request with fresh policy evaluation.

---

## 15. Execution State Machine

```
                              [SUBMIT REQUEST]
                                      │
                                      ▼
                                 (REQUESTED)
                                      │
                         [Deterministic Policy Eval]
                                      │
                    ┌─────────────────┴─────────────────┐
                    ▼                                   ▼
             (POLICY_DENIED)                   (POLICY_EVALUATED)
                    │                                   │
              [Terminated]              ┌───────────────┴───────────────┐
                                        ▼                               ▼
                                  [Risk <= MED]                  [Risk >= HIGH]
                                        │                               │
                                        │                     (AWAITING_SECOND_AUTH)
                                        │                               │
                                        │                 ┌─────────────┴─────────────┐
                                        │                 ▼                           ▼
                                        │          (AUTH_REJECTED)               (AUTHORIZED)
                                        │                 │                           │
                                        ▼                 ▼                           │
                                   (AUTHORIZED) <─────────┴───────────────────────────┘
                                        │
                           [Acquire Advisory Lock & Run]
                                        │
                                        ▼
                                   (EXECUTING)
                                        │
                         ┌──────────────┴──────────────┐
                         ▼                             ▼
                 (EXECUTION_FAILED)                (EXECUTED)
                         │                             │
                   [Fail-Closed]             [Trigger Verifier]
                                                       │
                                                       ▼
                                             (VERIFYING_PENDING)
                                                       │
                                        ┌──────────────┴──────────────┐
                                        ▼                             ▼
                                   (VERIFIED)                (VERIFICATION_FAILED)
                                        │                             │
                                  [Succeeded]                  [Alert & Rollback]
```

### State Semantics:
- `REQUESTED`: Initial ingress state.
- `POLICY_EVALUATED`: Deterministic policy evaluation passed; action is deemed eligible.
- `AWAITING_SECOND_AUTHORIZATION`: High/Critical risk action paused awaiting second principal signature.
- `AUTHORIZED`: All required authorizers have signed; freshness timer active ($<300\text{s}$).
- `EXECUTING`: Subsystem adapter actively dispatching state mutation under PostgreSQL advisory lock.
- `EXECUTED`: Subsystem adapter reports successful dispatch; pending independent confirmation.
- `VERIFYING_PENDING`: Verification engine actively querying authoritative target data source.
- `VERIFIED`: Out-of-band query confirmed target state matches containment invariants. **Terminal Success.**
- `VERIFICATION_FAILED`: Target state does not reflect containment. Triggers immediate security incident escalation and compensating rollback.
- `EXECUTION_FAILED`: Subsystem adapter failed to execute. Safe fail-closed handling applied.
- `CANCELLED`: Explicitly aborted by authorized supervisory principal prior to execution.
- `EXPIRED`: Freshness window ($300\text{s}$) lapsed prior to execution.

---

## 16. Independent Verification

Verification in 5E is **strictly decoupled** from execution. The subsystem adapter that performs the containment cannot act as its own verifier.

### Verification Matrix by Action:

| Action Category | Target Subsystem | Execution Adapter Action | Independent Verification Source & Invariant |
| :--- | :--- | :--- | :--- |
| **Candidate Session** | Session Store (Redis / DB) | Deletes JWT session mapping; flags session revoked. | Verifier queries `candidate_sessions` directly: asserts `session_status == 'REVOKED'` and Redis token key returns `NIL`. |
| **User Account** | Authentication Database | Sets `users.is_active = FALSE`. | Verifier queries `users` table with read-committed snapshot: asserts `is_active == FALSE` and active token count == 0. |
| **Exam Centre** | Centre Gateway Dispatcher | Flags centre routing table to `RESTRICTED`. | Verifier issues mock heartbeat ping to centre gateway endpoint: asserts HTTP `403 Centre Operations Suspended`. |
| **Question Object** | Exam Delivery Engine / Pool| Sets `question_pool.is_quarantined = TRUE`.| Verifier inspects delivery engine active item manifest: asserts `question_id` absent from active form allocation queue. |
| **Exam Form** | Blueprint Allocator | Marks form status to `FORM_SUSPENDED`. | Verifier queries candidate allocation table: asserts zero candidate slots assigned to form post-timestamp $t_{\text{contain}}$. |

### Verification Proof Object:
Every verification produces an immutable verification evidence link logged to 5D:
$$\text{Proof} = \{ \text{RequestID}, \text{TargetID}, \text{VerifierID}, \text{ObservedState}, \text{ExpectedState}, \text{Timestamp}, \text{SourceHash} \}$$

---

## 17. Failure Semantics

To prevent security compromises caused by partial failures, 5E enforces strict fail-safe rules:

1. **Missing Execution Response $\neq$ Success**: If an execution adapter times out or disconnects, the request status transitions to `EXECUTION_FAILED` (or `VERIFYING_PENDING` if partial mutation suspected). It is **never** assumed to have succeeded.
2. **Policy Engine Unavailable**: Defaults to `DENY`. Containment requests cannot proceed without an affirmative, cryptographically signed policy decision.
3. **Database Unavailable**: Execution adapters fail closed; no containment actions are dispatched if the database cannot record the pre-execution transaction.
4. **Target Subsystem Unavailable**: If the target subsystem (e.g. session store) is unreachable, the action fails with `ERR_TARGET_UNREACHABLE`. The incident remains in `INVESTIGATING` with a high-priority audit alert.
5. **Partial Execution in Batch/Composite Actions**: If an action affects multiple items and partially fails, the execution coordinator initiates immediate compensation for completed items where safe, transitions request to `FAILED_PARTIAL`, and escalates to `SUPER_ADMIN`.
6. **Audit Failure Invariant**: If `AuditService.log_security_event()` fails, the entire containment transaction is aborted and rolled back. No containment action can complete without an authoritative audit log.

---

## 18. Rollback / Compensation

Containment actions must specify an explicit rollback protocol:

```
+─────────────────────────────────────────────────────────────────────────────+
|                         Rollback Classification                             |
+-----------------------------------------------------------------------------+
| 1. REVERSIBLE:                                                              |
|    - Session Revocation  --> Candidate Re-Authentication Protocol           |
|    - Account Disabling   --> Supervisory Account Re-enablement              |
|    - Question De-assign  --> Question Pool Reinstatement                    |
|                                                                             |
| 2. PARTIALLY REVERSIBLE:                                                    |
|    - Centre Restriction  --> Lift Restriction; Extend Centre Exam SLA       |
|    - Form Suspension     --> Resume Form for Unstarted Slots; Reschedule    |
|                                                                             |
| 3. IRREVERSIBLE:                                                            |
|    - Slot Termination    --> Mandatory Re-examination Scheduling            |
|    - Form Invalidation   --> Scoring Re-standardization / Reserve Paper     |
+─────────────────────────────────────────────────────────────────────────────+
```

### Compensation Workflow:
1. Rollback strictly requires `SUPER_ADMIN` authorization.
2. A rollback generates a new `containment_request` of type `ACT_COMPENSATE_REVERSE` bound to the original `request_id`.
3. An audit event `CONTAINMENT_ROLLED_BACK` is emitted, recording the justification and original action reference.

---

## 19. Audit Integration

Phase 3C-5E integrates directly with the existing canonical `AuditService` (`backend/app/modules/audit/service.py`) without introducing secondary audit tables.

### 5E Containment Audit Event Taxonomy:

| Audit Event Type | Trigger Point | Actor ID | Resource Type | Metadata Payload Elements |
| :--- | :--- | :--- | :--- | :--- |
| `CONTAINMENT_REQUESTED` | Incident analyst initiates request | Analyst UUID | `CONTAINMENT_REQUEST` | `request_id`, `incident_id`, `generation`, `action_type`, `target_id`, `risk_level` |
| `CONTAINMENT_POLICY_EVALUATED` | Policy engine completes decision | System Worker | `CONTAINMENT_POLICY` | `request_id`, `policy_id`, `policy_version`, `decision`, `evaluation_hash` |
| `CONTAINMENT_AUTHORIZATION_REQUESTED` | Action requires second authorizer | System Worker | `CONTAINMENT_REQUEST` | `request_id`, `approver_role_required`, `expires_at` |
| `CONTAINMENT_AUTHORIZED` | Principal signs authorization | Authorizer UUID | `CONTAINMENT_REQUEST` | `request_id`, `authorizer_role`, `signature_hash`, `dual_auth_flag` |
| `CONTAINMENT_REJECTED` | Authorizer or policy rejects action | Authorizer UUID | `CONTAINMENT_REQUEST` | `request_id`, `rejection_reason_code`, `justification` |
| `CONTAINMENT_EXECUTION_STARTED` | Coordinator begins adapter dispatch| System Worker | `CONTAINMENT_EXECUTION`| `request_id`, `adapter_name`, `target_id`, `idempotency_key` |
| `CONTAINMENT_EXECUTION_SUCCEEDED` | Adapter confirms dispatch | System Worker | `CONTAINMENT_EXECUTION`| `request_id`, `adapter_response_id`, `latency_ms` |
| `CONTAINMENT_EXECUTION_FAILED` | Adapter errors or times out | System Worker | `CONTAINMENT_EXECUTION`| `request_id`, `error_code`, `error_message`, `retryable_flag` |
| `CONTAINMENT_VERIFICATION_STARTED`| Verifier begins query | Verifier Engine| `CONTAINMENT_VERIFICATION`|`request_id`, `verifier_id`, `target_source` |
| `CONTAINMENT_VERIFIED` | State verified out-of-band | Verifier Engine| `CONTAINMENT_VERIFICATION`|`request_id`, `observed_state`, `proof_hash`, `verification_latency` |
| `CONTAINMENT_VERIFICATION_FAILED` | State mismatch detected | Verifier Engine| `CONTAINMENT_VERIFICATION`|`request_id`, `observed_state`, `expected_state`, `discrepancy_code` |
| `CONTAINMENT_EXPIRED` | Authorization TTL lapsed | System Worker | `CONTAINMENT_REQUEST` | `request_id`, `ttl_seconds`, `expired_at` |
| `CONTAINMENT_CANCELLED` | Aborted prior to execution | Supervisor UUID| `CONTAINMENT_REQUEST` | `request_id`, `cancellation_reason` |
| `CONTAINMENT_ROLLBACK_REQUESTED` | Rollback initiated | Supervisor UUID| `CONTAINMENT_REQUEST` | `original_request_id`, `rollback_action`, `justification` |
| `CONTAINMENT_ROLLED_BACK` | Compensation completed & verified | System Worker | `CONTAINMENT_REQUEST` | `original_request_id`, `compensation_id`, `verified_state` |

All events are logged with `result=AuditResult.SUCCESS` (or `FAILURE` for rejections/errors), using dedicated Mode B transactions to guarantee forensic immutability.

---

## 20. Audit Sealing Interaction

Phase 3C-5E respects the cryptographic sealing architecture implemented in Phase 3C-4A and Phase 3C-4B:

1. **Immediate vs. Sealed Evidence**:
   - Immediate audit logs are inserted into `audit_logs` with cryptographic chaining (`prev_hash`, `event_hash`).
   - Insertion into `audit_logs` provides **immediate evidentiary proof**.
   - An event is **NOT sealed** until the background Sealer Worker includes it in a closed epoch block sealed by `MockKMS` (prototype) or Cloud KMS (production).
2. **Seal Verification Status in Containment**:
   - When 5E verifies containment, it updates the incident's `seal_verification_status` to `PENDING_SEAL`.
   - The observational containment fields record `audit_event_reference = log.id`.
   - When the sealer seals the epoch containing that audit log, a verification task updates the incident's `seal_verification_status` to `SEALED_VERIFIED`, recording `sealed_epoch_id` and `seal_block_hash`.
3. **Tamper Resilience**:
   - If an attacker modifies an audit row before epoch sealing, the sealer detects a hash chain break, records `SEAL_TAMPERED`, and raises a Critical System Alarm.

---

## 21. Emergency Containment

Emergency containment provides a tightly bounded operational path during acute attacks under strict safeguards:

1. **Eligibility Criteria**:
   - Only permitted during active national examination delivery hours (`EXAM_IN_PROGRESS`).
   - Threat severity must be `CRITICAL` or `HIGH` with active candidate data exfiltration or systemic question exposure detected.
2. **Permitted Actions**:
   - Limited strictly to `ACT_CAND_SESSION_TERM`, `ACT_ACCT_DISABLE`, and `ACT_Q_QUARANTINE_OBJ`.
   - **Prohibited**: Slot-wide cancellation, master key deletion, or national network shutdowns.
3. **Emergency Dual-Control Bypass Conditions**:
   - Allowed only for `HIGH` risk actions (never `CRITICAL`).
   - Requires `SUPER_ADMIN` credentials + Hardware Security Token (FIDO2/WebAuthn).
   - Emergency window expires automatically after **15 minutes**.
4. **Mandatory Post-Incident Reconciliation**:
   - Every emergency containment action automatically files an `EMERGENCY_CONTAINMENT_INCIDENT` in 5D.
   - Requires formal sign-off by the Chief Controller of Examinations within 24 hours.

---

## 22. Threat Model

A comprehensive threat analysis was conducted covering 25 distinct threat vectors:

| # | Threat Vector | Attack Path | Preventive Control | Detective Control | Recovery / Containment | Residual Risk |
| :- | :--- | :--- | :--- | :--- | :--- | :--- |
| **T01** | Compromised Analyst Account | Attacker uses stolen analyst credentials to trigger malicious mass containment. | RBAC restricts analyst to LOW/MED; max 1 session per action; blast radius limits. | Anomaly detection on analyst request frequency; session IP tracking. | Rapid credential revocation via 5E; rollback of affected sessions. | LOW |
| **T02** | Compromised `SUPER_ADMIN` | Attacker compromises a single super-admin to disrupt examinations. | High/Critical actions require Two-Person Control (distinct second super-admin). | Real-time dual-authorization alerts to executive channels. | Immediate emergency break-glass lock; second authorizer denies request. | LOW-MEDIUM |
| **T03** | Compromised Detection Rule | Malicious or buggy rule in 5C generates floods of false alarms. | 5C rules cannot execute containment; all actions pass through 5E policy engine. | Policy engine flags rule anomaly; rate-limits rule-triggered requests. | Quarantine detection rule; dismiss false incidents as `FALSE_POSITIVE`. | LOW |
| **T04** | Malicious Insider (Invigilator) | Corrupt invigilator attempts to terminate sessions of specific candidates. | Invigilators have ZERO containment permissions in RBAC matrix. | API authorization reject logged to `audit_logs` as `UNAUTHORIZED_ATTEMPT`. | Account disabled; proctor re-assigned. | NEGLIGIBLE |
| **T05** | Stolen Session Token | Attacker replays stolen bearer token to execute containment. | Tokens bound to IP/Device fingerprint; strict 300s TTL on containment tokens. | AuditService logs token hash and IP; flags geographic teleportation. | Invalidate token via `ACT_ACCT_TOKEN_REVOKE`. | LOW |
| **T06** | Replayed Authorization | Attacker captures a valid authorizer signature and resubmits it. | Request nonce + expiration timestamp + unique constraint on `idempotency_key`. | Database unique violation error on re-submission. | Replayed request rejected with HTTP 409 Conflict. | NEGLIGIBLE |
| **T07** | Duplicate Containment Request | Network retry sends identical execution command twice. | Idempotency key checked under advisory lock; returns cached verified result. | Execution coordinator logs duplicate request metric. | Zero duplicate destructive execution. | NEGLIGIBLE |
| **T08** | Confused Deputy Attack | Attacker tricks containment service into mutating an unauthorized subsystem. | Execution adapters accept only strongly typed target IDs verified against policy. | Policy engine verifies target belongs to incident context. | Reject mismatched target with `ERR_TARGET_DISCREPANCY`. | LOW |
| **T09** | Privilege Escalation | User elevates from `SECURITY_OFFICER` to `SUPER_ADMIN` via parameter tampering. | Role validated from cryptographically verified server-side JWT session context. | Role mismatch check against database `users` record. | Reject request; revoke user session immediately. | NEGLIGIBLE |
| **T10** | TOCTOU Race Condition | Target status changes between policy evaluation and execution. | PostgreSQL row-level `FOR UPDATE` lock on target + advisory lock during execution. | Version check in atomic update query. | Rollback if version mismatch detected; retry evaluation. | LOW |
| **T11** | Stale Policy Decision | Request authorized under Policy v1 is executed after Policy v2 revokes it. | Coordinator verifies policy version remains active prior to adapter dispatch. | Policy engine checks active policy catalog version. | Expire request with `ERR_POLICY_SUPERSEDED`. | LOW |
| **T12** | Stale Incident Generation | Request authorized for Gen 1 executes against Gen 2 after rollover. | Request strictly binds `incident_generation == incident.generation`. | Query checks `incident.correlation_status == 'OPEN'`. | Reject execution with `EXPIRED_STALE_GENERATION`. | NEGLIGIBLE |
| **T13** | Target Substitution | Attacker alters target ID in transit between authorizer and executor. | Authorizer signature signs canonical hash of `(TargetID || Action || Scope)`. | Coordinator recomputes hash and validates against authorizer signature. | Signature mismatch raises `CryptographicIntegrityError`. | NEGLIGIBLE |
| **T14** | Blast-Radius Escalation | Action intended for 1 candidate escalates to centre-wide shutdown. | Strict scope parser rejects wildcards; max entity thresholds enforced by policy. | Evaluator compares requested entity count with policy ceiling. | Reject with `DENY_BLAST_RADIUS_EXCEEDED`. | NEGLIGIBLE |
| **T15** | Executor Compromise | Execution adapter compromised; lies about execution success. | Decoupled independent verification queries target data source out-of-band. | Verifier detects target state mismatch; raises `VERIFICATION_FAILED`. | Quarantine adapter; trigger manual incident review. | LOW |
| **T16** | Verifier Compromise | Verifier compromised; falsely claims non-executed action succeeded. | Verifier must produce cryptographic proof referencing authoritative DB state. | Cross-check during epoch sealing and audit log verification. | Independent audit trail flags inconsistency. | LOW |
| **T17** | Audit Tampering | Attacker deletes containment audit log to hide unauthorized action. | Immutability triggers block UPDATE/DELETE on `audit_logs`; hash chain breaks. | Sealer detects broken hash chain; raises Critical System Alarm. | Database restore from write-once replica. | NEGLIGIBLE |
| **T18** | Database Rollback Inconsistency| DB transaction rolls back after external API call succeeded. | Two-phase dispatch: external adapter execution occurs only upon DB commit. | Reconciliation worker checks pending execution tokens. | Compensating reverse action dispatched if uncommitted. | LOW |
| **T19** | Network Partition | Network splits between coordinator and subsystem adapter during execution. | Fail-closed state: transitions to `VERIFYING_PENDING` with timeout. | Verifier checks target state; determines if action landed or failed. | Safe retry or manual operator escalation. | LOW-MEDIUM |
| **T20** | Partial Containment | 3 of 10 targeted sessions terminated before executor crashed. | Coordinator tracks sub-item execution manifests atomically. | Verifier checks each sub-target individually. | Re-dispatch remaining items under idempotent retry. | LOW |
| **T21** | Emergency Override Abuse | Malicious super-admin uses emergency bypass to evade dual control. | Emergency mode restricted to live exam hours; logs risk 1.0 alert; triggers audit. | Real-time notification dispatched to Examination Board members. | Post-incident board review; legal accountability. | LOW |
| **T22** | Denial of Service on Engine | Attacker floods 5E with fake containment requests to exhaust resources. | Ingress rate limiting per analyst/IP; async task queuing; DB connection pools. | Prometheus metrics track queue depth and rejection rate. | Rate-limit offending principal; preserve engine capacity. | LOW |
| **T23** | Authorization Collision | Two analysts approve conflicting actions for the same incident simultaneously. | PostgreSQL transaction-scoped advisory lock on `incident_id`. | Second transaction detects conflicting in-flight action. | Second request rejected with `409 Conflict`. | NEGLIGIBLE |
| **T24** | Cross-Exam Containment | Threat in Exam A causes containment of question belonging to Exam B. | Explicit `exam_id` partitioning across all target lookups and database queries. | Policy engine verifies target belongs to incident's `exam_id`. | Reject cross-exam targets with `ERR_CROSS_EXAM_VIOLATION`.| NEGLIGIBLE |
| **T25** | Cross-Tenant Scope Leak | Multi-organization deployment leaks containment across organizational boundaries.| Tenant UUID bound to every request, policy, and subsystem query. | SQL queries enforce `tenant_id = :current_tenant`. | Cross-tenant requests fail with `404 Not Found`. | NEGLIGIBLE |

---

## 23. Zero-Trust Controls

To satisfy the Zero-Trust mandate, containment execution verifies the **11 Dimensions of Authority** before any state mutation:

1. **WHO**: Authenticated principal ID and cryptographically verified role.
2. **WHAT**: Exact containment action identifier from the approved catalogue.
3. **WHY**: Associated 5D incident ID and documented investigative justification.
4. **WHICH INCIDENT**: Explicit foreign key binding to `security_incidents.id`.
5. **WHICH GENERATION**: Monotonic generation integer matching `security_incidents.generation`.
6. **WHICH ACTION**: Exact action type matching policy capability.
7. **WHICH TARGET**: Fully qualified canonical target reference (e.g. `urn:bsea:session:sess_123`).
8. **WHICH POLICY**: Immutable `policy_id` and `policy_version`.
9. **WHICH AUTHORIZATION**: Single or dual cryptographic signatures with non-identical authorizers.
10. **WHEN**: Authorization timestamp verified within the 300-second freshness window.
11. **UNDER WHAT CONTEXT**: Active examination slot status and centre operational state.

---

## 24. Cryptographic Controls

### Algorithms & Primitives:
- **Hashing**: SHA-256 for all canonical envelopes, request hashes, challenges, and idempotency keys.
- **Canonical Serialization**: RFC 8785 JSON Canonicalization Scheme (JCS) with UTF-8 encoding.
- **Digital Signatures**: Ed25519 (or ECDSA P-256) for authorizer approvals and verification proofs.
- **Key Storage**:
  - *Prototype*: Software-backed `MockKMS` simulating KMS asymmetric signing and CMK operations.
  - *Production*: Dedicated AWS KMS Asymmetric Signing Key (`KMS_CONTAINMENT_SIGNING_KEY_ARN`) with IAM least-privilege policy.

---

## 25. Prototype vs. Production Classification

| Architecture Component | Phase 3C Prototype Implementation | Production Target Requirement | Production Gap / Risk Mitigation |
| :--- | :--- | :--- | :--- |
| **KMS / Cryptographic Keys** | Software `MockKMS` in-memory mock. | AWS KMS multi-region CMK / Dedicated FIPS 140-2 Level 3 HSM. | Prototype validates signing protocol; production requires hardware tamper resistance. |
| **Worker Execution** | In-process asynchronous tasks (`asyncio`). | Distributed durable queue workers (AWS SQS FIFO + Celery/Temporal). | Prototype validates state transitions; production requires queue durability across host crashes. |
| **Session State Store** | Local PostgreSQL database tables. | Distributed In-Memory Key-Value Store (Amazon ElastiCache Redis Cluster). | Redis cluster required in production for sub-millisecond session invalidation at scale. |
| **Database Concurrency** | PostgreSQL 16 on local single instance. | Multi-AZ Amazon RDS PostgreSQL with read replicas and automated failover. | Prototype tests advisory locks; multi-AZ requires connection drain verification. |
| **Centre Gateway Control** | Mock HTTP adapter returning simulated status codes. | Mutual TLS (mTLS) outbound API gateway to on-premise centre server. | Production requires hardware mTLS client certificates on centre servers. |
| **Certification & Compliance** | Prototype verification. | STQC, CERT-In, and ISO 27001 formal security certification audits. | Formal external third-party penetration testing required prior to national rollout. |

---

## 26. Data Model Proposal

The 5E data model introduces 4 dedicated conceptual entities while strictly reusing 5D and 5A:

```
+──────────────────────────+       1:N       +──────────────────────────+
|    ContainmentPolicy     |────────────────>|    ContainmentRequest    |
| - policy_id (PK)         |                 | - id (PK)                |
| - policy_version         |                 | - incident_id (FK -> 5D) |
| - policy_rules_json      |                 | - idempotency_key (UQ)   |
+──────────────────────────+                 | - status                 |
                                             +────────────┬─────────────+
                                                          │ 1:1
                                                          ▼
+──────────────────────────+       1:1       +──────────────────────────+
| ContainmentVerification  |<────────────────|   ContainmentExecution   |
| - id (PK)                |                 | - id (PK)                |
| - request_id (FK)        |                 | - request_id (FK)        |
| - observed_state         |                 | - adapter_name           |
| - verification_status    |                 | - executed_at            |
+──────────────────────────+                 +──────────────────────────+
```

### Proposed Schema Attributes:
1. **`containment_policies`**: Stores immutable versioned rule sets defining risk levels, blast radius limits, and dual-control requirements.
2. **`containment_requests`**: Central coordination record tracking the request from ingress to resolution, binding incident generation and authorization signatures.
3. **`containment_executions`**: Audit record of the adapter dispatch, execution latency, and raw subsystem response.
4. **`containment_verifications`**: Independent verification proof, documenting out-of-band checks and state proofs.

---

## 27. API Boundary Proposal (Conceptual)

All endpoints are conceptual specifications for implementation planning. **No endpoints are implemented in Rev-01.**

```
POST   /api/v1/containment/requests
       Caller: SECURITY_OFFICER, SUPER_ADMIN
       Input:  { incident_id, action_type, target_type, target_id, scope, justification }
       Output: { request_id, status: "AWAITING_AUTHORIZATION", policy_decision, expires_at }
       Audit:  CONTAINMENT_REQUESTED, CONTAINMENT_POLICY_EVALUATED

POST   /api/v1/containment/requests/{request_id}/authorize
       Caller: SUPER_ADMIN (Distinct Principal)
       Input:  { authorization_signature, mfa_token, justification }
       Output: { request_id, status: "AUTHORIZED", authorized_at }
       Audit:  CONTAINMENT_AUTHORIZED

POST   /api/v1/containment/requests/{request_id}/execute
       Caller: Internal Execution Coordinator Worker
       Input:  { request_id, idempotency_key }
       Output: { request_id, status: "EXECUTED", execution_reference }
       Audit:  CONTAINMENT_EXECUTION_STARTED, CONTAINMENT_EXECUTION_SUCCEEDED

POST   /api/v1/containment/requests/{request_id}/verify
       Caller: Independent Verification Worker
       Input:  { request_id }
       Output: { request_id, verification_status: "VERIFIED", proof }
       Audit:  CONTAINMENT_VERIFICATION_STARTED, CONTAINMENT_VERIFIED

POST   /api/v1/containment/requests/{request_id}/cancel
       Caller: SUPER_ADMIN
       Input:  { request_id, cancellation_reason }
       Output: { request_id, status: "CANCELLED" }
       Audit:  CONTAINMENT_CANCELLED
```

---

## 28. Observability & Telemetry

Containment observability is implemented via Prometheus metrics and structured audit logging with **zero sensitive candidate data exposure**:

### Bounded Prometheus Metrics:
- `bsea_containment_requests_total{action, risk_level, status}`: Counter of all requests.
- `bsea_containment_policy_evaluations_total{decision}`: Counter of policy decisions.
- `bsea_containment_authorization_latency_seconds`: Histogram of time from request to dual authorization.
- `bsea_containment_execution_duration_seconds{adapter}`: Histogram of adapter execution time.
- `bsea_containment_verification_failures_total{target_type}`: Counter of verification discrepancies.
- `bsea_containment_emergency_overrides_total`: Counter of emergency single-superadmin bypasses.
- `bsea_containment_blast_radius_violations_total`: Counter of scope firewall blocks.

---

## 29. Architecture Test Strategy

The implementation test matrix must validate all 5E security invariants prior to code acceptance:

| Test ID | Test Category | Scenario & Invariant Under Test | Expected Outcome |
| :--- | :--- | :--- | :--- |
| `TC-5E-01` | Policy Engine | Submit request with incident in `TRIAGE` status. | Policy rejects with `DENY_INVALID_INCIDENT_STATE`. |
| `TC-5E-02` | Policy Engine | Request blast radius exceeding allowed entity threshold. | Policy rejects with `DENY_BLAST_RADIUS_EXCEEDED`. |
| `TC-5E-03` | Two-Person Control | Requester attempts to sign as second authorizer for `HIGH` action. | Engine raises `DualControlSelfApprovalError`. |
| `TC-5E-04` | Two-Person Control | Authorized request executed after 301 seconds (TTL expired). | Coordinator rejects with `ERR_AUTHORIZATION_EXPIRED`. |
| `TC-5E-05` | Generation Binding | Request authorized on Gen 1 executed after Gen 2 rollover. | Coordinator rejects with `EXPIRED_STALE_GENERATION`. |
| `TC-5E-06` | Idempotency | Parallel concurrent execution calls with identical `idempotency_key`.| Advisory lock serializes; exactly 1 execution; 2nd returns cached result. |
| `TC-5E-07` | Target Discrepancy | Target ID altered between authorization signature and execution. | Cryptographic verification fails; raises `IntegrityError`. |
| `TC-5E-08` | Scope Isolation | Containment request for Exam A attempts to target candidate in Exam B. | Subsystem adapter rejects with `ERR_CROSS_EXAM_VIOLATION`. |
| `TC-5E-09` | Verification Engine | Subsystem adapter reports success, but DB record remains active. | Verifier detects mismatch; transitions to `VERIFICATION_FAILED`. |
| `TC-5E-10` | Fail-Closed | Subsystem adapter throws timeout / network disconnect. | Status set to `EXECUTION_FAILED`; no partial success presumed. |
| `TC-5E-11` | Audit Integration | Simulated DB failure during `log_security_event()`. | Containment transaction aborts; zero state mutation. |
| `TC-5E-12` | Rollback | Rollback dispatched for reversible session invalidation. | Compensating re-login permitted; `CONTAINMENT_ROLLED_BACK` logged. |

---

## 30. 5D / 5E / 5F Responsibility Matrix

```
+──────────────────────────────────+──────────────────────────────────+──────────────────────────────────+
| Phase 3C-5D                      | Phase 3C-5E                      | Phase 3C-5F                      |
| Incident Management Foundation   | Policy-Governed Containment      | Enterprise SIEM / SOC            |
+──────────────────────────────────+──────────────────────────────────+──────────────────────────────────+
| - Threat Vector Identity (JCS)   | - Containment Policy Catalog     | - Syslog / CEF Event Forwarding  |
| - Correlation Rollover (3600s)   | - Risk Level Classification      | - Splunk / Elastic Connectors    |
| - Monotonic Generations          | - Two-Person Dual Authorization  | - External SOC Webhook Alerts    |
| - 7-State Lifecycle Machine      | - Idempotent Execution Adapters  | - Multi-tenant SIEM Dashboards   |
| - Observational CONTAINED State  | - Independent Verification Engine| - Threat Intelligence Ingestion  |
| - Append-Only Links & Comments   | - Fail-Safe Compensation Controls| - Cross-Institution Correlation  |
| - Canonical Audit Logging        | - Containment Telemetry Metrics  | - Regulatory Reporting Feeds     |
+──────────────────────────────────+──────────────────────────────────+──────────────────────────────────+
```

---

## 31. Open Questions

The following architectural questions are catalogued for stakeholder review:
1. **Psychometric Compensation for In-Flight Question Quarantine**: When an active question object is quarantined mid-exam (`ACT_Q_QUARANTINE_OBJ`), should the scoring engine automatically re-weight remaining questions, or dynamically substitute from a pre-decrypted reserve pool? *(Recommendation: Reserve question dynamic substitution via candidate client sync protocol).*
2. **Offline Exam Centre Protocol**: If an exam centre experiences a total Internet disconnection, how should local containment policies be enforced? *(Recommendation: On-premise offline policy cache with local hardware token validation).*
3. **Emergency Single-SuperAdmin Threshold**: Should single-superadmin emergency override be completely prohibited even during live examination hours? *(Recommendation: Prohibit for CRITICAL actions; allow for HIGH actions strictly with 120s timer and automatic retrospective Board notification).*

---

## 32. Architecture Invariants

The following invariants are binding and inviolable:
1. **No Autonomous Destructive Execution**: Detection rules (5C) and incident correlation (5D) can never directly execute containment actions.
2. **Inviolable Dual Control**: No single human principal or service account can satisfy both sides of a required Two-Person Control authorization.
3. **Strict Generation Binding**: Every containment action is cryptographically bound to a specific incident generation. A stale generation cannot mutate state.
4. **Authoritative Out-of-Band Verification**: Execution success can never be inferred from adapter return codes; it requires independent query proof against the target state.
5. **Fail-Closed on Ambiguity**: Any timeout, network partition, policy discrepancy, or audit error must fail safely without executing unverified mutations.
6. **Immutable Audit Provenance**: Every containment action, approval, execution, and verification must emit an authoritative audit log into `audit_logs` before transaction commit.
7. **Scope Containment Firewall**: Containment actions are mathematically bounded by their declared blast radius and cannot escalate across exams or centres.

---

## 33. Acceptance Criteria

Phase 3C-5E implementation will be accepted only when:
1. All 12 test cases in the Test Strategy (`TC-5E-01` through `TC-5E-12`) pass with genuine database and mock execution proofs.
2. The 7-state 5D lifecycle correctly reflects observational transitions to `CONTAINED` upon successful 5E verification.
3. All 15 containment audit events are logged via canonical `AuditService` and verified in `audit_logs`.
4. Two-person control genuinely rejects self-approvals under multi-user asyncpg connection tests.
5. Zero regressions occur across the existing 271 passing repository test baseline.

---

## REV-01 REVIEW REQUIREMENT

### A. Decisions Made
1. Adopted a decoupled 4-stage pipeline: Policy Evaluation $\rightarrow$ Dual Authorization $\rightarrow$ Coordinated Execution $\rightarrow$ Independent Verification.
2. Established 4 risk tiers (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), mandating Two-Person Control for `HIGH` and `CRITICAL`.
3. Bound containment requests cryptographically to the exact 5D `incident_id`, `incident_generation`, and `threat_vector_key`.
4. Defined independent verification as an out-of-band query against the authoritative target subsystem state.
5. Reused canonical `AuditService` with dedicated Mode B transactions for all 15 containment audit events.

### B. Assumptions
1. Candidate session stores (Redis or DB) support atomic key deletion and status queries.
2. National exam centres maintain sufficient outbound connectivity to receive mTLS containment directives.
3. Examination blueprints include reserve question items for in-flight question quarantine scenarios.

### C. Unresolved Questions
1. Resolution of dynamic question substitution protocol vs. scoring re-standardization during active item quarantine.
2. Confirmation of whether Single-SuperAdmin emergency override is permissible for `HIGH` risk actions during live exam hours.

### D. Security Risks
1. Risk of proctor operational confusion if sessions are suspended during active exam delivery.
2. Dependency on accurate NTP/server clock synchronization for 300-second authorization freshness windows.

### E. Recommended Rev-02 Changes
1. Formalize the reserve question psychometric substitution API contract.
2. Incorporate concrete mTLS client certificate validation workflows for on-premise centre gateways.

### F. Implementation Readiness Assessment

# ARCHITECTURE READY FOR REVIEW

The Phase 3C-5E Policy-Governed Security Containment Architecture Specification Rev-01 is complete, mathematically bounded, internally consistent, and ready for formal stakeholder and security review. **No implementation code should be written until Rev-01 receives explicit user authorization.**
