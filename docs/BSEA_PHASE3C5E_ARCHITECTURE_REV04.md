# B-SEA Phase 3C-5E: Policy-Governed Security Containment Architecture Specification
## Architecture Review Rev-04 — Final Consistency Correction & Implementation Blueprint

**Document Reference**: `BSEA-ARCH-3C5E-REV04`  
**Status**: ARCHITECTURE SPECIFICATION (FINAL ARCHITECTURE GATE / READ-ONLY)  
**Date**: 2026-09-16  
**Baseline Git Commit**: `7683dd6f8d67f5289cc8cc86da3112a8aaade6ec` (Phase 3C-5D Frozen at Revision `a1b2c3d4e5f6`)  
**Supersedes**: `docs/BSEA_PHASE3C5E_ARCHITECTURE_REV03.md`, `REV02`, and `REV01`  
**Target Subsystem**: `backend/app/modules/containment/` (Deferred to Implementation Phase)  
**Review Status**: ARCHITECTURE READY FOR IMPLEMENTATION REVIEW  

---

## Executive Summary of Rev-04 Final Consistency Corrections

Architecture Review Rev-04 represents the definitive, normative architecture specification for Phase 3C-5E (**Policy-Governed Security Containment Subsystem**) of the Bharat Secure Examination Architecture (B-SEA). It incorporates the complete architecture decisions from Rev-02 and Rev-03, and applies ONE final set of consistency corrections across all boundary layers before implementation authorization:

1. **Dual Policy Decision Pipelines (Standard vs. Emergency)**:
   - Resolves the apparent contradiction between standard dual-approval policy rules and emergency break-glass.
   - Clarifies that standard policy returning `REQUIRE_SECOND_AUTHORIZER` is **not** automatically reinterpreted as an emergency authorization. Instead, an emergency request enters a dedicated **Break-Glass Eligibility Pipeline** which evaluates emergency criteria independently to yield `BREAK_GLASS_ALLOWED` or `BREAK_GLASS_DENIED`.
2. **Decoupling Database Rollback from External Network Mutation**:
   - Eliminates any naive architectural assumption that rolling back a PostgreSQL transaction undoes an external containment mutation (such as an HTTP/gRPC command to terminate a candidate session or an external IdP account lock).
   - Strictly defines the authoritative boundary between **PostgreSQL Database Transaction Rollback** and **External Action Compensation**.
   - Formulates the exact end-to-end execution sequence and defines deterministic recovery across 8 failure boundary scenarios (definite success, definite failure, timeout, lost response, post-mutation DB failure, pre-dispatch audit failure, post-dispatch audit failure, and unavailable verification).
3. **Dynamic Baseline Test Gate Formulation (TC-GATE-21)**:
   - Removes hard-coded static numbers ("All 271 baseline tests pass") from the normative acceptance criterion.
   - Formulates a forward-compatible, dynamic regression gate: all pre-5E baseline tests continue to pass, all 5E architecture tests pass, zero unexplained regressions, zero test failures, and all skipped tests remain documented.
   - Preserves the historical 5D baseline (`276 collected, 271 passed, 5 skipped, 0 failed`) as a reference floor.
4. **Orthogonality of Incident Severity vs. Containment Action Risk**:
   - Explicitly establishes that **Incident Severity** (5D dimension) and **Containment Action Risk** (5E dimension) are independent and orthogonal.
   - A `CRITICAL` severity incident can be contained via a `LOW` or `HIGH` risk action; however, `CRITICAL` risk containment actions remain **categorically and permanently prohibited from Break-Glass**, regardless of incident severity.
5. **Rigorous Verification of `risk_score` Schema & Semantics**:
   - Formally verifies against the frozen PostgreSQL schema (`audit_logs`) that `risk_score` exists as a native `Float` column ($0.0 \le s \le 1.0$).
   - Explicitly separates **quantitative measurement** (`risk_score`) from **semantic event classification** (`event_type`), mandating that `risk_score = 1.0` is never used as a proxy for the emergency event type (`CONTAINMENT_EMERGENCY_OVERRIDE`).
6. **Bounded Execution Lease & Token Expiry Semantics**:
   - Formulates an atomic token consumption model with an explicit 60-second **Execution Lease**.
   - Token expiry prior to dispatch causes rejection; token expiry after atomic dispatch begins does **not** retroactively invalidate an active execution lease.
   - Establishes bounded deadlines for execution (60s) and independent verification (120s).
7. **Explicit Tri-State Execution & Verification Outcomes**:
   - Replaces vague "fail closed" terminology with deterministic state semantics:
     - Execution states: `EXECUTION_SUCCEEDED`, `EXECUTION_FAILED`, `EXECUTION_UNKNOWN`.
     - Verification states: `VERIFICATION_VERIFIED`, `VERIFICATION_FAILED`, `VERIFICATION_INCONCLUSIVE`.
   - Defines formal operational handling for network timeouts and inconclusive outcomes via a dedicated quarantine queue and manual Security Officer attestation.
8. **Authoritative Audit Ordering & Mode B Isolation**:
   - Establishes the exact 8-step audit sequence for containment actions, ensuring no containment action can succeed without an attributable, immutable audit trail.
   - Clearly distinguishes between transactionally coupled audit events and durable post-execution records.
9. **Final State Consistency & 7-Tier Decoupled State Architecture**:
   - Strictly separates 7 distinct operational dimensions: 5D Incident State, Containment Intent State, Containment Request State, Authorization State, Execution State, Verification State, and Break-Glass Token State.
   - Guarantees that execution failure never creates a fake 5D `RESOLVED`/`CLOSED` state.
10. **Expanded Acceptance Gate (TC-GATE-01 through TC-GATE-28)**:
    - Adds 7 targeted test scenarios (TC-GATE-22 through TC-GATE-28) covering DB rollback divergence, execution timeout ambiguity, cross-dimensional severity/risk gates, and lease expiration.
11. **Final Verdict**:
    - Concludes with the exact normative verdict: `# ARCHITECTURE READY FOR IMPLEMENTATION REVIEW`.

---

## 1. Break-Glass Policy Path & Dual Decision Pipelines

### The Core Architectural Dilemma
In Rev-03, an apparent contradiction existed:
- A `HIGH` risk action evaluated under normal policy rules returns `REQUIRE_SECOND_AUTHORIZER`, strictly requiring two distinct authorizers ($P_1 
eq P_2$).
- If an emergency Break-Glass request were to treat `REQUIRE_SECOND_AUTHORIZER` as an authorization to execute, it would create an architectural bypass that undermines policy governance.

### The Rev-04 Dual Pipeline Resolution
Rev-04 resolves this by defining two distinct, deterministic policy decision pipelines within the Policy Engine:

```
                                 [Containment Ingress]
                                           │
                        ┌──────────────────┴──────────────────┐
                        ▼                                     ▼
             [Standard Request Path]               [Emergency Break-Glass Path]
                        │                                     │
                        ▼                                     ▼
          +───────────────────────────+         +───────────────────────────+
          |   Standard Policy Engine  |         | Break-Glass Policy Engine |
          |   (Evaluates Core Rules)  |         | (Evaluates Crisis Rules)  |
          +─────────────┬─────────────+         +─────────────┬─────────────+
                        │                                     │
        ┌───────────────┼───────────────┐             ┌───────┴───────┐
        ▼               ▼               ▼             ▼               ▼
     (ALLOW)         (DENY)       (REQUIRE_SEC)  (BG_ALLOWED)    (BG_DENIED)
        │               │               │             │               │
        ▼               ▼               ▼             ▼               ▼
   Single Auth     Terminated     Dual Approver   FIDO2 Challenge  Terminated
   (LOW/MED Risk)  (Violates)     Required        Single Token     (Must Use
                                  (P1 + P2)       (60s Lease)      Dual Auth)
```

### A. Standard Policy Pipeline Decision Set
The Standard Policy Pipeline evaluates regular containment requests and yields one of four deterministic decisions:
1. `ALLOW`:
   - Permitted for `LOW` or `MEDIUM` risk actions where the target entity is within bounds and the requesting principal holds appropriate role authority (`SECURITY_OFFICER` or `SUPER_ADMIN`).
   - Single-person authorization is sufficient.
2. `DENY`:
   - Categorical rejection when the action violates policy invariants (e.g., target entity is allowlisted, incident is not in `INVESTIGATING` status, action blast radius exceeds policy thresholds, or requested action is invalid).
3. `REQUIRE_SECOND_AUTHORIZER`:
   - Returned when the requested action is classified as `HIGH` or `CRITICAL` risk and meets structural prerequisites.
   - Strictly mandates Two-Person Control: execution cannot proceed until a second, distinct authorizer ($P_2 
eq P_1$) submits a valid, cryptographic authorization signature.
4. `REQUIRE_ADDITIONAL_EVIDENCE`:
   - Returned when signal confidence, evidence hash binding, or detection vector correlation is insufficient to support the requested blast radius.

### B. Emergency Break-Glass Policy Pipeline Decision Set
When a `SUPER_ADMIN` explicitly invokes the emergency override path (indicating that acute active exfiltration is occurring and a second authorizer is physically unavailable), the request does **not** bypass policy. Instead, it is routed to the dedicated **Break-Glass Policy Engine**, which evaluates a specialized emergency policy ruleset:

1. `BREAK_GLASS_ALLOWED`:
   - Granted **only if all six emergency eligibility criteria are simultaneously satisfied**:
     1. **5D Incident State**: Incident is in status `INVESTIGATING`.
     2. **5D Incident Severity**: Incident severity is `HIGH` or `CRITICAL`.
     3. **Operational Context**: Examination window is actively live (`EXAM_IN_PROGRESS`).
     4. **Eligible Action Tier**: Requested action is within the pre-approved emergency single-entity subset:
        - `ACT_CAND_SESSION_TERM`
        - `ACT_ACCT_DISABLE`
        - `ACT_Q_PREVENT_ASSIGN`
     5. **Strict Scope Ceiling**: Target scope is strictly single-entity (`max_allowed_entities == 1`). Multi-entity or wildcard targets are categorically rejected.
     6. **Rate Limiting**: Requesting principal has not exceeded 2 break-glass actions in the past 60 minutes, and the examination slot has not exceeded 5 total break-glass actions.
   - Yielding `BREAK_GLASS_ALLOWED` authorizes the issuance of a single-use `BreakGlassToken` upon successful FIDO2 WebAuthn hardware-token verification.

2. `BREAK_GLASS_DENIED`:
   - Returned if any emergency eligibility condition fails (e.g., action is `CRITICAL` risk tier, target scope exceeds 1 entity, incident severity is `MEDIUM` or below, exam is not in progress, or rate limits are exceeded).
   - If `BREAK_GLASS_DENIED` is returned, the emergency path terminates immediately. The action **cannot** be executed without standard Two-Person dual authorization.

### Normative Invariant:
**Emergency Break-Glass NEVER reinterprets `REQUIRE_SECOND_AUTHORIZER` as automatic authorization.**  
A standard request receiving `REQUIRE_SECOND_AUTHORIZER` remains pending dual approval. An emergency break-glass request is an explicit, separately audited policy evaluation that requires independent justification, FIDO2 hardware challenge, and real-time Board notification.

---

## 2. Inviolable Dual Control on CRITICAL Actions & Blast Radius Governance

B-SEA establishes an inviolable architectural boundary: **Actions carrying catastrophic, irreversible, or cohort-wide blast radius can NEVER be authorized by a single person under any circumstances, including emergency break-glass.**

### A. The Mathematical Dual-Control Invariant
For any containment action $A$ where $	ext{RiskTier}(A) = 	ext{CRITICAL}$:
$$orall\ 	ext{Execution}(A) \implies 	ext{Principal}(P_1) 
eq 	ext{Principal}(P_2) \land 	ext{Role}(P_1) = 	ext{SUPER\_ADMIN} \land 	ext{Role}(P_2) = 	ext{SUPER\_ADMIN}$$
$$	ext{BreakGlass}(A) \equiv \mathbf{FALSE}\ (	ext{Categorically Rejection})$$

### B. Blast Radius Limits & Risk Classification
| Action Identifier | Action Name | Risk Tier | Blast Radius | Normal Authorization | Break-Glass Allowed? |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `ACT_CAND_SESSION_TERM` | Terminate Candidate Session | `LOW` | Single Candidate Session | Single Officer | **YES** (Single Auth / BG) |
| `ACT_ACCT_DISABLE` | Disable Account | `HIGH` | Single User Account | Dual Control (SecOff + SuperAdmin) | **YES** (Single SuperAdmin + BG) |
| `ACT_Q_PREVENT_ASSIGN` | Prevent Question Assignment | `HIGH` | Single Question Object | Dual Control (SecOff + SuperAdmin) | **YES** (Single SuperAdmin + BG) |
| `ACT_CENTRE_RESTRICT` | Restrict Delivery Capacity | `HIGH` | Single Physical Centre | Dual Control (SecOff + SuperAdmin) | **NO** (Dual SuperAdmin Only) |
| `ACT_FORM_SUSPEND` | Suspend Form Variant | `CRITICAL`| Entire Form Cohort | Dual SuperAdmin | **NO (CATEGORICALLY PROHIBITED)** |
| `ACT_CENTRE_SUSPEND` | Suspend Centre Operations | `CRITICAL`| Entire Centre Facility | Dual SuperAdmin | **NO (CATEGORICALLY PROHIBITED)** |
| `ACT_CRYPTO_ROT_MASTER` | Rotate Slot Master CMK | `CRITICAL`| National Slot Key | Dual SuperAdmin + CTO Signoff | **NO (CATEGORICALLY PROHIBITED)** |
| `ACT_EXAM_TERMINATE` | National Exam Termination | `DISASTER`| Entire National Exam | Statutory Board Quorum | **NO (OUT OF SCOPE / STATUTORY)** |

---

## 3. Orthogonality of Incident Severity vs. Containment Action Risk

Rev-04 explicitly decouples **Incident Severity** (evaluated by Phase 3C-5D during detection and correlation) from **Containment Action Risk** (evaluated by Phase 3C-5E during containment planning and authorization).

### The 2D Severity vs. Risk Matrix:
```
                   CONTAINMENT ACTION RISK (5E Dimension)
                      LOW           MEDIUM          HIGH           CRITICAL
                +──────────────+──────────────+──────────────+──────────────────+
       CRITICAL | Permitted    | Permitted    | Permitted    | Permitted        |
                | Single Auth  | Single Auth  | Dual Auth    | Dual SUPER_ADMIN |
                | or BG        | or BG        | or BG        | NO BREAK-GLASS   |
INCIDENT        +──────────────+──────────────+──────────────+──────────────────+
SEVERITY   HIGH | Permitted    | Permitted    | Permitted    | Permitted        |
  (5D           | Single Auth  | Single Auth  | Dual Auth    | Dual SUPER_ADMIN |
Dimension)      | or BG        | or BG        | or BG        | NO BREAK-GLASS   |
                +──────────────+──────────────+──────────────+──────────────────+
         MEDIUM | Permitted    | Permitted    | Permitted    | DENY             |
                | Single Auth  | Single Auth  | Dual Auth    | (Disproportionate|
                | NO BG        | NO BG        | NO BG        |  Blast Radius)   |
                +──────────────+──────────────+──────────────+──────────────────+
       LOW/INFO | DENY         | DENY         | DENY         | DENY             |
                | (Dispropor.) | (Dispropor.) | (Dispropor.) | (Disproportion.) |
                +──────────────+──────────────+──────────────+──────────────────+
```

### Orthogonality Invariants:
1. **High Incident Severity Does Not Dictate High Action Risk**:
   - A `CRITICAL` incident (e.g., active memory compromise on a candidate terminal) can be completely addressed by a `LOW` risk action (`ACT_CAND_SESSION_TERM` targeting that specific candidate session).
   - The containment system must always favor the lowest-risk action capable of mitigating the threat (Principle of Minimal Blast Radius).
2. **Break-Glass is Governed Exclusively by Action Risk Tier**:
   - Break-Glass eligibility is determined strictly by the risk tier of the **containment action**, never solely by incident severity.
   - A `CRITICAL` severity incident does **not** unlock break-glass for a `CRITICAL` risk action. Suspending an examination form variant (`ACT_FORM_SUSPEND`) or centre (`ACT_CENTRE_SUSPEND`) remains categorically barred from single-person break-glass, even during a crisis.

---

## 4. Normative Catalogues of Containment Actions

### A. CRITICAL Actions Catalogue
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
|                        | CONTAINMENT_EXECUTION_RESULT, CONTAINMENT_VERIFIED |
+────────────────────────+────────────────────────────────────────────────────+
| Action Identifier      | ACT_CENTRE_SUSPEND                                 |
| Action Name            | Complete Operational Suspension of Exam Centre     |
| Target Scope           | All active candidates at physical centre           |
| Max Blast Radius       | Single Examination Centre Facility                 |
| Reversibility          | IRREVERSIBLE (Requires candidate rescheduling)     |
| Normal Authorization   | Two-Person Control: Two Distinct SUPER_ADMINs       |
| Break-Glass Permitted? | NO (CATEGORICALLY PROHIBITED)                      |
| Execution Adapter      | CentreGatewayAdapter                               |
| Independent Verifier   | CentreGatewayVerifier (Asserts HTTP 403 / revoked) |
| Audit Events           | CONTAINMENT_REQUESTED, CONTAINMENT_AUTHORIZED,     |
|                        | CONTAINMENT_EXECUTION_RESULT, CONTAINMENT_VERIFIED |
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
|                        | CONTAINMENT_EXECUTION_RESULT, CONTAINMENT_VERIFIED |
+─────────────────────────────────────────────────────────────────────────────+
```

### B. HIGH Actions Catalogue
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
| Audit Events           | CONTAINMENT_REQUESTED, CONTAINMENT_AUTHORIZED,     |
|                        | CONTAINMENT_EXECUTION_RESULT, CONTAINMENT_VERIFIED |
+────────────────────────+────────────────────────────────────────────────────+
| Action Identifier      | ACT_ACCT_DISABLE                                   |
| Action Name            | Disable Compromised User Account                   |
| Target Scope           | Single Principal (Candidate / Invigilator)         |
| Max Blast Radius       | Single Account Across All Subsystems (Max 1 Entity)|
| Reversibility          | REVERSIBLE (Re-enable account via admin console)   |
| Normal Authorization   | Two-Person Control: SEC_OFFICER + SUPER_ADMIN      |
| Break-Glass Permitted? | YES (Single SUPER_ADMIN + FIDO2 Break-Glass Token) |
| Execution Adapter      | IdentityProviderAdapter                            |
| Independent Verifier   | IdentityProviderVerifier (Asserts is_active=FALSE) |
| Audit Events           | CONTAINMENT_REQUESTED, CONTAINMENT_AUTHORIZED,     |
|                        | CONTAINMENT_EXECUTION_RESULT, CONTAINMENT_VERIFIED |
+────────────────────────+────────────────────────────────────────────────────+
| Action Identifier      | ACT_CENTRE_RESTRICT                                |
| Action Name            | Restrict Centre Network Ingress / Concurrency      |
| Target Scope           | Single Centre Network Gateway                      |
| Max Blast Radius       | Single Exam Centre Network Gateway                 |
| Reversibility          | REVERSIBLE (Restore ingress threshold)             |
| Normal Authorization   | Two-Person Control: Two Distinct SUPER_ADMINs       |
| Break-Glass Permitted? | NO (Multi-candidate impact requires dual approval) |
| Execution Adapter      | CentreIngressAdapter                               |
| Independent Verifier   | CentreIngressVerifier (Asserts rate limit active)  |
| Audit Events           | CONTAINMENT_REQUESTED, CONTAINMENT_AUTHORIZED,     |
|                        | CONTAINMENT_EXECUTION_RESULT, CONTAINMENT_VERIFIED |
+─────────────────────────────────────────────────────────────────────────────+
```

---

## 5. Decoupled 4-Tier Identity Architecture

To eliminate race conditions, duplicate executions, and replay vulnerabilities, Rev-04 enforces four separate, cryptographically bound identity constructs:

```
+─────────────────────────────────────────────────────────────────────────────+
|                     4-TIER IDENTITY SEPARATION ARCHITECTURE                 |
+─────────────────────────────────────────────────────────────────────────────+
| Tier 1: Intent Identity (`IntentKey`)                                       |
| - SHA-256(incident_id || generation || action_type || target_urn)           |
| - Identifies the abstract logical containment goal.                         |
| - Strictly independent of RequesterID. Shared across multiple requesters.   |
+─────────────────────────────────────────────────────────────────────────────+
                                       │
                                       ▼
+─────────────────────────────────────────────────────────────────────────────+
| Tier 2: Request Identity (`RequestKey`)                                      |
| - SHA-256(IntentKey || requester_id || request_nonce || timestamp)          |
| - Identifies a specific submission attempt by a specific principal.         |
| - Enables tracking of distinct requests converging on the same intent.     |
+─────────────────────────────────────────────────────────────────────────────+
                                       │
                                       ▼
+─────────────────────────────────────────────────────────────────────────────+
| Tier 3: Authorization Nonce (`AuthNonce` / `BreakGlassNonce`)               |
| - 256-bit cryptographically secure pseudorandom value.                      |
| - Bound to approver public key, policy version, and approval timestamp.     |
| - Enforces strict single-use consumption via database unique constraints.   |
+─────────────────────────────────────────────────────────────────────────────+
                                       │
                                       ▼
+─────────────────────────────────────────────────────────────────────────────+
| Tier 4: Execution Run ID (`ExecutionRunId`)                                 |
| - UUIDv4 generated per physical execution dispatch attempt.                 |
| - Distinguishes initial dispatch attempts from compensation or retries.     |
| - Uniquely links adapter logs, network traces, and verifier reports.        |
+─────────────────────────────────────────────────────────────────────────────+
```

### Invariant:
Two security officers submitting containment requests for the same compromised candidate session produce identical `IntentKey` values. The PostgreSQL advisory lock on `IntentKey` serializes the requests: the first executes, and the second attaches as an observer, preventing duplicate destructive network calls.

---

## 6. External Execution vs. Database Transaction Semantics

A primary focus of Rev-04 is eliminating any ambiguous wording suggesting that a database rollback can automatically undo an external containment mutation.

### The Fundamental Distributed Systems Reality:
- **PostgreSQL Transaction Rollback**: Operates purely within the database engine. It discards uncommitted row insertions or modifications in local tables (`containment_requests`, `security_incidents`). It has **zero physical effect** on external subsystems.
- **External Action Compensation**: If an execution adapter successfully dispatches an HTTP/gRPC command to Redis or an external Identity Provider, **the external state has mutated**. Rolling back the local PostgreSQL transaction does not restore the external state; it merely creates a dangerous state divergence (an unrecorded mutation).

### Authoritative End-to-End Execution Sequence:
```
Step 1: Containment Request Received & Validated
Step 2: Policy Evaluation (Standard or Break-Glass Pipeline)
Step 3: Authorization Verification (Single / Dual / Break-Glass)
Step 4: Persist Execution Intent in Database:
        - Sets state to EXECUTING
        - Atomically consumes Authorization Nonce
        - Commits to PostgreSQL (Durable Pre-Dispatch Intent)
Step 5: Emit Audit Event: CONTAINMENT_EXECUTION_STARTED (Mode B)
Step 6: Network Dispatch to Subsystem Adapter (Redis / IdP / Exam Delivery)
Step 7: Capture Raw Execution Outcome:
        - Definite Success ──> State: EXECUTION_SUCCEEDED
        - Definite Failure ──> State: EXECUTION_FAILED
        - Timeout / Lost Packet ──> State: EXECUTION_UNKNOWN (NEVER ASSUME FAILURE!)
Step 8: Independent Verification Out-of-Band:
        - Independent Verifier inspects authoritative target data store
        - Confirmed Mutated ──> State: VERIFICATION_VERIFIED
        - Confirmed Unmutated ──> State: VERIFICATION_FAILED
        - Ambiguous / Target Down ──> State: VERIFICATION_INCONCLUSIVE
Step 9: Persist Final Containment State in Database
Step 10: Emit Final Audit Event: CONTAINMENT_VERIFIED / FAILED / INCONCLUSIVE (Mode B)
Step 11: 5D Observational Update (ONLY if VERIFICATION_VERIFIED):
         - Invokes SecurityIncidentService.transition_status(status=CONTAINED)
```

### Deterministic Handling of 8 Boundary Failure Scenarios:

| Failure Scenario | Immediate Execution State | Physical Target Reality | Recovery & Architectural Behavior |
| :--- | :--- | :--- | :--- |
| **A. Action Definitely Succeeds** | `EXECUTION_SUCCEEDED` | Target is contained. | Dispatches independent verifier; advances to `VERIFICATION_VERIFIED`. |
| **B. Action Definitely Fails** | `EXECUTION_FAILED` | Target is unmutated. | Fails closed. Incident remains `INVESTIGATING`. Logs failure error code. |
| **C. Network Timeout on Dispatch**| `EXECUTION_UNKNOWN` | **Indeterminate** (May be mutated or unmutated). | **Never assume failure!** Verifier queries target directly out-of-band to establish ground truth. |
| **D. Response Packet Lost** | `EXECUTION_UNKNOWN` | Target received command and mutated. | Verifier confirms target state; advances directly to `VERIFIED`. |
| **E. DB Fails After External Mutation**| Orphaned External State | Target is contained; DB record missing/uncommitted. | **Reconciliation Daemon** scans target audit logs, detects unrecorded mutation, reconstructs DB record, logs `CONTAINMENT_RECONCILIATION_CORRECTED`. |
| **F. Audit Fails Before Dispatch**| Transaction Aborted | Target is unmutated. | Zero dispatch. Request marked `ABORTED_AUDIT_FAILURE`. Safe fail-closed. |
| **G. Audit Fails After Dispatch** | Adapter succeeded; DB audit insert crashed. | Target is contained; audit DB crashed. | Fallback audit buffer flushed to local encrypted disk syslog; triggers emergency alert `AUDIT_PERSISTENCE_FAULT`. |
| **H. Verification Unavailable** | `VERIFICATION_INCONCLUSIVE`| Target mutation unknown. | Request held in `INCONCLUSIVE`. High-priority alert dispatched to Security Officer console for manual verification. |

---

## 7. Explicit Tri-State Execution & Independent Verification Outcomes

Rev-04 eliminates vague "fail closed" phrasing by defining rigid, explicit state machines for both Execution and Verification:

```
+─────────────────────────────────────────────────────────────────────────────+
|                        EXECUTION OUTCOME STATES                             |
+─────────────────────────────────────────────────────────────────────────────+
| 1. EXECUTION_SUCCEEDED  | Adapter received definite acknowledgement (HTTP   |
|                         | 200 / Redis +OK). Dispatches Verifier.            |
+-------------------------+---------------------------------------------------+
| 2. EXECUTION_FAILED     | Adapter received definite rejection (HTTP 4xx/5xx |
|                         | or connection refused). Safe terminal failure.     |
+-------------------------+---------------------------------------------------+
| 3. EXECUTION_UNKNOWN    | Network timeout, connection reset, or lost packet.|
|                         | Outcome uncertain. Mandates Verifier inspection.   |
+─────────────────────────────────────────────────────────────────────────────+

                                      │
                                      ▼
+─────────────────────────────────────────────────────────────────────────────+
|                       VERIFICATION OUTCOME STATES                           |
+─────────────────────────────────────────────────────────────────────────────+
| 1. VERIFICATION_VERIFIED| Target data store directly inspected out-of-band; |
|                         | state matches containment invariant. (Success).   |
+-------------------------+---------------------------------------------------+
| 2. VERIFICATION_FAILED  | Target data store inspected out-of-band; confirmed|
|                         | state did NOT mutate. (Containment did not land). |
+-------------------------+---------------------------------------------------+
| 3. VERIFICATION_        | Target data store unreachable, corrupt, or        |
|    INCONCLUSIVE         | conflicting. Mandates immediate operator console  |
|                         | escalation. ZERO assumption of success.           |
+─────────────────────────────────────────────────────────────────────────────+
```

### Operator Handling for `VERIFICATION_INCONCLUSIVE`:
1. The containment request is routed to the **Emergency Containment Quarantine Queue**.
2. Automated retry is **strictly prohibited** to prevent duplicate destructive mutations.
3. A high-priority audible and visual alarm is raised on the Central Security Officer Console.
4. An authorized Security Officer must manually inspect the target subsystem console and submit a signed manual attestation (`ATTEST_MANUAL_CONTAINED` or `ATTEST_MANUAL_FAILED`).

---

## 8. Break-Glass Protocol, Execution Lease & Bounded Expiry Semantics

### A. Break-Glass Token Lifecycle & Bounded Deadlines
```
t_0: Token Issued (expires_at = t_0 + 900s)
      │
      ▼
t_1: Coordinator Consumes Nonce & Acquires DB Lease (dispatch begins)
      │ ──> TOKEN CONSUMED IN DB
      │ ──> EXECUTION LEASE INITIATED (Deadline = t_1 + 60s)
      │
      ▼
t_2: Adapter Dispatches Network Call to Subsystem
      │
      ├──────────────────────────────────────────────────────────┐
      ▼ (Normal Case: Response in 2s)                            ▼ (Hang Case: Lease Expires)
[HTTP 200 Ack]                                             [Lease Deadline Lapsed (t_1 + 60s)]
  - Status: EXECUTION_SUCCEEDED                              - Status: EXECUTION_UNKNOWN
  - Verifier Dispatched                                      - Coordinator Drops Adapter Socket
  - Token Expiry Irrelevant (Action Begun)                   - Verifier Dispatched Out-of-Band
```

### B. Normative Expiry & Lease Rules:
1. **Pre-Dispatch Phase**:
   - If `NOW() > token.expires_at` before the execution coordinator atomically acquires the database lock and consumes the token nonce, the token is **expired**. Execution is rejected with `ERR_BREAK_GLASS_TOKEN_EXPIRED`. Zero mutation occurs.
2. **Dispatch Phase (Atomic Execution Lease)**:
   - When dispatch begins, the token is marked `CONSUMED` in PostgreSQL, and an **Execution Lease** of exactly **60 seconds** is granted.
   - Once the lease begins, subsequent expiration of `token.expires_at` does **not** retroactively abort the network request in flight.
3. **Execution Deadline Expiration**:
   - If the external adapter does not return a response within 60 seconds, the execution coordinator forcefully terminates the network socket, marks the execution outcome as `EXECUTION_UNKNOWN`, and immediately dispatches the Independent Verifier.
4. **Verification Deadline**:
   - The Independent Verifier has a hard timeout of **120 seconds**.
   - If verification cannot confirm target state within 120 seconds, the request transitions to `VERIFICATION_INCONCLUSIVE` and raises an emergency operator alarm.

---

## 9. Authoritative Audit Ordering, Sequencing & Mode B Isolation

Every containment action generates an unbroken, cryptographically attributable audit trail recorded via canonical `AuditService.log_security_event()`:

```
Step 1: CONTAINMENT_REQUESTED
        - Transactionally coupled to containment_requests row creation.
        - Records requester_id, action_type, canonical_target_urn, scope.
Step 2: CONTAINMENT_POLICY_EVALUATED
        - Transactionally coupled to policy decision storage.
        - Records policy_id, policy_version, decision, decision_hash.
Step 3: CONTAINMENT_AUTHORIZED
        - Transactionally coupled to approver signature storage.
        - Records approver_id, signature_hash, dual_auth_flag.
        *(If Break-Glass: additionally emits CONTAINMENT_EMERGENCY_OVERRIDE with risk_score = 1.0)*
Step 4: CONTAINMENT_EXECUTION_STARTED
        - Transactionally committed before external network socket opens.
        - Records adapter_name, intent_key, execution_lease_expires_at.
Step 5: CONTAINMENT_EXECUTION_RESULT
        - Post-dispatch durable record.
        - Records result: EXECUTION_SUCCEEDED, FAILED, or UNKNOWN; latency_ms.
Step 6: CONTAINMENT_VERIFICATION_STARTED
        - Verifier worker start. Records verifier_id, query_target.
Step 7: CONTAINMENT_VERIFIED / FAILED / INCONCLUSIVE
        - Durable verification proof object.
        - Records observed_state, target_proof_hash.
Step 8: INCIDENT_STATUS_CHANGED (in 5D)
        - Observational status update in security_incidents.
```

### Transactional Coupling Invariants:
- **Pre-Dispatch Safety**: Step 4 (`CONTAINMENT_EXECUTION_STARTED`) must be committed to PostgreSQL before the execution coordinator opens a network socket to the external adapter. If database write fails, zero network traffic is emitted.
- **Durable Post-Dispatch**: Steps 5 through 7 execute in dedicated Mode B transactions that cannot be rolled back by client errors.
- **Sealing Compatibility**: All events enter the Phase 3C-4A linear hash chain immediately and are sealed during subsequent Epoch Sealer rounds.

---

## 10. Risk Score Semantics & Schema Verification

### A. Database Schema Verification
Verification against `backend/app/core/models.py` (Alembic head revision `a1b2c3d4e5f6`) confirms:
```python
risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
```
The column `risk_score` exists in `audit_logs` as a native SQLAlchemy `Float`.

### B. Decoupling Measurement from Classification:
- **`risk_score` is a Quantitative Measurement**: A normalized floating-point value ($0.0 \le s \le 1.0$) indicating evaluated threat severity, anomaly confidence, or operational urgency.
- **`event_type` is the Semantic Classification**: An unambiguous string constant defining the specific audit event (e.g., `CONTAINMENT_EMERGENCY_OVERRIDE`, `CONTAINMENT_AUTHORIZED`).

### C. Invariant:
**`risk_score = 1.0` is NEVER a substitute for event type.**  
An emergency break-glass action is semantically identified by `event_type = 'CONTAINMENT_EMERGENCY_OVERRIDE'`. It sets `risk_score = 1.0` as its quantitative measurement. Automated alerting filters on both fields:
```sql
SELECT * FROM audit_logs 
WHERE event_type = 'CONTAINMENT_EMERGENCY_OVERRIDE' 
  AND risk_score = 1.0;
```

---

## 11. Phase 3C-5D to Phase 3C-5E Integration Interface

Phase 3C-5E integrates strictly through the frozen Phase 3C-5D service contract:

```
+─────────────────────────────────────────────────────────────────────────────+
|               5D INCIDENT MANAGEMENT SERVICE CONTRACT                       |
+─────────────────────────────────────────────────────────────────────────────+
| SecurityIncidentService.transition_status(                                  |
|   incident_id: UUID,                                                        |
|   target_status: IncidentStatus.CONTAINED,                                  |
|   expected_version: int,                                                    |
|   expected_generation: int,                                                 |
|   metadata: {                                                               |
|     "containment_reference_id": request_id,                                 |
|     "containment_mechanism": "AUTOMATED_POLICY" | "EMERGENCY_BREAK_GLASS",  |
|     "authorization_principal": approver_id,                                 |
|     "containment_timestamp": verified_at,                                   |
|     "audit_event_reference": audit_event_id                                 |
|   }                                                                         |
| )                                                                           |
+─────────────────────────────────────────────────────────────────────────────+
```

### Stale Generation & Concurrency Rejection:
The update in 5D executes under an atomic Compare-and-Swap (CAS) query:
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
If the incident rolled over ($N ightarrow N+1$) during 5E processing, rowcount is `0`. 5D raises `StaleGenerationError`. 5E immediately rolls back, logs `CONTAINMENT_STALE_GEN_REJECTED`, and halts. **Generation $N+1$ remains untouched.**

---

## 12. Final State Consistency & The 7 Decoupled State Architectures

Rev-04 formalizes complete separation across all 7 operational dimensions:

```
+─────────────────────────────────────────────────────────────────────────────+
| Dimension                  | Valid Finite States                            |
+────────────────────────────+────────────────────────────────────────────────+
| 1. 5D Incident State       | TRIAGE, INVESTIGATING, CONTAINED, RESOLVED,    |
|                            | CLOSED, FALSE_POSITIVE, DUPLICATE              |
+────────────────────────────+────────────────────────────────────────────────+
| 2. Containment Intent      | REGISTERED, IN_PROGRESS, CONTAINED, EXPIRED,   |
|                            | FAILED                                         |
+────────────────────────────+────────────────────────────────────────────────+
| 3. Containment Request     | REQUESTED, POLICY_EVALUATED,                   |
|                            | AWAITING_AUTHORIZATION, AUTHORIZED, EXECUTING, |
|                            | EXECUTED, VERIFYING_PENDING, VERIFIED, FAILED,  |
|                            | EXPIRED, CANCELLED                             |
+────────────────────────────+────────────────────────────────────────────────+
| 4. Authorization           | PENDING_APPROVAL, APPROVED_SINGLE,             |
|                            | APPROVED_DUAL, APPROVED_BREAK_GLASS, REJECTED, |
|                            | EXPIRED, REVOKED                               |
+────────────────────────────+────────────────────────────────────────────────+
| 5. Execution               | PENDING, DISPATCHED, SUCCEEDED, FAILED, UNKNOWN |
+────────────────────────────+────────────────────────────────────────────────+
| 6. Verification            | PENDING, VERIFIED, FAILED, INCONCLUSIVE        |
+────────────────────────────+────────────────────────────────────────────────+
| 7. Break-Glass Token       | ISSUED, CONSUMED, EXPIRED, REVOKED,            |
|                            | UNDER_REVIEW, RATIFIED, BREACH_DECLARED        |
+─────────────────────────────────────────────────────────────────────────────+
```

### State Decoupling Invariants:
1. **Execution Failure $
ot\Rightarrow$ Incident Closure**: An execution failure transitions Execution State to `FAILED` and Request State to `FAILED`. The 5D Incident State remains strictly `INVESTIGATING`.
2. **Verification Condition Precedent**: Only when Verification State transitions to `VERIFIED` is 5E permitted to call 5D `transition_status(status=CONTAINED)`.
3. **Atomic Generation Guard**: If the 5D Incident rolled over ($N ightarrow N+1$), the CAS update in 5D rejects the transition. Intent State becomes `FAILED`, Request State becomes `EXPIRED_STALE_GENERATION`, while Generation $N+1$ in 5D remains `OPEN` and `INVESTIGATING`.

---

## 13. Final Security Invariant Matrix

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
| **I-12** | **Explicit Unknown/Inconclusive Handling**| Network timeout mistakenly presumed success or failure. | Execution & Verification State Machines | Transitions to `EXECUTION_UNKNOWN` / `INCONCLUSIVE`. | `CONTAINMENT_EXECUTION_TIMEOUT` |
| **I-13** | **Immutable Audit Attribution** | Unattributable actions; tampering with incident history. | Canonical `AuditService` Mode B Transaction | Aborts entire containment if audit write fails. | Canonical `audit_logs` row |
| **I-14** | **Observational 5D Boundary** | Containment subsystem corrupting incident detection core.| Strict Service Contract (`transition_status`) | Rejects unauthorized column updates via triggers. | `INCIDENT_STATUS_CHANGED` |

---

## 14. Dynamic Baseline Test Gate & Complete Acceptance Test Suite

### A. Dynamic Acceptance Criterion (TC-GATE-21)
The normative acceptance criterion for regression testing is formulated dynamically:
- **All pre-5E baseline tests continue to pass.**
- **All 5E architecture acceptance tests pass.**
- **Zero unexplained regressions.**
- **Zero test failures.**
- **Skipped tests are documented and justified.**
- **Total test count expands monotonically as implementation proceeds.**

*Historical Benchmark (Phase 3C-5D Freeze)*:  
`Collected: 276 | Passed: 271 | Skipped: 5 | Failed: 0`  
*(This historical result serves as a floor, not a fixed future acceptance ceiling).*

### B. Complete 28-Scenario Implementation Acceptance Gate

| Test ID | Category | Specific Invariant & Scenario Tested | Mandatory Expected Outcome |
| :--- | :--- | :--- | :--- |
| `TC-GATE-01` | Idempotency | Parallel concurrent requests with identical `IntentKey`. | Advisory lock serializes; exactly 1 execution; 2nd returns cached result. |
| `TC-GATE-02` | Idempotency | Different requesters submit request for same target session. | Resolves to identical `IntentKey`; second requester attached as observer. |
| `TC-GATE-03` | Idempotency | Network retry after successful execution. | Detects `status == VERIFIED`; returns `200 OK` with existing proof. |
| `TC-GATE-04` | 5D Boundary | Generation rollover ($N ightarrow N+1$) occurs during 5E execution. | 5D CAS query rejects update; 5E halts; Gen $N+1$ remains untouched. |
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
| `TC-GATE-21` | Regression | Full repository test suite executed post-5E integration. | **Zero test failures; zero unexplained regressions against baseline.** |
| `TC-GATE-22` | DB Divergence | External mutation succeeds, but local DB transaction rolls back. | Reconciliation daemon detects external mutation; reconstructs audit trail. |
| `TC-GATE-23` | Timeout State | Execution adapter times out during network dispatch. | State set to `EXECUTION_UNKNOWN`; verifier dispatches; success NOT assumed. |
| `TC-GATE-24` | Orthogonality | Incident severity is `CRITICAL`, but requested action is `ACT_FORM_SUSPEND`.| Break-glass categorically blocked; dual super-admin required. |
| `TC-GATE-25` | Policy Gate | Request receives `REQUIRE_SECOND_AUTHORIZER` in standard policy. | Does NOT auto-authorize; separate emergency policy evaluation required. |
| `TC-GATE-26` | Lease Pre-Check | Break-glass token expires prior to execution dispatch. | Request rejected immediately; zero external network mutation emitted. |
| `TC-GATE-27` | Lease Post-Check| Token expires while adapter is executing within 60s lease. | Execution lease honored; action completes; verifier verifies out-of-band. |
| `TC-GATE-28` | Intent Lock | Officer B submits request for Target X while Officer A's request is in flight. | Resolves to same `IntentKey`; advisory lock serializes; zero duplicate run. |

---

## 15. Final Architecture Verdict

### A. Summary of All Rev-04 Consistency Corrections:
1. **Dual Policy Pathways Established**: Separated standard dual-approval policy rules from emergency break-glass eligibility rules.
2. **Decoupled External Mutation from DB Transactions**: Replaced naive rollback assumptions with explicit tri-state execution and out-of-band verification.
3. **Dynamic Regression Gate (TC-GATE-21)**: Formulated monotonic expansion rule with zero regressions.
4. **Orthogonal Severity & Risk**: Incident severity does not dictate action risk tier; `CRITICAL` actions remain inviolable.
5. **Exact Risk Score Semantics**: Reaffirmed `risk_score` as quantitative metric ($0.0 \le s \le 1.0$) and `event_type` as semantic classification.
6. **Execution Lease Semantics**: Defined 60-second execution lease preventing retroactive token invalidation while bounding deadlines.
7. **28-Scenario Acceptance Matrix**: Added TC-GATE-22 through TC-GATE-28 covering all targeted failure modes.

### B. Final Verdict

# ARCHITECTURE READY FOR IMPLEMENTATION REVIEW

Phase 3C-5E Architecture Specification Rev-04 completely resolves all consistency issues, establishes an airtight transactional boundary, and provides a fully deterministic blueprint. **Phase 3C-5E is certified ready for formal human implementation review.**
