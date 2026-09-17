# B-SEA Phase 3C-5E: Policy-Governed Security Containment Architecture Specification
## Architecture Review Rev-04.1 — Final Consistency Correction & Implementation Blueprint

**Document Reference**: `BSEA-ARCH-3C5E-REV04.1`  
**Status**: ARCHITECTURE SPECIFICATION (FINAL ARCHITECTURE GATE / READ-ONLY)  
**Date**: 2026-09-16  
**Baseline Git Commit**: `7683dd6f8d67f5289cc8cc86da3112a8aaade6ec` (Phase 3C-5D Frozen at Revision `a1b2c3d4e5f6`)  
**Supersedes**: `docs/BSEA_PHASE3C5E_ARCHITECTURE_REV04.md`, `REV03`, `REV02`, and `REV01`  
**Target Subsystem**: `backend/app/modules/containment/` (Deferred to Implementation Phase)  
**Review Status**: ARCHITECTURE READY FOR IMPLEMENTATION REVIEW  

---

## Executive Summary of Rev-04.1 Surgical Consistency Corrections

Architecture Review Rev-04.1 represents the final, authoritative consistency correction for Phase 3C-5E (**Policy-Governed Security Containment Subsystem**) of the Bharat Secure Examination Architecture (B-SEA). It preserves all established architecture decisions from Rev-02, Rev-03, and Rev-04, while executing surgical corrections across failure handling, audit safety, external idempotency, retry mechanics, execution leases, cryptographic action naming, and acceptance test scenarios:

1. **Refined Audit Guarantee Semantics (Pre-Dispatch Safety & Forensic Completeness)**:
   - Replaces overly broad phrasing with two mathematically precise invariants:
     - **PRE-DISPATCH SAFETY INVARIANT**: No external containment dispatch may begin unless mandatory pre-dispatch execution intent, authorization state, and required audit records have been durably committed.
     - **FORENSIC COMPLETENESS INVARIANT**: Every externally dispatched containment attempt must eventually have an attributable, immutable audit record. If post-dispatch persistence fails, the reconciliation process reconstructs the execution record without claiming that PostgreSQL rollback reversed the external mutation.
   - Explicitly asserts: **Database rollback NEVER reverses an already-dispatched external mutation.**
2. **Authoritative External Execution Idempotency & Reconciliation (`ExecutionID` Pipeline)**:
   - Formulates the exact external correlation chain:
     $$\text{ExecutionID} \longrightarrow \text{ExternalOperationID} \longrightarrow \text{TargetURN} \longrightarrow \text{TargetVersion} \longrightarrow \text{ExecutionResult} \longrightarrow \text{VerificationResult}$$
   - Mandates deterministic external idempotency semantics where technically supported.
   - Enforces **UNKNOWN $\longrightarrow$ VERIFY BEFORE RETRY**: reconciliation must query ground truth out-of-band before any retry can be authorized. Blind redispatch of `UNKNOWN` operations is strictly prohibited.
3. **Deterministic Handling of `EXECUTION_UNKNOWN` and `VERIFICATION_INCONCLUSIVE`**:
   - Codifies the deterministic tri-state resolution tree:
     - `EXECUTION_UNKNOWN` $\longrightarrow$ Independent Verification $\longrightarrow$ `VERIFIED` (success), `FAILED` (containment did not take effect; retry requires fresh authorization), or `INCONCLUSIVE` (quarantine; no automated retry; signed manual Security Officer attestation required).
   - Prohibits automatic repeated execution loops under all ambiguous states.
4. **Permanent Break-Glass Token Consumption & Strict Re-Authorization**:
   - Re-affirms: $\mathbf{ONE\ BREAK\_GLASS\_TOKEN} \longrightarrow \mathbf{ONE\ CONTAINMENT\ INTENT} \longrightarrow \mathbf{ONE\ EXECUTION\ ATTEMPT}$.
   - Token consumption is permanent upon dispatch.
   - If execution yields `UNKNOWN` or verification yields `INCONCLUSIVE`, the consumed token cannot be reused, and no automatic retry is permitted. Any subsequent execution strictly requires a fresh emergency eligibility decision, new FIDO2 re-challenge, and a newly minted token.
5. **Execution Lease & Expiry Semantics**:
   - Preserves the 15-minute token TTL and 60-second execution lease.
   - Clarifies that lease expiry without an authoritative response produces `EXECUTION_UNKNOWN` (never `EXECUTION_FAILED`), and that token expiration during an active lease does not invalidate the in-flight execution.
6. **Cryptographic Action Precision (`ACT_CRYPTO_REVOKE_MASTER`)**:
   - Resolves ambiguous "rotation" terminology by explicitly distinguishing operational key rotation from emergency master key revocation/invalidation.
   - Re-classifies and conceptualizes the action as **`ACT_CRYPTO_REVOKE_MASTER`** (formerly referenced as `ACT_CRYPTO_ROT_MASTER`), denoting the emergency invalidation of the slot CMK that permanently renders encrypted packages unreadable (irreversible, national blast radius, categorically ineligible for Break-Glass).
7. **Expanded Implementation Acceptance Gate (TC-GATE-29 through TC-GATE-35)**:
   - Adds 7 targeted test scenarios covering external DB rollback reconciliation, timeout verification paths, inconclusive quarantines, permanent token consumption, fresh emergency evaluation, and lease expiry semantics.
8. **Final Architecture Verdict**:
   - Confirms that with all 7 surgical corrections applied, the architecture is completely deterministic, robust, and internally consistent:
     `# ARCHITECTURE READY FOR IMPLEMENTATION REVIEW`

---

## 1. Break-Glass Policy Path & Dual Decision Pipelines

### The Core Architectural Dilemma
In Rev-03, an apparent contradiction existed:
- A `HIGH` risk action evaluated under normal policy rules returns `REQUIRE_SECOND_AUTHORIZER`, strictly requiring two distinct authorizers ($P_1 \neq P_2$).
- If an emergency Break-Glass request were to treat `REQUIRE_SECOND_AUTHORIZER` as an authorization to execute, it would create an architectural bypass that undermines policy governance.

### The Dual Pipeline Resolution
Rev-04 and Rev-04.1 resolve this by defining two distinct, deterministic policy decision pipelines within the Policy Engine:

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
   - Strictly mandates Two-Person Control: execution cannot proceed until a second, distinct authorizer ($P_2 \neq P_1$) submits a valid, cryptographic authorization signature.
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
For any containment action $A$ where $	ext{RiskTier}(A) = \text{CRITICAL}$:
$$\forall\ \text{Execution}(A) \implies \text{Principal}(P_1) \neq \text{Principal}(P_2) \land \text{Role}(P_1) = \text{SUPER\_ADMIN} \land \text{Role}(P_2) = \text{SUPER\_ADMIN}$$
$$\text{BreakGlass}(A) \equiv \mathbf{FALSE}\ (\text{Categorical Rejection})$$

### B. Blast Radius Limits & Risk Classification
| Action Identifier | Action Name | Risk Tier | Blast Radius | Normal Authorization | Break-Glass Allowed? |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `ACT_CAND_SESSION_TERM` | Terminate Candidate Session | `LOW` | Single Candidate Session | Single Officer | **YES** (Single Auth / BG) |
| `ACT_ACCT_DISABLE` | Disable Account | `HIGH` | Single User Account | Dual Control (SecOff + SuperAdmin) | **YES** (Single SuperAdmin + BG) |
| `ACT_Q_PREVENT_ASSIGN` | Prevent Question Assignment | `HIGH` | Single Question Object | Dual Control (SecOff + SuperAdmin) | **YES** (Single SuperAdmin + BG) |
| `ACT_CENTRE_RESTRICT` | Restrict Delivery Capacity | `HIGH` | Single Physical Centre | Dual Control (SecOff + SuperAdmin) | **NO** (Dual SuperAdmin Only) |
| `ACT_FORM_SUSPEND` | Suspend Form Variant | `CRITICAL`| Entire Form Cohort | Dual SuperAdmin | **NO (CATEGORICALLY PROHIBITED)** |
| `ACT_CENTRE_SUSPEND` | Suspend Centre Operations | `CRITICAL`| Entire Centre Facility | Dual SuperAdmin | **NO (CATEGORICALLY PROHIBITED)** |
| `ACT_CRYPTO_REVOKE_MASTER` | Emergency Master CMK Revocation | `CRITICAL`| National Slot Decryption Key | Dual SuperAdmin + CTO Signoff | **NO (CATEGORICALLY PROHIBITED)** |
| `ACT_EXAM_TERMINATE` | National Exam Termination | `DISASTER`| Entire National Exam | Statutory Board Quorum | **NO (OUT OF SCOPE / STATUTORY)** |

---

## 3. Orthogonality of Incident Severity vs. Containment Action Risk

Rev-04.1 explicitly decouples **Incident Severity** (evaluated by Phase 3C-5D during detection and correlation) from **Containment Action Risk** (evaluated by Phase 3C-5E during containment planning and authorization).

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
| Action Identifier      | ACT_CRYPTO_REVOKE_MASTER (Alias: ACT_CRYPTO_ROT_M) |
| Action Name            | Emergency Invalidation of Master Exam Package CMK  |
| Target Scope           | All decryption endpoints for examination slot      |
| Max Blast Radius       | National Exam Slot Decryption Key                  |
| Reversibility          | IRREVERSIBLE (Permanently disables package access) |
| Normal Authorization   | Dual SUPER_ADMIN + Chief Technology Officer Signoff|
| Break-Glass Permitted? | NO (CATEGORICALLY PROHIBITED)                      |
| Execution Adapter      | KMSMasterKeyAdapter                                |
| Independent Verifier   | KMSKeyVerifier (Asserts KeyState == Disabled)      |
| Audit Events           | CONTAINMENT_REQUESTED, CONTAINMENT_AUTHORIZED,     |
|                        | CONTAINMENT_EXECUTION_RESULT, CONTAINMENT_VERIFIED |
+─────────────────────────────────────────────────────────────────────────────+
```

#### Precise Semantics of `ACT_CRYPTO_REVOKE_MASTER`:
- **Ordinary Key Rotation vs. Emergency Revocation**:
  - *Standard Key Rotation* (Administrative/Operational): Creates a new key version while preserving decryption capability for existing encrypted examination ciphertexts. This is a scheduled administrative operation outside the scope of Phase 3C-5E containment.
  - *`ACT_CRYPTO_REVOKE_MASTER`* (Emergency Cryptographic Invalidation): An acute, emergency containment operation that **permanently disables, revokes, or destroys the master decryption key** in KMS. This causes all previously delivered encrypted exam packages for the slot to become completely unreadable.
  - Because existing examination materials immediately become undecryptable, this action is **IRREVERSIBLE**, inflicts national-level disruption, and mandates Dual Super-Admin plus CTO cryptographic sign-off. It is **categorically ineligible for Break-Glass**.

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

To eliminate race conditions, duplicate executions, and replay vulnerabilities, Rev-04.1 enforces four separate, cryptographically bound identity constructs:

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

A foundational principle of Rev-04.1 is that **database transactions and external network mutations exist across separate failure domains**.

### The Fundamental Distributed Systems Reality:
- **PostgreSQL Transaction Rollback**: Discards uncommitted rows in local tables (`containment_requests`, `security_incidents`). It operates strictly within database memory/WAL and has **zero physical effect** on external subsystems.
- **External Action Compensation**: If an execution adapter successfully dispatches an HTTP/gRPC command to Redis or an Identity Provider, **the external state has mutated**. Rolling back the local PostgreSQL transaction does not reverse the external mutation.
- **Normative Law**:
  $$\mathbf{Database\ Rollback\ NEVER\ Reverses\ an\ Already	ext{-}Dispatched\ External\ Mutation.}$$

### A. Pre-Dispatch Safety vs. Forensic Completeness Invariants:

1. **PRE-DISPATCH SAFETY INVARIANT**:
   No external containment dispatch may begin unless the mandatory pre-dispatch execution intent, authorization state, and required audit records have been durably committed to PostgreSQL.
   - If PostgreSQL write fails prior to network dispatch, the transaction aborts and **zero network traffic is emitted**.

2. **FORENSIC COMPLETENESS INVARIANT**:
   Every externally dispatched containment attempt must eventually have an attributable, immutable audit record.
   - If post-dispatch database persistence fails (e.g., connection lost during execution result logging), the system reconciliation process must reconstruct the execution attempt without assuming that local rollback reversed the external mutation.

### B. Authoritative External Execution Correlation:
Every external execution attempt is bound into an immutable correlation chain:
$$\text{ExecutionID} \longrightarrow \text{ExternalOperationID / Idempotency Reference} \longrightarrow \text{TargetURN} \longrightarrow \text{TargetVersion / Fingerprint} \longrightarrow \text{Execution Result} \longrightarrow \text{Independent Verification Result}$$

- The execution adapter must pass `ExternalOperationID` (derived deterministically from `ExecutionRunId`) as an idempotency key to external subsystem endpoints where technically supported.
- If PostgreSQL rolls back after dispatch, the **Reconciliation Process** MUST:
  1. Reconstruct the execution attempt from durable pre-dispatch evidence or external operation identity.
  2. Query and verify the authoritative target system out-of-band.
  3. Determine the target state: `SUCCESS`, `FAILED`, or `UNKNOWN`.
  4. **NEVER blindly redispatch an UNKNOWN operation.**

### C. Normative Retry Law:
$$\mathbf{UNKNOWN} \longrightarrow \mathbf{VERIFY\ BEFORE\ RETRY}$$
- A retry is permitted **only** when independent verification has established that the previous operation did not take effect and a fresh policy authorization is granted.
- For non-idempotent or uncertain external operations, verification must strictly precede any retry.

### D. Authoritative End-to-End Execution Flow:
```
Step 1: Containment Request Received & Validated
Step 2: Policy Evaluation (Standard or Break-Glass Pipeline)
Step 3: Authorization Verification (Single / Dual / Break-Glass)
Step 4: Persist Execution Intent in Database:
        - Sets state to EXECUTING
        - Atomically consumes Authorization Nonce / Token
        - COMMITTED TO POSTGRESQL (Durable Pre-Dispatch Intent)
Step 5: Emit Audit Event: CONTAINMENT_EXECUTION_STARTED (Mode B)
Step 6: Network Dispatch to Subsystem Adapter (With ExternalOperationID)
Step 7: Capture Raw Execution Outcome:
        - Definite Success ──> State: EXECUTION_SUCCEEDED
        - Definite Failure ──> State: EXECUTION_FAILED
        - Timeout / Dropped Socket ──> State: EXECUTION_UNKNOWN (NEVER ASSUME FAILURE!)
Step 8: Independent Verification Out-of-Band:
        - Independent Verifier directly queries authoritative target store
        - Confirmed Mutated ──> State: VERIFICATION_VERIFIED
        - Confirmed Unmutated ──> State: VERIFICATION_FAILED
        - Ambiguous / Unreachable ──> State: VERIFICATION_INCONCLUSIVE
Step 9: Persist Final Containment State in Database
Step 10: Emit Final Audit Event: CONTAINMENT_VERIFIED / FAILED / INCONCLUSIVE (Mode B)
Step 11: 5D Observational Update (ONLY if VERIFICATION_VERIFIED):
         - Invokes SecurityIncidentService.transition_status(status=CONTAINED)
```

### E. Handling of 8 Boundary Failure Scenarios:

| Failure Scenario | Immediate Execution State | Physical Target Reality | Recovery & Architectural Behavior |
| :--- | :--- | :--- | :--- |
| **A. Action Definitely Succeeds** | `EXECUTION_SUCCEEDED` | Target is contained. | Dispatches independent verifier; advances to `VERIFICATION_VERIFIED`. |
| **B. Action Definitely Fails** | `EXECUTION_FAILED` | Target is unmutated. | Fails closed. Incident remains `INVESTIGATING`. Logs failure error code. |
| **C. Network Timeout on Dispatch**| `EXECUTION_UNKNOWN` | **Indeterminate** (May be mutated or unmutated). | **Never assume failure!** Verifier queries target directly out-of-band to establish ground truth. |
| **D. Response Packet Lost** | `EXECUTION_UNKNOWN` | Target received command and mutated. | Verifier confirms target state; advances directly to `VERIFIED`. |
| **E. DB Fails After External Mutation**| Orphaned External State | Target is contained; DB record missing/uncommitted. | **Reconciliation Process** queries target using `ExternalOperationID`, detects mutation, reconstructs DB record, logs `CONTAINMENT_RECONCILIATION_CORRECTED`. |
| **F. Audit Fails Before Dispatch**| Transaction Aborted | Target is unmutated. | Zero dispatch. Request marked `ABORTED_AUDIT_FAILURE`. Safe fail-closed. |
| **G. Audit Fails After Dispatch** | Adapter succeeded; DB audit insert crashed. | Target is contained; audit DB crashed. | Fallback audit buffer flushed to local encrypted disk syslog; triggers emergency alert `AUDIT_PERSISTENCE_FAULT`. |
| **H. Verification Unavailable** | `VERIFICATION_INCONCLUSIVE`| Target mutation unknown. | Request quarantined in `INCONCLUSIVE`. High-priority alert dispatched to Security Officer console for signed manual attestation. |

---

## 7. Deterministic Handling of UNKNOWN & INCONCLUSIVE Outcomes

Rev-04.1 defines exact state transition mechanics when execution or verification encounters ambiguity:

```
                          [Execution Dispatched]
                                    │
                  ┌─────────────────┴─────────────────┐
                  ▼                                   ▼
        [Definite Result]                   [Timeout / Lost ACK]
        (SUCCEEDED / FAILED)                          │
                  │                                   ▼
                  │                           EXECUTION_UNKNOWN
                  │                                   │
                  └─────────────────┬─────────────────┘
                                    │
                                    ▼
                        [Independent Verification]
                                    │
            ┌───────────────────────┼───────────────────────┐
            ▼                       ▼                       ▼
   VERIFICATION_VERIFIED   VERIFICATION_FAILED    VERIFICATION_INCONCLUSIVE
            │                       │                       │
            ▼                       ▼                       ▼
    Action Succeeded;        Containment Did         Quarantine Request;
    Observational Update     NOT Land;               NO Automatic Retry;
    in 5D (CONTAINED).       Retry Permitted ONLY    Signed Manual Security
                             Via NEW Authorized      Officer Attestation
                             Execution Attempt.      Required.
```

### Deterministic State Invariants:
1. **Execution Timeout $\not\Rightarrow$ Execution Failure**:
   If network dispatch times out or the connection drops, state is **`EXECUTION_UNKNOWN`**. The coordinator is prohibited from marking it failed or retrying blindly.
2. **Deterministic Tri-State Verification Resolution**:
   - `VERIFICATION_VERIFIED`: Authoritative target store confirms containment state. Action declared successful; proceeds to 5D status update.
   - `VERIFICATION_FAILED`: Authoritative target store confirms entity is unmutated. Action did not take effect. Request marked `FAILED`. Any retry mandates a brand new authorized execution path.
   - `VERIFICATION_INCONCLUSIVE`: Target store is unreachable, corrupt, or returning inconsistent data. Request is immediately moved to **Emergency Containment Quarantine**.
3. **Quarantine Invariants for `VERIFICATION_INCONCLUSIVE`**:
   - **Automatic repeated execution is strictly prohibited.**
   - The original `ExecutionID` and `ExternalOperationID` are durably preserved.
   - An audible and visual alarm is raised on the Central Security Officer Console.
   - Resolution mandates a signed manual attestation (`ATTEST_MANUAL_CONTAINED` or `ATTEST_MANUAL_FAILED`) by a verified Security Officer after out-of-band console inspection.
   - Any subsequent execution attempt strictly requires a fresh authorization pipeline run.

---

## 8. Break-Glass Protocol, Execution Lease & Bounded Expiry Semantics

### A. Break-Glass Token Lifecycle & Bounded Deadlines
```
t_0: Token Issued (expires_at = t_0 + 900s)
      │
      ▼
t_1: Coordinator Consumes Nonce & Acquires DB Lease (dispatch begins)
      │ ──> TOKEN PERMANENTLY CONSUMED IN POSTGRESQL
      │ ──> EXECUTION LEASE INITIATED (Deadline = t_1 + 60s)
      │
      ▼
t_2: Adapter Dispatches Network Call to Subsystem (with ExternalOperationID)
      │
      ├──────────────────────────────────────────────────────────┐
      ▼ (Normal Case: Response in 2s)                            ▼ (Hang Case: Lease Expires)
[HTTP 200 Ack]                                             [Lease Deadline Lapsed (t_1 + 60s)]
  - Status: EXECUTION_SUCCEEDED                              - Status: EXECUTION_UNKNOWN (Not Failed!)
  - Verifier Dispatched                                      - Coordinator Drops Adapter Socket
  - Token Expiry Irrelevant (Lease Active)                   - Verifier Dispatched Out-of-Band
```

### B. Normative Expiry & Lease Rules:
1. **Pre-Dispatch Check**:
   - If `NOW() > token.expires_at` before the coordinator acquires the database lock and atomically consumes the nonce, the token is **expired**. Execution is rejected with `ERR_BREAK_GLASS_TOKEN_EXPIRED`. Zero external mutation occurs.
2. **Dispatch Phase (Atomic Execution Lease Acquisition)**:
   - When dispatch begins, the token is atomically and permanently marked `CONSUMED` in PostgreSQL.
   - An **Execution Lease** of exactly **60 seconds** is granted.
   - Once the lease begins, subsequent expiration of the original 15-minute token TTL does **not** retroactively abort or invalidate the in-flight network request.
3. **Execution Lease Expiry Semantics**:
   - The execution lease expiry does **not** imply SUCCESS or FAILURE.
   - If the external adapter does not return an authoritative result within 60 seconds, the coordinator cuts the network socket and marks the outcome as **`EXECUTION_UNKNOWN`** (never `EXECUTION_FAILED`). The Independent Verifier is immediately dispatched.
4. **Verification Timeout (120 Seconds)**:
   - Independent verification has a hard deadline of **120 seconds**.
   - If verification cannot reach ground truth within 120 seconds, it transitions to `VERIFICATION_INCONCLUSIVE` and raises an immediate quarantine alarm.

### C. Permanent Consumption & Strict Retry Semantics:
$$\mathbf{ONE\ BREAK\_GLASS\_TOKEN} \longrightarrow \mathbf{ONE\ CONTAINMENT\ INTENT} \longrightarrow \mathbf{ONE\ EXECUTION\ ATTEMPT}$$
- **Permanent Consumption**: Consumption of a `BreakGlassToken` is permanent for that execution attempt.
- **No Token Reuse**: If execution becomes `EXECUTION_UNKNOWN` or verification becomes `VERIFICATION_INCONCLUSIVE`, the consumed token **cannot be reused**.
- **No Automatic Retries**: Timeouts or inconclusive verification results **never** implicitly authorize another execution attempt.
- **Fresh Authorization Mandate**: Any subsequent emergency execution attempt requires:
  1. Submitting a new emergency request.
  2. Full independent evaluation by the Break-Glass Eligibility Pipeline (re-verifying active exam window, severity, rate limits).
  3. Fresh FIDO2 WebAuthn hardware challenge.
  4. Issuance of a brand new, uniquely nonced `BreakGlassToken`.

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
        - Records adapter_name, intent_key, execution_lease_expires_at, external_op_id.
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
- **Forensic Completeness**: Steps 5 through 7 execute in dedicated Mode B transactions that cannot be rolled back by client errors. If database connection fails during post-dispatch logging, the reconciliation daemon reconstructs the audit record from the target store logs.
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
If the incident rolled over ($N \rightarrow N+1$) during 5E processing, rowcount is `0`. 5D raises `StaleGenerationError`. 5E immediately rolls back, logs `CONTAINMENT_STALE_GEN_REJECTED`, and halts. **Generation $N+1$ remains untouched.**

---

## 12. Final State Consistency & The 7 Decoupled State Architectures

Rev-04.1 formalizes complete separation across all 7 operational dimensions:

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
1. **Execution Failure $\not\Rightarrow$ Incident Closure**: An execution failure transitions Execution State to `FAILED` and Request State to `FAILED`. The 5D Incident State remains strictly `INVESTIGATING`.
2. **Verification Condition Precedent**: Only when Verification State transitions to `VERIFIED` is 5E permitted to call 5D `transition_status(status=CONTAINED)`.
3. **Atomic Generation Guard**: If the 5D Incident rolled over ($N \rightarrow N+1$), the CAS update in 5D rejects the transition. Intent State becomes `FAILED`, Request State becomes `EXPIRED_STALE_GENERATION`, while Generation $N+1$ in 5D remains `OPEN` and `INVESTIGATING`.

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
| **I-12** | **Deterministic Ambiguity Quarantine** | Network timeout mistakenly presumed success or failure. | Execution & Verification State Machines | Transitions to `EXECUTION_UNKNOWN` / `INCONCLUSIVE`. | `CONTAINMENT_EXECUTION_TIMEOUT` |
| **I-13** | **Pre-Dispatch Safety & Completeness** | Unattributable mutations; missing audit records. | Canonical `AuditService` Mode B Transaction | Aborts dispatch on DB failure; reconciles post-run.| Canonical `audit_logs` row |
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

### B. Complete 35-Scenario Implementation Acceptance Gate

| Test ID | Category | Specific Invariant & Scenario Tested | Mandatory Expected Outcome |
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
| `TC-GATE-19` | Audit | Simulated DB failure during pre-dispatch `AuditService.log_security_event()`. | Entire transaction aborts; zero network dispatch committed to target. |
| `TC-GATE-20` | Rollback | Rollback requested for `ACT_CAND_SESSION_TERM`. | Reversible compensation logged; candidate permitted to re-authenticate. |
| `TC-GATE-21` | Regression | Full repository test suite executed post-5E integration. | **Zero test failures; zero unexplained regressions against baseline.** |
| `TC-GATE-22` | DB Divergence | External mutation succeeds, but local DB transaction rolls back. | Reconciliation process reconstructs record via `ExternalOperationID`. |
| `TC-GATE-23` | Timeout State | Execution adapter times out during network dispatch. | State set to `EXECUTION_UNKNOWN`; verifier dispatches; success NOT assumed. |
| `TC-GATE-24` | Orthogonality | Incident severity is `CRITICAL`, but requested action is `ACT_FORM_SUSPEND`.| Break-glass categorically blocked; dual super-admin required. |
| `TC-GATE-25` | Policy Gate | Request receives `REQUIRE_SECOND_AUTHORIZER` in standard policy. | Does NOT auto-authorize; separate emergency policy evaluation required. |
| `TC-GATE-26` | Lease Pre-Check | Break-glass token expires prior to execution dispatch. | Request rejected immediately; zero external network mutation emitted. |
| `TC-GATE-27` | Lease Post-Check| Token expires while adapter is executing within 60s lease. | Execution lease honored; action completes; verifier verifies out-of-band. |
| `TC-GATE-28` | Intent Lock | Officer B submits request for Target X while Officer A's request is in flight. | Resolves to same `IntentKey`; advisory lock serializes; zero duplicate run. |
| `TC-GATE-29` | Reconcile Target | External mutation succeeds, PostgreSQL transaction rolls back. | Reconciliation verifies target state & reconstructs record without duplicate run. |
| `TC-GATE-30` | UNKNOWN Verified| Execution outcome is `EXECUTION_UNKNOWN`, verifier asserts `VERIFIED`. | State advances to `VERIFIED`; 5D updated; zero duplicate retry dispatched. |
| `TC-GATE-31` | UNKNOWN Failed | Execution outcome is `EXECUTION_UNKNOWN`, verifier asserts `FAILED`. | Request marked `FAILED`; retry mandates new authorized execution attempt. |
| `TC-GATE-32` | Inconclusive Q | Execution outcome is `EXECUTION_UNKNOWN`, verifier is `INCONCLUSIVE`.| Request quarantined; automatic retry blocked; manual attestation required. |
| `TC-GATE-33` | BG No Reuse | Consumed Break-Glass token encounters `UNKNOWN` or `INCONCLUSIVE`. | Token permanently consumed; reuse rejected with `ERR_TOKEN_ALREADY_CONSUMED`. |
| `TC-GATE-34` | BG Fresh Auth | Re-attempt of previously failed/inconclusive Break-Glass action. | Mandates fresh emergency eligibility evaluation and new FIDO2 authorization. |
| `TC-GATE-35` | Lease Expiry | Execution lease (60s) expires without authoritative external ack. | State transitions to `EXECUTION_UNKNOWN` (never falsely marked `FAILED`). |

---

## 15. Final Architecture Verdict

### A. Summary of All Rev-04.1 Surgical Consistency Corrections:
1. **Refined Audit Invariants**: Defined Pre-Dispatch Safety and Forensic Completeness; established that database rollback never reverses an external mutation.
2. **Authoritative Idempotency & Reconciliation Chain**: Enforced `ExecutionID` $\rightarrow$ `ExternalOperationID` $\rightarrow$ `TargetURN` $\rightarrow$ `TargetVersion` $\rightarrow$ `ExecutionResult` $\rightarrow$ `VerificationResult` and the principle of **UNKNOWN $\rightarrow$ VERIFY BEFORE RETRY**.
3. **Deterministic Ambiguity Handling**: Established quarantine and signed manual attestation for `VERIFICATION_INCONCLUSIVE`; prohibited automated retries on ambiguous states.
4. **Permanent Break-Glass Token Consumption**: One token $\rightarrow$ one execution attempt. No reuse; fresh authorization and emergency policy evaluation required for any re-attempt.
5. **Execution Lease Semantics**: Explicit 60-second lease; lease expiration yields `EXECUTION_UNKNOWN` rather than failure.
6. **Cryptographic Action Precision**: Formally classified `ACT_CRYPTO_REVOKE_MASTER` as an irreversible master CMK invalidation action with national blast radius.
7. **Expanded 35-Scenario Acceptance Matrix**: Integrated TC-GATE-29 through TC-GATE-35 covering all boundary edge cases.

### B. Final Verdict

# ARCHITECTURE READY FOR IMPLEMENTATION REVIEW

Phase 3C-5E Architecture Specification Rev-04.1 completely resolves every targeted consistency point, establishes an airtight distributed transactional boundary, and provides a fully deterministic, robust blueprint. **Phase 3C-5E is certified ready for formal human implementation review.**
