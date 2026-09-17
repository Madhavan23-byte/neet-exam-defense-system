# B-SEA Phase 3C-5E: Policy-Governed Security Containment Architecture Specification
## Architecture Review Rev-02 — Reconciliation & Final Blueprint

**Document Reference**: `BSEA-ARCH-3C5E-REV02`  
**Status**: ARCHITECTURE SPECIFICATION (READ-ONLY / NO CODE IMPLEMENTED)  
**Date**: 2026-09-16  
**Baseline Git Commit**: `7683dd6f8d67f5289cc8cc86da3112a8aaade6ec` (Phase 3C-5D Frozen at Revision `a1b2c3d4e5f6`)  
**Supersedes**: `docs/BSEA_PHASE3C5E_ARCHITECTURE_REV01.md`  
**Target Subsystem**: `backend/app/modules/containment/` (Deferred to Implementation Phase)  
**Review Status**: ARCHITECTURE READY FOR REVIEW  

---

## Executive Summary of Rev-02 Reconciliations

Architecture Review Rev-02 resolves all critical architectural gaps, ambiguities, and security risks identified during the human review of Rev-01.

### Key Rev-02 Corrections & Invariants:
1. **Redesigned Idempotency Architecture**: Completely decouples **Containment Intent Identity** from the requesting principal. `RequesterID` is removed from the intent hash. Two distinct authorized officers requesting the identical logical containment action now resolve to the exact same `IntentKey`, eliminating race conditions, parallel duplicate executions, and conflicting mutations.
2. **Strict 5D / 5E Ownership Boundary**: Establishes a rigid, one-way contract. Phase 3C-5D exclusively owns the incident lifecycle. Phase 3C-5E exclusively owns containment evaluation, execution, and independent verification. 5E interacts with 5D solely by invoking `SecurityIncidentService.transition_status()` with pre-defined observational metadata. 5E can never write arbitrary incident fields or mutate a succeeding generation.
3. **Question Quarantine Decision**: Rejects in-flight dynamic question substitution in 5E. Formally limits 5E question containment to **`ACT_Q_PREVENT_ASSIGN`** (preventing question assignment in future slots/forms) and flagging affected items for post-exam psychometric compensation. Real-time dynamic reserve question delivery is classified as an Examination-Integrity/Psychometric Subsystem concern deferred to post-Phase 3C.
4. **Offline Centre Containment Decision**: Formally **PROHIBITS** autonomous local containment execution by offline testing centres. Bypassing central consensus under WAN disconnection introduces unacceptable risk of rogue invigilator abuse and clock-tampering attacks. Containment directives require centralized quorum; offline centres remain in localized autonomous exam delivery mode until WAN restoration.
5. **Emergency Authorization Overhaul**: Categorically rejects the Rev-01 proposal where a 120-second timeout automatically implied emergency execution authority. Timeout $\neq$ authorization. For `CRITICAL` risk actions, Two-Person Control is inviolable with **zero single-person bypass permitted**. For `HIGH` risk actions, an emergency Break-Glass protocol is defined with strict cryptographic constraints, a 15-minute TTL, and mandatory automated Board review within 12 hours.
6. **Strict Separation of Requester, Approver, Executor, and Verifier**: Enforces that for all `HIGH` and `CRITICAL` actions, the human requester, human approver, execution adapter, and independent verifier must be distinct entities. The executor is architecturally prohibited from self-certifying its own success.

---

## 1. Idempotency Model & Identity Decoupling

In Rev-01, the idempotency key mistakenly included `RequesterID`. If Officer A submitted a containment request for Session X, and Officer B simultaneously or subsequently submitted a request for Session X, two distinct idempotency keys were generated. This created a severe race condition where duplicate, parallel, or conflicting destructive operations could be executed against the target subsystem.

Rev-02 establishes a mathematically sound, 4-tier decoupled identity model:

```
+─────────────────────────────────────────────────────────────────────────────+
|                         4-TIER IDENTITY ARCHITECTURE                        |
+─────────────────────────────────────────────────────────────────────────────+
| Tier 1: Containment Intent Identity (Canonical IntentKey)                   |
|         Binds WHAT, WHICH TARGET, WHICH INCIDENT, and WHICH GENERATION.     |
|         Independent of WHO submitted the request.                           |
|                                                                             |
| Tier 2: Request Identity (RequestID)                                        |
|         Tracks individual submission instances (UUIDv4) and audit ingress.  |
|                                                                             |
| Tier 3: Authorization Identity (AuthorizationID / SignatureChallenge)       |
|         Cryptographically binds PolicyVersion, Approver, Nonce, and Intent. |
|                                                                             |
| Tier 4: Execution Identity (ExecutionID / ExecutionReference)               |
|         Tracks technical execution dispatches, adapter tokens, and retries. |
+─────────────────────────────────────────────────────────────────────────────+
```

### A. Containment Intent Identity (`IntentKey`)
The `IntentKey` represents the unique logical operation to be performed on the target system. It is deterministic, immutable, and strictly independent of the requesting principal:

$$\text{IntentKey} = \text{SHA-256}(\text{CanonicalJCS}(\text{IntentEnvelope}))$$

Where the `IntentEnvelope` is an RFC 8785 Canonical JSON object:
```json
{
  "action_type": "ACT_CAND_SESSION_TERM",
  "canonical_target_urn": "urn:bsea:session:cand_9a8b7c6d",
  "incident_generation": 1,
  "incident_id": "8c5095b0-2b81-4c9d-8193-3e36297b0844",
  "scope_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "threat_vector_key": "4f9b2c3d8e7a1f0a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a"
}
```

### B. Canonical Target URN Specification
Target identifiers must follow a rigid Uniform Resource Name (URN) syntax to prevent target ambiguity:
- Candidate Session: `urn:bsea:session:<session_uuid>`
- User Account: `urn:bsea:user:<user_uuid>`
- Examination Centre: `urn:bsea:centre:<centre_code>`
- Question Object: `urn:bsea:question:<question_uuid>`
- Examination Form: `urn:bsea:exam:<exam_id>:form:<form_id>`

### C. Duplicate & Concurrency Behavior Matrix

| Scenario | Ingress Event | Coordination Engine Action | Resulting Execution State |
| :--- | :--- | :--- | :--- |
| **Same Requester Retry** | Same officer re-sends request after client network drop. | Detects matching `IntentKey`. Advisory lock serializes. | Returns existing `request_id` and current state (`EXECUTING` or `VERIFIED`). Zero duplicate mutation. |
| **Different Requester** | Officer B requests same action while Officer A's request is in-flight. | Detects matching `IntentKey` in state `AWAITING_AUTHORIZATION` or `EXECUTING`. | Attaches Officer B as co-requester; joins existing request lifecycle. Zero duplicate mutation. |
| **Repeated Authorization**| Second approver clicks approve twice. | Detects authorization already recorded for `IntentKey`. | Idempotent `200 OK`; duplicate signature safely discarded. |
| **Worker Crash Mid-Flight**| Worker dies while adapter is executing. | Worker restarts. Inspects `IntentKey` in `EXECUTING` state past heartbeat threshold. | Dispatches **Independent Verifier** first. If target state already mutated, advances to `VERIFIED`. If unmutated, safely re-dispatches adapter under advisory lock. |
| **Network Timeout to Target**| Execution coordinator receives timeout from Session Redis. | Transitions to `VERIFICATION_PENDING`. | Calls Independent Verifier. If target is revoked, marks `VERIFIED`. If unrevoked, fails closed with `EXECUTION_FAILED`. |

---

## 2. Phase 3C-5D / Phase 3C-5E Ownership Boundary

To preserve the architectural integrity of Phase 3C-5D, Phase 3C-5E is strictly constrained in how it interacts with 5D incidents. 5E is a **consumer** of 5D incidents and a **reporter** of containment outcomes, never an arbitrary modifier.

```
+───────────────────────────────────+       +───────────────────────────────────+
|      Phase 3C-5D Incident Core    |       |    Phase 3C-5E Containment Engine |
|                                   |       |                                   |
| - Owns incident lifecycle states  |       | - Owns policy evaluation          |
| - Owns correlation generations    |       | - Owns dual authorization         |
| - Owns rolling inactivity window  |       | - Owns execution adapters         |
| - Owns evidence link immutability |       | - Owns independent verification   |
| - Owns threat vector identity     |       | - Owns containment request ledger |
+─────────────────▲─────────────────+       +─────────────────┬─────────────────+
                  │                                           │
                  │   Authoritative Transition Contract       │
                  └───────────────────────────────────────────┘
                      transition_status(
                          incident_id,
                          new_status = CONTAINED,
                          expected_version,
                          containment_data = {
                              containment_reference_id,
                              containment_mechanism,
                              authorization_principal,
                              containment_timestamp,
                              audit_event_reference
                          }
                      )
```

### Strict Ownership Invariants:
1. **Zero Direct Schema Writes**: 5E components possess zero database permissions to execute direct `UPDATE` queries on `security_incidents`. All updates must route through the 5D `SecurityIncidentService.transition_status()` method.
2. **Exact Allowed Mutation Fields**: When 5E reports a verified containment, 5D updates strictly:
   - `status = SecurityIncidentStatus.CONTAINED`
   - `containment_reference_id = containment_requests.id`
   - `containment_mechanism = containment_requests.action_type`
   - `authorization_principal = containment_requests.approver_id`
   - `containment_timestamp = containment_verifications.verified_at`
   - `audit_event_reference = audit_logs.id`
   - `seal_verification_status = SealVerificationStatus.PENDING_SEAL`
   - `version = expected_version + 1`
   - `updated_at = NOW()`
3. **Generation Binding Invariant**:
   - Every containment request is cryptographically bound to `incident_generation = N`.
   - If an incident rolls over to Generation $N+1$ (due to a 3600-second inactivity timeout) while 5E is evaluating or executing containment:
     $$\text{Assert}(\text{request}.\text{incident\_generation} == \text{incident}.\text{generation})$$
   - 5D rejects the transition with `StaleGenerationError`. 5E immediately aborts and logs `CONTAINMENT_ABORTED_STALE_GENERATION`.
   - **Under no circumstances can a containment verified for Generation $N$ mutate Generation $N+1$ or a different incident.**
4. **Audit Sequencing**:
   1. 5E Execution Coordinator completes execution.
   2. 5E Independent Verifier verifies target state and emits `CONTAINMENT_VERIFIED` to `audit_logs`.
   3. 5E invokes 5D `transition_status()`.
   4. 5D verifies generation and OCC version, updates `security_incidents`, and emits `INCIDENT_STATUS_CHANGED` to `audit_logs`.

---

## 3. Question Quarantine Analysis & Normative Decision

When a question leak or defect incident is verified, how should the examination system handle the affected question in-flight? Rev-02 conducts a rigorous multi-dimensional trade-off analysis across three competing approaches:

### Comparative Architectural Analysis:

| Architectural Dimension | Option A: Real-Time Dynamic Reserve Substitution | Option B: Post-Exam Psychometric / Scoring Compensation | Option C: Hybrid Strategy (Rev-02 Normative) |
| :--- | :--- | :--- | :--- |
| **Exam Integrity** | High: Compromised item removed immediately from live screens. | High: Statistical elimination of compromised item prevents cheating score benefit. | **Maximum**: Prevents future assignment; isolates in-flight sessions; normalizes scores. |
| **Candidate Fairness** | Medium-Low: Candidates mid-question suffer cognitive shock, clock disruption, and unequal question difficulty. | **Maximum**: All candidates evaluated on identical remaining valid items; zero mid-exam cognitive disruption. | **High**: Zero disruption for active sessions; compromised item safely nullified for all candidates. |
| **Answer-Key Handling** | Complex: Dynamic synchronization of encrypted answer keys to distributed centres. | **Simple**: Answer key for quarantined item marked `CANCELLED` centrally. | **Deterministic**: Item flagged `DO_NOT_SCORE` in central scoring engine. |
| **Psychometric Equivalence**| Extremely Difficult: Pre-calibrated reserve item may not match difficulty/IRT parameters in-flight. | **Robust**: Classical Test Theory (CTT) & Item Response Theory (IRT) post-equating methods. | **Robust**: Standard IRT item deletion and scale re-anchoring protocol. |
| **Active Session Behavior**| **Fragile**: Requires real-time WebSocket push, candidate screen lock, DOM rerendering, timer pause. | **Completely Stable**: Candidate finishes exam smoothly; zero client crashes or UI desync. | **Completely Stable**: Zero mid-exam client disruption. |
| **Offline Centre Behavior** | **Fails**: Disconnected centres cannot receive dynamic reserve question packets. | **100% Resilient**: Works regardless of centre WAN status during live testing hours. | **100% Resilient**: Works across offline, intermittently connected, and online centres. |
| **Security Risk** | High: In-flight push introduces new remote-code / content injection attack surfaces. | **Lowest**: Minimal operational touchpoints during high-stress exam window. | **Lowest**: Zero real-time content injection risks. |

### Normative Decision for Phase 3C-5E:
1. **Option A (Dynamic Mid-Exam Question Substitution) is REJECTED in 5E**: Real-time push substitution across distributed, high-latency, and offline examination centres introduces unacceptable operational fragility, psychometric variance, and candidate panic during live national examinations.
2. **Adoption of Option C (Hybrid Quarantine & Scoring Protocol)**:
   - **In 5E Containment**: Limit question containment strictly to **`ACT_Q_PREVENT_ASSIGN`**. When executed, the Question Allocator immediately removes the question object from all future exam slots, future forms, and subsequent candidate test generations.
   - **In Scoring & Delivery Engine (Deferred to Examination Subsystem)**: The affected question is flagged with status `QUARANTINED_PENDING_PSYCHOMETRIC_REVIEW`. Active candidates complete the paper without disruption. In the central scoring pipeline, the question is evaluated under the statutory **National Scoring Compensation Protocol** (full credit awarded to all candidates who attempted/received the flawed item, or item removed from denominator score across the cohort).

---

## 4. Offline Exam Centre Containment Analysis & Decision

Rev-01 suggested providing a local offline policy cache and on-premise hardware security token for disconnected exam centres. Rev-02 evaluates this proposal as an entirely new, high-risk trust boundary.

### Trust Boundary Analysis of Offline Containment:

```
[Central High-Security Cloud]                       [Local Exam Centre LAN (Untrusted Physical Env)]
  - HSM-Backed KMS                                    - Centre Admin PC (Vulnerable to Physical Tampering)
  - Strict Dual Control Quorum                        - Hardware Token (Subject to Coercion / Theft)
  - Multi-Region Immutability                         - Local System Clock (Subject to Clock Rollback)
         │                                                   │
         │ (WAN Disconnect / Partition)                      │
         X <─────────────────────────────────────────────────┘
           Can local centre securely execute containment without central quorum?
```

### Critical Security Vulnerabilities in Offline Containment:
1. **Compromised Centre Administrator Threat**: If an on-premise administrator possesses credentials to execute local containment without central cloud verification, a rogue or coerced administrator could execute malicious mass session terminations or corrupt question pools across the entire centre.
2. **Clock Rollback & Replay Attacks**: Offline policy caches rely on timestamps for policy expiration ($300\text{s}$) and authorization tokens. Without an atomic, authenticated NTP or GPS hardware clock source (rare in distributed commercial exam centres), local servers are vulnerable to clock rollback attacks, enabling replay of expired emergency tokens.
3. **WAN Restoration Reconciliation Conflicts**: If an offline centre executes containment while the central cloud independently executes a different directive (or closes the incident), reconnecting the centre creates irreconcilable split-brain states in candidate audit records.

### Normative Decision:
**Offline Local Autonomous Containment Execution is CATEGORICALLY PROHIBITED in Phase 3C-5E.**
- All containment directives in 5E require authenticated execution through the centralized API Gateway and central database consensus.
- When an examination centre experiences a WAN outage:
  1. The centre operates in **Autonomous Local Delivery Mode** (candidates continue testing; responses buffer in encrypted local storage).
  2. The centre **cannot receive** remote containment commands and **cannot originate** destructive containment actions.
  3. Physical centre incidents are handled via standard on-site proctoring protocols and reported centrally upon WAN restoration.
- Specialized on-premise hardware gateway containment is formally **DEFERRED to Phase 4 (Edge Infrastructure Hardening)**.

---

## 5. Emergency Authorization Architecture

Rev-01 proposed that if a second authorizer did not respond within 120 seconds, a `HIGH` risk action would automatically execute under single-superadmin authority.

**Rev-02 explicitly REJECTS this proposal.**  
**Core Invariant: A timeout MUST NEVER imply authorization.**

### Analysis of Emergency Models:

```
+─────────────────────────────────────────────────────────────────────────────+
| Model A: Strict Inviolable Two-Person Control                               |
|          - Pro: Maximum security; completely eliminates rogue super-admin.   |
|          - Con: If second approver is incapacitated, response is paralyzed. |
|                                                                             |
| Model B: Automatic Timeout Bypass (Rev-01 Flaw - REJECTED)                  |
|          - Attack: Malicious actor DoSes second approver for 120 seconds,   |
|                    automatically gaining unilateral destruction rights.     |
|                                                                             |
| Model C: Escalation to Active On-Call Executive Approver Roster             |
|          - Pro: Preserves Two-Person Control by routing to backup approvers. |
|          - Con: Requires dynamic on-call schedule integration.               |
|                                                                             |
| Model D: Strictly Bounded Emergency Break-Glass (Rev-02 Adopted)            |
|          - Pro: Allows rapid containment for constrained scope only.        |
|          - Safeguard: Inviolable cryptographic dual control on CRITICAL.     |
+─────────────────────────────────────────────────────────────────────────────+
```

### Normative Emergency Policy Specification:

#### 1. Inviolable Rule for `CRITICAL` Risk Actions:
Single-person bypass is **CATEGORICALLY PROHIBITED** for all `CRITICAL` risk actions (e.g., suspending an entire exam form or multi-centre operations). Two distinct `SUPER_ADMIN` signatures are mandatory under all circumstances. If a second approver is unavailable, the action remains blocked; incident response escalates via out-of-band Board crisis telephone protocol.

#### 2. Strictly Bounded Emergency Break-Glass for `HIGH` Risk Actions:
A single `SUPER_ADMIN` may invoke `ACT_EMERGENCY_BREAK_GLASS` to execute a `HIGH` risk action **only if all of the following conditions are simultaneously satisfied**:
1. **Examination State**: The exam is actively in progress (`EXAM_IN_PROGRESS`).
2. **Eligible Action Subset**: Restricted strictly to:
   - `ACT_CAND_SESSION_TERM` (Single Session)
   - `ACT_ACCT_DISABLE` (Single User Account)
   - `ACT_Q_PREVENT_ASSIGN` (Flag question for future slots)
   - *Prohibited*: Centre restriction, form suspension, key invalidation.
3. **Cryptographic Break-Glass Key**: The super-admin must provide an ephemeral, single-use Break-Glass Token issued by an independent security sidecar.
4. **Mandatory Audit Signature**: The request is logged with `risk_score = 1.0` and event type `CONTAINMENT_EMERGENCY_OVERRIDE`.
5. **Enforced Retrospective Accountability**:
   - The emergency action expires automatically after **15 minutes**.
   - An automated cryptographic dossier is immediately transmitted to the Examination Oversight Board.
   - The Chief Controller of Examinations must formally countersign the action within **12 hours**, or the system flags a **Severe Security Governance Violation**.

---

## 6. Verified Incident Definition & Ingress Eligibility

Not every incident in 5D is eligible to trigger containment. To prevent premature containment triggered by unverified or noisy signals, 5E establishes an unambiguous eligibility gate.

```
+─────────────────────────────────────────────────────────────────────────────+
|                    5E CONTAINMENT INGRESS ELIGIBILITY GATE                  |
+─────────────────────────────────────────────────────────────────────────────+
| Mandatory Precondition               | Permitted Values / Criteria          |
+──────────────────────────────────────+──────────────────────────────────────+
| 1. Incident Lifecycle Status (5D)    | Exactly `INVESTIGATING`              |
| 2. Incident Correlation Status (5D)  | Exactly `OPEN`                       |
| 3. Minimum Incident Severity         | `MEDIUM`, `HIGH`, or `CRITICAL`      |
| 4. Evidentiary Proof Threshold       | >= 1 Verified IncidentEvidenceLink   |
| 5. Incident Freshness                | latest_signal_at within last 24h     |
| 6. Preceding Rollover Check          | Must match active generation number  |
+──────────────────────────────────────+──────────────────────────────────────+
```

### Ineligible Incident States & Handling Rules:
1. **`TRIAGE`**: Ineligible. Incidents in triage are unverified advisory alerts. Any containment request submitted for a triage incident is rejected with `ERR_INCIDENT_IN_TRIAGE`.
2. **`CONTAINED`**: Ineligible for duplicate containment. If additional containment is needed, the incident must be re-evaluated under `INVESTIGATING`.
3. **`RESOLVED` & `CLOSED`**: Ineligible. Terminal cases cannot execute containment.
4. **`FALSE_POSITIVE`**: Ineligible. Terminal evaluation determining signal was benign.
5. **`DUPLICATE`**: Ineligible. Requests targeting a duplicate incident are rejected with `ERR_DUPLICATE_INCIDENT_REDIRECT`. The operator must redirect the request to the canonical parent incident (`duplicate_of_incident_id`).
6. **`REOPENED` Incidents**: In 5D, reopening an incident leaves `correlation_status = 'CLOSED'`. Consequently, reopened incidents cannot execute automated containment until an analyst completes re-investigation and an explicit supervisory containment override is authorized.

---

## 7. TOCTOU (Time-of-Check to Time-of-Use) Protection

A critical failure mode in distributed containment is state divergence between the moment an action is authorized and the moment it is executed.

```
Time: t_0                       t_1                     t_2                     t_3
  │                              │                       │                       │
  ▼                              ▼                       ▼                       ▼
[Policy Evaluated] ──> [Two-Person Authorized] ──> [Target Mutates] ──> [Execution Attempted]
  - Target: Session A    - Signed for Session A    - Session A Logs Out    - DESTROYS WRONG
  - Version: 1           - Bound to Version 1        New Session B Starts    SESSION!
```

### Rev-02 Multi-Layer Fingerprinting & Atomic Validation:

1. **Cryptographic State Fingerprinting**:
   At evaluation time, 5E captures an immutable snapshot of all participating entities:
   $$\text{StateFingerprint} = \text{SHA-256}(\text{IncidentVersion} \parallel \text{IncidentGen} \parallel \text{TargetVersion} \parallel \text{PolicyVersion})$$
2. **Authorization Binding**:
   The authorization signature $\text{Sig}_2$ signs $\text{StateFingerprint}$.
3. **Atomic CAS Pre-Execution Check**:
   Execution occurs within a PostgreSQL transaction holding an exclusive advisory lock on `IntentKey`. The coordinator executes an atomic revalidation query:
   ```sql
   SELECT id FROM security_incidents
   WHERE id = :incident_id
     AND generation = :expected_generation
     AND correlation_status = 'OPEN'
     AND status = 'INVESTIGATING'
     AND version = :expected_incident_version
   FOR UPDATE;
   ```
4. **Target Subsystem Version Check**:
   The execution adapter checks the target's current version (e.g., `candidate_sessions.version == expected_target_version`).
5. **Divergence Handling**:
   If any version or state element has changed, the transaction aborts with `TOCTOUConflictError`. Request transitions to `FAILED_TOCTOU_CONFLICT`. Zero mutation occurs.

---

## 8. Target Binding & Substitution Defense

To prevent Confused Deputy attacks where an authorized action targeting benign entity $X$ is redirected to target critical entity $Y$:

1. **Canonical Target Binding**:
   Target identity is strictly bound to its canonical URN and primary database UUID:
   $$\text{TargetBindingHash} = \text{SHA-256}(\text{CanonicalURN} \parallel \text{TargetDatabaseUUID} \parallel \text{ExamID} \parallel \text{CentreID})$$
2. **Zero Inferred Targets**: Execution adapters accept **only** fully resolved, strongly typed target parameters. An adapter never queries or infers target IDs based on rule names or search queries.
3. **Pre-Execution Target Integrity Verification**:
   Before dispatching the mutation, the execution adapter queries the target subsystem directly:
   - Validates that `TargetDatabaseUUID` exists.
   - Validates that the entity belongs to `ExamID` and `CentreID`.
   - Recomputes `TargetBindingHash`.
   - If computed hash $\neq$ authorized hash, the adapter halts execution and raises `TargetSubstitutionAttackDetected`.

---

## 9. Separation of Duties: Requester, Approver, Executor, Verifier

Rev-02 mandates mathematical separation of duties. No single role or component can perform more than one critical stage in the containment lifecycle:

```
+─────────────────────────────────────────────────────────────────────────────+
|                         SEPARATION OF DUTIES ARCHITECTURE                   |
+─────────────────────────────────────────────────────────────────────────────+
| 1. REQUESTER  | Proposes containment. Human principal (SECURITY_OFFICER).   |
|               | Evaluates evidence, selects action, defines scope.          |
+---------------+-------------------------------------------------------------+
| 2. APPROVER   | Cryptographically authorizes request. Distinct principal    |
|               | (SUPER_ADMIN). Validates justification and policy fit.      |
+---------------+-------------------------------------------------------------+
| 3. EXECUTOR   | Dispatches technical mutation. Automated background service |
|               | worker. Holds adapter write credentials. Cannot authorize.  |
+---------------+-------------------------------------------------------------+
| 4. VERIFIER   | Inspects target state out-of-band. Automated verifier worker.|
|               | Holds read-only inspection credentials. Cannot execute.     |
+─────────────────────────────────────────────────────────────────────────────+
```

### Separation Constraints:
- $\text{Requester} \neq \text{Approver}$ (Enforced by `DualControlSelfApprovalError`).
- $\text{Approver} \neq \text{Executor}$ (Approver is human; Executor is machine service).
- $\text{Executor} \neq \text{Verifier}$ (Executor adapter code and Verifier engine code reside in distinct modules with segregated database connection pools).
- **The Executor is architecturally prohibited from self-certifying execution success.**

---

## 10. Comprehensive Failure Matrix

The following normative matrix defines exact failure semantics across all system boundary faults:

| Fault Condition | System State | Safe Fail-Closed Behavior | Retry Behavior | Operator Action Required | Audit Log Requirement |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Policy Service Unavailable** | `REQUESTED` | Fails closed. Request rejected. | Operator manual retry after service recovery. | Check policy service daemon and DB connection pool. | `CONTAINMENT_POLICY_EVAL_FAILED` |
| **Authorization Service Down**| `POLICY_EVALUATED` | Action blocked. Request pauses until TTL. | Auto-retry within 300s freshness window. | Notify secondary approvers via out-of-band alert. | `CONTAINMENT_AUTH_SERVICE_UNAVAILABLE`|
| **Database Unavailable** | Any | Fails closed. Zero network mutations dispatched. | Reconnect with exponential backoff. | Database failover to replica. | Emitted to local disk syslog until DB up. |
| **Execution Adapter Timeout** | `EXECUTING` | Transitions to `VERIFYING_PENDING`. Success NOT inferred. | Independent verifier queries target state. | Inspect subsystem adapter logs. | `CONTAINMENT_EXECUTION_TIMEOUT` |
| **Worker Crash Mid-Execution**| `EXECUTING` | Advisory lock auto-released. Request flagged `ORPHANED`. | Supervisor worker inspects target state before retrying. | Review dead worker stack trace. | `CONTAINMENT_WORKER_CRASH_DETECTED` |
| **Network Partition (Cloud-Subsys)**| `EXECUTING` | Adapter aborts dispatch. Request remains unexecuted. | Retry up to 3 times under advisory lock. | Inspect VPC routing and gateway status. | `CONTAINMENT_ADAPTER_NETWORK_FAULT` |
| **Adapter Success, DB Commit Fails**| External Mutated, DB Uncommitted | Target is contained; DB rollback leaves request unrecorded. | 5E Reconciliation Worker detects untracked target mutation. | Reconciles DB request ledger to match target state. | `CONTAINMENT_RECONCILIATION_CORRECTED` |
| **DB Commits, Adapter Fails** | DB says `EXECUTED`, Target Unchanged | Verifier detects mismatch; flags `VERIFICATION_FAILED`. | Auto-dispatches compensating rollback or re-execution. | High-priority alert to Security Officer. | `CONTAINMENT_VERIFICATION_DISCREPANCY`|
| **Ambiguous Subsystem Response**| `EXECUTING` | Does not assume success. Transitions to `VERIFYING_PENDING`. | Verifier queries target 3 times over 15 seconds. | Manual verification by analyst if inconclusive. | `CONTAINMENT_RESPONSE_AMBIGUOUS` |
| **Verification Disagreement** | Target state diverged from expected | Flags `VERIFICATION_FAILED`. Emits Critical Alert. | No auto-retry. Freezes further containment on target. | Security Officer conducts manual target audit. | `CONTAINMENT_VERIFICATION_FAILED` |
| **Stale Authorization (TTL > 300s)**| `AWAITING_AUTH` | Request transitions to `EXPIRED`. Zero execution. | Denied. Requires new request and fresh approval. | Submit fresh containment request. | `CONTAINMENT_EXPIRED` |
| **Stale Generation Rollover** | 5D rolled over to $N+1$ | Pre-execution CAS check fails. Request rejected. | Denied. Must re-evaluate under new generation. | Re-triage incident under Generation $N+1$. | `CONTAINMENT_STALE_GEN_REJECTED` |
| **Target State Diverged (TOCTOU)**| Target modified externally | CAS revalidation fails. Execution aborted. | Denied. Re-evaluate policy against current state. | Inspect external target mutations. | `CONTAINMENT_TOCTOU_ABORT` |
| **Duplicate / Concurrent Request**| Parallel requests on same Intent | Advisory lock serializes; 2nd blocks and returns 1st result. | No-op. Cached result returned. | None (Handled gracefully). | `CONTAINMENT_DUPLICATE_SUPPRESSED` |
| **Replayed Auth Signature** | Nonce already recorded | Unique constraint on `auth_nonce` raises DB conflict. | Denied permanently. | Investigate suspected replay attack. | `CONTAINMENT_REPLAY_ATTACK_BLOCKED` |
| **Audit Service Failure** | During log emission | Entire containment transaction rolls back atomically. | Retry whole transaction once. | Check audit storage volume and KMS status. | System Panic Alarm to Security Lead. |

---

## 11. Blast-Radius Model & Anti-Escalation Firewall

To protect national examination integrity, every containment action is mathematically bounded within an explicit hierarchy:

```
Level 1: Single Session        (Max Entity: 1 Session)
Level 2: Single Candidate      (Max Entity: 1 Candidate / All Devices)
Level 3: Single User Account   (Max Entity: 1 System User / Invigilator)
Level 4: Single Question Obj   (Max Entity: 1 Question Variant)
Level 5: Question Pool Item    (Max Entity: 1 Blueprint Item in Future Forms)
Level 6: Examination Centre    (Max Entity: 1 Physical Facility - Restricted Ops)
Level 7: Examination Form      (Max Entity: 1 Form Variant in Single Slot)
Level 8: National Exam Cohort  (ENTIRE EXAM - CATEGORICALLY PROHIBITED FROM 5E)
```

### Anti-Escalation Firewall Rules:
1. **Mathematical Scope Limits**:
   ```python
   MAX_SCOPE_LIMITS = {
       "ACT_CAND_SESSION_TERM": 1,
       "ACT_CAND_SESSION_SUSP": 1,
       "ACT_ACCT_DISABLE": 1,
       "ACT_Q_PREVENT_ASSIGN": 1,
       "ACT_CENTRE_RESTRICT": 1,
   }
   ```
2. **Prohibition of Implicit Scope Expansion**:
   An approved request for Level 1 can **never** execute against Level 2 or Level 6 without submitting a completely new containment request, undergoing independent policy evaluation, and satisfying the higher tier's authorization requirements.
3. **Escalation Anomaly Filter**:
   If more than 5 Level 1 requests targeting the same exam centre are submitted within a 60-second window, the coordinator triggers a **Scope Escalation Anomaly**, halts automated processing, and mandates human review by a `SUPER_ADMIN`.

---

## 12. Re-Evaluated Containment Action Catalogue

Rev-02 rigorously re-evaluates all 13 containment actions, establishing concrete ownership, operational constraints, and phase assignments:

| Action ID | Name & Target | Risk | Blast Radius | Reversibility | Phase | Auth Required | Dual Control? | Executor Adapter | Verifier Service | Rollback Protocol | Emergency Eligible? |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- | :--- | :--- | :---: |
| `ACT_CAND_SESSION_TERM` | Terminate Candidate Session | LOW | Single Session (1) | REVERSIBLE | **5E** | `SECURITY_OFFICER` | NO | `SessionAdapter` | `SessionVerifier` | Re-login allowed if window open | **YES** |
| `ACT_CAND_SESSION_SUSP` | Suspend Session (Proctor Check)| LOW | Single Session (1) | REVERSIBLE | **5E** | `SECURITY_OFFICER` | NO | `SessionAdapter` | `SessionVerifier` | Proctor un-suspends session | **YES** |
| `ACT_CAND_REAUTH_REQ` | Force Biometric/MFA Re-auth | LOW | Single Session (1) | REVERSIBLE | **5E** | `SECURITY_OFFICER` | NO | `SessionAdapter` | `SessionVerifier` | Candidate completes MFA challenge | NO |
| `ACT_ACCT_DISABLE` | Disable User/Candidate Account | MEDIUM | Single Account (1) | REVERSIBLE | **5E** | `SECURITY_OFFICER` | NO | `AccountAdapter` | `AccountVerifier` | Supervisory account reinstatement | **YES** |
| `ACT_ACCT_TOKEN_REVOKE` | Revoke All Refresh Tokens | MEDIUM | Single Account (1) | REVERSIBLE | **5E** | `SECURITY_OFFICER` | NO | `AccountAdapter` | `AccountVerifier` | Re-authenticate on next request | NO |
| `ACT_Q_PREVENT_ASSIGN` | Prevent Question Assignment | HIGH | Question in Pool (1)| REVERSIBLE | **5E** | `SEC_OFFICER` + `SUPER`| **YES** | `ContentAdapter` | `ContentVerifier` | Unflag question in blueprint pool | **YES** |
| `ACT_Q_QUARANTINE_OBJ` | Dynamic Question Substitution | HIGH | Question Variant | PARTIAL | **DEFERRED** | Dual `SUPER_ADMIN` | **YES** | Delivery Subsys | Psychometric Ver | Post-exam scoring compensation | NO |
| `ACT_CENTRE_RESTRICT` | Restrict Centre Dispatch | HIGH | Single Centre (1) | PARTIAL | **5E** | `SEC_OFFICER` + `SUPER`| **YES** | `CentreAdapter` | `CentreVerifier` | Lift operational restriction | NO |
| `ACT_CENTRE_SUSPEND` | Suspend Centre Operations | CRITICAL| Entire Centre | IRREVERSIBLE | **DEFERRED** | Dual `SUPER_ADMIN` | **YES** | Edge Gateway | Independent Audit| Re-schedule examination slot | NO |
| `ACT_CRYPTO_KEY_INVAL` | Invalidate Session Key | LOW | Single Session (1) | REVERSIBLE | **5E** | `SECURITY_OFFICER` | NO | `CryptoAdapter` | `CryptoVerifier` | Renegotiate ephemeral ECDH key | NO |
| `ACT_CRYPTO_ROT_MASTER`| Rotate Master Exam CMK | CRITICAL| Entire Slot | IRREVERSIBLE | **DEFERRED** | Dual `SUPER_ADMIN` | **YES** | AWS KMS CMK | CloudTrail Ver | Disaster recovery protocol only | NO |
| `ACT_FORM_SUSPEND` | Suspend Exam Form Variant | CRITICAL| Candidates on Form| PARTIAL | **5E** | Dual `SUPER_ADMIN` | **YES** | `ExamAdapter` | `ExamVerifier` | Re-enable form for unstarted slots| NO |
| `ACT_EXAM_TERMINATE` | National Exam Termination | DISASTER| Entire Examination | IRREVERSIBLE | **PROHIBITED**| Board Statutory | **OUT OF SCOPE**| N/A | N/A | Formal Government Re-examination | **NEVER** |

---

## 13. Policy Versioning & Immutability

1. **Policy Specification Model**:
   Policies are defined as immutable declarative JSON documents:
   ```json
   {
     "policy_id": "POL-CONTAIN-2026-CORE",
     "policy_version": "v02.1",
     "effective_from": "2026-09-01T00:00:00Z",
     "effective_to": "2026-12-31T23:59:59Z",
     "rules": [
       {
         "rule_id": "RULE-R01-SESSION-TERM",
         "action_type": "ACT_CAND_SESSION_TERM",
         "min_incident_severity": "MEDIUM",
         "allowed_requester_roles": ["SECURITY_OFFICER", "SUPER_ADMIN"],
         "requires_dual_control": false,
         "max_blast_radius": 1
       }
     ]
   }
   ```
2. **Policy Fingerprinting**:
   $$\text{PolicyFingerprint} = \text{SHA-256}(\text{CanonicalJCS}(\text{PolicyDocument}))$$
3. **Decision Binding**:
   Every policy decision records:
   $$\text{DecisionRecord} = \{ \text{PolicyID}, \text{PolicyVersion}, \text{PolicyFingerprint}, \text{IncidentID}, \text{Generation}, \text{Action}, \text{TargetURN}, \text{Decision}, \text{Timestamp} \}$$
4. **Handling Policy Updates Mid-Flight**:
   If Policy v1 is superseded by Policy v2 after authorization but before execution, the execution coordinator detects the mismatch:
   $$\text{Assert}(\text{request}.\text{policy\_fingerprint} == \text{ActivePolicyCatalog}.\text{current\_fingerprint})$$
   If superseded, execution halts immediately with `ERR_POLICY_SUPERSEDED`. The request transitions to `EXPIRED`. Zero execution under stale policy.

---

## 14. Cryptographic Replay Protection Protocol

To guarantee that an authorization signed for Incident $A$, Generation 1, Target $X$ can **never** be replayed against Incident $B$, Generation 2, or Target $Y$:

```
                             AUTHORIZATION CHALLENGE BINDING
+─────────────────────────────────────────────────────────────────────────────+
|  IntentKey        : SHA-256(IncidentID || Gen || Action || TargetURN)       |
|  PolicyFingerprint: SHA-256(PolicyDocument)                                 |
|  TargetSnapshot   : SHA-256(TargetURN || TargetUUID || TargetVersion)       |
|  AuthNonce        : Cryptographically Secure Random 256-bit Hex Token       |
|  FreshnessWindow  : ExpiresAt = IssuedAt + 300 Seconds                      |
+──────────────────────────────────────┬──────────────────────────────────────+
                                       │ Signed by Approver Private Key
                                       ▼
                     Cryptographic Authorization Signature
```

### Replay Defense Verification Steps:
1. **Nonce Consumption**: When the execution coordinator processes the authorization, it attempts an atomic insert into the database table `containment_auth_nonces`:
   ```sql
   INSERT INTO containment_auth_nonces (auth_nonce, request_id, consumed_at)
   VALUES (:auth_nonce, :request_id, NOW());
   ```
   If `auth_nonce` already exists, PostgreSQL throws a unique constraint violation. Execution aborts with `ReplayAttackDetectedError`.
2. **Generation Re-Verification**: Evaluates `request.incident_generation == incident.generation`. An old authorization signed for Generation 1 cannot execute against Generation 2.
3. **Freshness Check**: Verifies `NOW() <= request.authorization_expires_at`. Replayed tokens outside the 300-second window fail closed.

---

## 15. Audit Lifecycle & Cryptographic Sealing

Phase 3C-5E strictly reuses the existing canonical `AuditService` and respects the Phase 3C-4A/4B sealing model:

```
[Containment Event Occurs]
            │
            ▼
   (1) AUDIT LOGGED
   - Inserted into PostgreSQL audit_logs table via Mode B transaction.
   - Computes event_hash = SHA-256(prev_hash || canonical_payload).
   - Guarantees immediate evidentiary proof.
            │
            ▼
   (2) AUDIT CHAINED
   - Linked to preceding audit log via linear cryptographic hash chain.
   - Protected by database trigger blocking UPDATE and DELETE.
            │
            ▼
   (3) AUDIT INCORPORATED
   - Background Sealer Worker gathers unsealed audit records into an Epoch block.
   - Epoch manifest computes Merkle root of all enclosed audit hashes.
            │
            ▼
   (4) AUDIT SEALED
   - Sealer invokes KMS to sign Epoch manifest.
   - Produces seal_block_hash and sealed_epoch_id.
   - Guarantees multi-year tamper-evident non-repudiation.
            │
            ▼
   (5) VERIFICATION PROVEN
   - 5D Incident seal_verification_status transitions to SEALED_VERIFIED.
```

### Invariant:
An event is **NEVER** referred to as "sealed" merely because it was inserted into `audit_logs`. It is `AUDIT_LOGGED` immediately, and becomes `AUDIT_SEALED` only after successful KMS epoch block closure.

---

## 16. Emergency Containment Protocol

The emergency protocol provides a tightly regulated, audit-bound path for acute crises during live examination windows:

```
+─────────────────────────────────────────────────────────────────────────────+
|                     EMERGENCY BREAK-GLASS PROTOCOL                          |
+─────────────────────────────────────────────────────────────────────────────+
| Eligible Actions       | ACT_CAND_SESSION_TERM, ACT_ACCT_DISABLE,           |
|                        | ACT_Q_PREVENT_ASSIGN only.                         |
| Ineligible Actions     | Centre suspension, form suspension, key rotation.  |
| Trigger Authority      | SUPER_ADMIN with active Break-Glass Hardware Token |
| Dual Control Bypass    | Permitted strictly for HIGH risk subset.           |
| CRITICAL Bypass        | CATEGORICALLY PROHIBITED.                          |
| Maximum Scope Limit    | 1 Entity per request.                              |
| Time-To-Live           | Exactly 15 minutes (900 seconds).                  |
| Audit Event            | CONTAINMENT_EMERGENCY_OVERRIDE (Risk Score 1.0)     |
| Retrospective Review   | Mandatory sign-off by Examination Board within 12h.|
+─────────────────────────────────────────────────────────────────────────────+
```

### Abuse Defense:
- If a `SUPER_ADMIN` invokes emergency break-glass, an immediate high-priority webhook alert is dispatched to all members of the Central Examination Oversight Committee.
- If the action is not ratified by the Board within 12 hours, the administrative credentials of the invoking super-admin are automatically flagged for security review.

---

## 17. Expanded Threat Model (14 Specialized Vectors)

Rev-02 details explicit attack paths, controls, and residual risks for the 14 core threats:

| Threat ID | Threat Vector | Attack Path & Exploitation Scenario | Preventive Control | Detective Control | Recovery Control | Residual Risk |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **TH-01** | Compromised `SUPER_ADMIN` | Attacker steals super-admin credentials to terminate all exams. | Two-Person Control on HIGH/CRITICAL; CRITICAL requires distinct second super-admin. | Real-time dual authorization push alerts; session anomaly detection. | Emergency session freeze; credential revocation via second admin. | LOW |
| **TH-02** | Compromised Executor | Compromised worker falsifies execution responses. | Executor has ZERO verification rights; independent verifier queries target state out-of-band. | Verifier detects target state unchanged; flags `VERIFICATION_DISCREPANCY`. | Quarantine executor worker host; dispatch backup worker. | LOW |
| **TH-03** | Compromised Verifier | Compromised verifier falsely attests containment succeeded. | Verifier must return raw cryptographic evidence payload hashed from target DB. | Cryptographic reconciliation worker re-checks during epoch sealing. | Verifier credentials revoked; incident reopened for investigation. | LOW |
| **TH-04** | Compromised Centre | Compromised centre admin attempts to disrupt local test sessions. | Autonomous local containment PROHIBITED in 5E; centre cannot execute containment. | Central API gateway rejects unauthorized centre-originated directives. | Centre placed in restricted dispatch; proctoring inspection team deployed.| NEGLIGIBLE |
| **TH-05** | Offline Cache Tampering | Attacker tampers with local policy cache on disconnected server. | Offline local containment PROHIBITED in 5E; zero offline policy cache deployed. | N/A (Architecture avoids offline trust boundary). | N/A | NEGLIGIBLE |
| **TH-06** | Hardware Token Theft | Physical FIDO2 token stolen from Security Officer. | Token protected by mandatory biometric / PIN; requires active authenticated IdP session. | Geolocation and device fingerprint mismatch alerts on token presentation. | Immediate token revocation in IAM; active session termination. | LOW |
| **TH-07** | Authorization Replay | Valid authorization capture resubmitted against new exam. | Unique constraint on `(intent_key, auth_nonce)`; strict 300s TTL. | Database unique violation logged as `REPLAY_ATTACK_DETECTED`. | Request rejected with HTTP 409 Conflict. | NEGLIGIBLE |
| **TH-08** | Target Substitution | Attacker replaces benign target ID with critical exam form ID. | Authorization signature signs canonical hash of `(TargetURN || Scope || Action)`. | Coordinator recomputes target hash; mismatch halts execution. | Request cancelled; analyst account locked for security review. | NEGLIGIBLE |
| **TH-09** | Stale Policy Exploitation| Attacker executes action authorized under revoked policy version. | Coordinator revalidates policy fingerprint against active catalog prior to dispatch. | Evaluator detects superseded policy version. | Request transitions to `EXPIRED_POLICY_SUPERSEDED`. | NEGLIGIBLE |
| **TH-10** | Stale Generation Rollover| Attacker executes action on Gen 1 after Gen 2 rollover. | Request strictly binds `generation == incident.generation`; atomic CAS check. | 5D CAS update rejects stale generation. | Request transitions to `EXPIRED_STALE_GENERATION`. | NEGLIGIBLE |
| **TH-11** | Scope Escalation | Attacker alters scope payload from single session to entire centre. | Scope object validated against mathematical ceiling; wildcard targets rejected. | Policy engine checks `scope.max_allowed_entities <= POLICY_LIMIT`. | Rejection with `DENY_BLAST_RADIUS_EXCEEDED`. | NEGLIGIBLE |
| **TH-12** | Emergency Override Abuse | Malicious admin invokes emergency break-glass for non-crisis. | Restricted to single session/account; logs risk 1.0; 12h mandatory Board review. | Immediate high-priority Board notification; daily executive audit report. | Administrative suspension if unratified within 12 hours. | LOW |
| **TH-13** | Malicious 2nd Approver | Rogue second approver colludes with rogue requester. | Distinct principals enforced; full audit attribution logged with IP/device hashes. | AuditService logs dual signatures; SIEM cross-correlates analyst collusion. | Forensic revocation and prosecution under examination integrity statute.| LOW |
| **TH-14** | DoS on Approver Roster | Attacker floods approvers with spam to delay critical response. | Ingress rate-limiting on requests; prioritization queue for CRITICAL incidents. | Alert queue latency metric `bsea_containment_auth_latency_seconds`. | Escalation to emergency on-call roster. | LOW |

---

## 18. Implementation Boundary: Prototype vs. Production

To maintain strict engineering integrity, Rev-02 delineates what is implemented in Phase 3C versus what represents production target hardening:

```
+─────────────────────────────────────────────────────────────────────────────+
| PROTOTYPE IMPLEMENTATION (Phase 3C)  | PRODUCTION TARGET (National Rollout) |
+──────────────────────────────────────+──────────────────────────────────────+
| 1. Cryptographic MockKMS:            | 1. Hardware Security Module (HSM):   |
|    - Software ECDSA / Ed25519 mock   |    - FIPS 140-2 Level 3 Hardware HSM |
|    - Validates signing protocols     |    - Dedicated AWS KMS Multi-Region  |
|                                      |                                      |
| 2. Execution Coordinator:            | 2. Distributed Queue Workers:        |
|    - In-process asyncio async tasks  |    - AWS SQS FIFO + Celery/Temporal  |
|    - PostgreSQL advisory locks       |    - Guaranteed message durability   |
|                                      |                                      |
| 3. Target Subsystems:                | 3. Distributed Production Stores:    |
|    - Local PostgreSQL tables         |    - Amazon ElastiCache Redis Cluster|
|    - Direct database queries         |    - mTLS Outbound Centre Gateways   |
|                                      |                                      |
| 4. Audit Storage:                    | 4. Forensic Cold Storage:            |
|    - Local PostgreSQL audit_logs     |    - AWS S3 Object Lock (WORM)       |
|    - In-database linear hash chain   |    - Multi-region immutable replica  |
+──────────────────────────────────────+──────────────────────────────────────+
```

---

## 19. Concrete Acceptance Criteria for Future Implementation

Phase 3C-5E implementation will be certified complete only when all of the following criteria are proven by automated tests:

1. **Zero Autonomous Detection Containment**: No detection rule in 5C can directly execute containment without traversing 5E policy evaluation.
2. **IntentKey Invariance**: Two distinct authorized principals requesting the same logical action generate the identical `IntentKey` and share execution state.
3. **Inviolable Dual Control**: An attempt by a requester to sign as second authorizer raises `DualControlSelfApprovalError`.
4. **Zero Single-Person Bypass on CRITICAL**: Single-person approval for `CRITICAL` risk actions is rejected under all circumstances.
5. **TOCTOU Revalidation**: Changing the target session version between authorization and execution triggers atomic rollback with `TOCTOUConflictError`.
6. **Generation Binding**: A request authorized for Generation 1 fails closed if Generation 2 has rolled over.
7. **Target Substitution Defense**: Modifying target URN or UUID in transit fails cryptographic verification.
8. **Scope Anti-Escalation**: Any request containing wildcards or exceeding max entity limits is rejected by the policy engine.
9. **Replay Rejection**: Resubmitting a consumed authorization nonce throws a database unique constraint violation.
10. **Executor/Verifier Decoupling**: The executor adapter cannot declare verification; verification must be attested by the independent verifier service.
11. **Timeout Fail-Closed**: An execution adapter timeout sets request state to `VERIFYING_PENDING` and never assumes success.
12. **5D Boundary Integrity**: 5E updates 5D solely via `transition_status()` with observational containment metadata.
13. **Full Audit Integration**: All 15 containment audit events are logged via canonical `AuditService` with `resource_type = 'CONTAINMENT_REQUEST'`.
14. **Zero Regression**: All existing 271 repository baseline tests pass without failure.

---

## 20. Final Architecture Status & Review Summary

### A. Decisions Made in Rev-02
1. **Decoupled Intent Identity**: Removed RequesterID from the idempotency key; defined 4-tier identity hierarchy (IntentKey, RequestID, AuthorizationID, ExecutionID).
2. **Strict 5D Boundary**: Confined 5E interaction with 5D strictly to invoking 	ransition_status() with observational metadata.
3. **Question Containment**: Prohibited mid-exam dynamic reserve question replacement; limited 5E to future assignment prevention (ACT_Q_PREVENT_ASSIGN) and post-exam psychometric compensation.
4. **Offline Centre Operation**: Formally prohibited autonomous offline local containment; centres operate in local delivery mode during WAN partitions.
5. **Emergency Authorization**: Rejected automatic timeout bypass; strictly enforced dual control on CRITICAL; bounded HIGH risk emergency override to 15-minute TTL and 12-hour Board review.
6. **Separation of Duties**: Formally segregated Requester, Approver, Executor, and Verifier into 4 distinct roles.

### B. Alternatives Considered & Rejected
- *Including RequesterID in Idempotency*: Rejected due to parallel duplicate execution risks.
- *Dynamic In-Flight Reserve Question Substitution*: Rejected due to psychometric calibration fragility and offline centre failure.
- *Local Centre Autonomous Policy Cache*: Rejected due to clock rollback vulnerability and rogue centre admin insider risk.
- *120-Second Timeout Emergency Bypass*: Rejected because timeout must never imply authorization.

### C. Security Invariants
- Detection (5C) and correlation (5D) have zero direct containment authority.
- Dual authorization cannot be satisfied by one principal.
- Containment requests are strictly bound to one incident generation.
- The executor cannot verify its own execution.
- Any ambiguity or timeout fails closed.
- Every containment action is strictly auditable and attributable.

### D. Trust Boundaries
- Zone 0 (Detection): Zero execution authority.
- Zone 1 (Incident Ops): Proposal authority only.
- Zone 2 (Policy & Dual Auth): Cryptographic authorization boundary.
- Zone 3 (Execution Coordinator): Advisory-lock serialized execution.
- Zone 4 (Independent Verification): Out-of-band state inspection.
- Zone 5 (Forensic Audit): Immutable Mode B audit trail and KMS sealing.

### E. Remaining Open Questions
1. Formalization of the post-exam psychometric scoring compensation formula for quarantined items (deferred to Scoring Subsystem).
2. Selection of production distributed queue framework (AWS SQS FIFO vs. Temporal.io) during deployment planning.

### F. Implementation Acceptance Criteria
1. Zero detection rules directly execute containment.
2. Two distinct principals generate identical IntentKey for the same logical intent.
3. Requester cannot sign as second authorizer.
4. Zero single-person bypass for CRITICAL risk actions.
5. TOCTOU revalidation aborts if target session or incident state mutates.
6. Stale generation cannot execute containment.
7. Independent verifier queries target state out-of-band; executor cannot self-certify.
8. Every containment action logs to canonical AuditService.
9. All 271 existing regression tests pass with zero regressions.

### G. Recommended Test Matrix
- TC-5E-01: Policy rejection of unverified/triage incidents.
- TC-5E-02: Anti-escalation firewall rejects wildcard and out-of-bounds scope.
- TC-5E-03: Two-Person Control rejects self-approval.
- TC-5E-04: Expired authorization TTL (> 300s) rejected.
- TC-5E-05: Generation rollover ( \rightarrow N+1$) causes stale execution rejection.
- TC-5E-06: Parallel identical intent requests serialized under advisory lock.
- TC-5E-07: Target substitution attack detected via hash mismatch.
- TC-5E-08: Out-of-band verifier detects execution discrepancy.
- TC-5E-09: Execution timeout triggers fail-closed VERIFYING_PENDING (no success assumed).
- TC-5E-10: Audit logging failure aborts containment transaction.

### H. Prototype Limitations
1. Cryptography uses in-memory MockKMS rather than hardware HSM.
2. In-process asyncio execution rather than distributed durable SQS FIFO workers.
3. Single-node PostgreSQL rather than Multi-AZ RDS cluster.
4. Direct database session queries rather than distributed ElastiCache Redis cluster.

---

## Final Architecture Status

# ARCHITECTURE READY FOR REVIEW

Phase 3C-5E Architecture Review Rev-02 resolves all architectural conflicts, eliminates ambiguities, and establishes an airtight, mathematically bounded specification. **No implementation code should be written until human reviewers grant explicit approval of Rev-02.**
