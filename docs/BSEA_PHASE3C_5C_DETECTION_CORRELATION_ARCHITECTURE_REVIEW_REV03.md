# B-SEA Phase 3C-5C — Detection & Correlation Foundation
## Forensic Architecture & Design Review (Rev-03)

| Document Metadata | Authoritative Specification |
| :--- | :--- |
| **Document ID** | `BSEA-ARCH-3C-5C-REV03` |
| **System** | Bharat Secure Examination Architecture (B-SEA) |
| **Component** | Security Intelligence, Correlation Engine & Shadow Detection |
| **Accepted Baseline** | `d6d430f929caa90ef8f0390abeceaa362c302ace` (`HEAD == origin/main`) |
| **Regression Baseline** | 220 passed, 5 skipped, 0 failed (225 collected) |
| **Current Status** | **ARCHITECTURE APPROVED FOR IMPLEMENTATION PENDING USER AUTHORIZATION** |
| **Operational Phase** | Phase 3C-5C (Building upon Phase 3C-5B Production Observability) |
| **Security Mode** | **STRICT SHADOW MODE (ADVISORY ONLY — ZERO AUTONOMOUS INTERVENTION)** |

---

## 1. Executive Summary

Phase 3C-5B established an immutable, production-grade **Observability Foundation** for B-SEA, introducing structured JSON logging with 3-tier recursive redaction, W3C distributed tracing, a strictly bounded 16-metric Prometheus registry (520 base time series, 1,390 expanded series, hard ceiling of 1,400), and automated CloudWatch alarms.

While Phase 3C-5B answers *"What is happening in the system right now?"*, **Phase 3C-5C** addresses the higher-order question: ***"Are individual security events part of an anomalous, coordinated, or adversarial pattern across space and time?"***

Phase 3C-5C introduces the **Detection & Correlation Foundation** designed under the strict paradigm:
```
Security Events (Audit/Auth/KMS/App)
       ↓
Durable Audit-Chain-to-SQS Dispatch (Amazon SQS in Prod / Async Queue in Proto)
       ↓
Detection Worker(s) (Dedicated ECS Task in Prod / In-Process Task in Proto)
       ↓
Event Normalization (Deterministic Internal Schema: SecurityEventNormalized)
       ↓
Correlation State (Redis ZSET in Prod / In-Memory Ring Buffer in Proto)
       ↓
Deterministic Detection Rule Engine (Versioned, Pure Stateless Evaluation)
       ↓
Security Signals (Advisory Detections with Explainable Evidence References)
       ↓
Shadow Mode (Zero Autonomous Blocking / Containment / Alteration)
       ↓
Structured Telemetry & Alerting (CloudWatch Logs Metric Filters & Alarms)
```

Rev-03 represents the final architecture reconciliation, resolving five critical precision items:
1. **Durable Audit-Chain-to-SQS Dispatch**: Corrected terminology; eliminated invalid "transactional outbox" claims. Clarified at-least-once delivery, dispatcher checkpointing without schema modification, and mandatory worker-side idempotency.
2. **CloudTrail KMS Management-Event Correlation**: Standardized terminology to "AWS CloudTrail KMS API management events"; replaced absolute claims with the rule that missing or delayed CloudTrail evidence alone is insufficient to classify activity as malicious.
3. **Redis Degradation Semantics**: Defined the explicit failure model when Redis is unavailable, establishing that workers operate with reduced correlation coverage without affecting core examination security controls.
4. **Rule-J Exact Boolean Logic**: Expressed the rule trigger as a strictly disambiguated Boolean expression: $(A \land B) \lor C$.
5. **Rule-A Identity Correlation Semantics**: Formalized three discrete identity correlation levels (`ACTOR_MATCH`, `IP_MATCH_ONLY`, `INSUFFICIENT_IDENTITY`), preventing false equivalence between IP addresses and actor identities.

---

## 2. Baseline / Repository Freeze

The architecture and design review is strictly anchored to the accepted baseline:
- **Repository Commit**: `d6d430f929caa90ef8f0390abeceaa362c302ace`
- **Git Branch**: `main` (`HEAD == origin/main`)
- **Working Tree**: Clean (zero modified tracked files)
- **Regression Suite**: 220 passed, 5 skipped, 0 failed (225 total tests collected)
- **Database Target**: Amazon RDS PostgreSQL 16 Multi-AZ with RDS Proxy (NOT Amazon Aurora)

### Strictly Preserved Repository Boundaries
The following files and subsystems remain **100% frozen and unmodified**:
- `backend/app/core/models.py`: No schema modifications.
- `backend/alembic/`: No new migrations.
- `backend/app/modules/audit/sealer.py`: Sealer cryptographic hash chain and Merkle tree logic remain untouched.
- `backend/app/modules/audit/quarantine.py`: Dual-custody poison quarantine remains untouched.
- `backend/app/crypto/kms_interface.py`: KMS signing, decryption, and derivation wrappers remain untouched.
- `backend/app/modules/security/service.py`: Legacy prototype security service remains untouched; deprecation is deferred.
- `terraform/`: No infrastructure modifications.

---

## 3. Rev-02 Findings Reconciliation

Rev-02 established a robust distributed execution framework but left five areas requiring forensic reconciliation. Rev-03 resolves each item explicitly:

| Area | Rev-02 State | Rev-03 Reconciled Architecture |
| :--- | :--- | :--- |
| **1. Outbox Semantics** | Incorrectly claimed "Transactional Outbox" without an outbox database table. | Corrected to **"Durable Audit-Chain-to-SQS Dispatch"**. PostgreSQL persistence is authoritative. SQS operates at-least-once. Dispatcher checkpointing uses memory/Redis without schema changes. |
| **2. CloudTrail Terminology** | Used "KMS data-plane events" and claimed "Zero False Malicious Flagging". | Standardized to **"AWS CloudTrail KMS API management events"**. Replaced claim with: *"Missing or delayed CloudTrail evidence alone is insufficient to classify activity as malicious."* |
| **3. Redis Degradation** | Loosely stated that workers fall back to local memory without bounding coverage loss. | Formalized the **Degraded Correlation Failure Model**. Local worker memory operates with reduced correlation coverage; telemetry records degraded status; zero impact on core exam security controls. |
| **4. Rule-J Logic** | Used ambiguous "AND/OR" prose combining backlog and lag. | Formalized exact Boolean logic: **$(A \land B) \lor C$**, separating `backlog_records` ($A$), `sealer_failures`/`sealer_lock_timeouts` ($B$), and `oldest_unsealed_age_seconds` ($C$). |
| **5. Rule-A Correlation** | Allowed IP fallback when `actor_id` is null without distinguishing correlation strength. | Established three explicit correlation strengths: **`ACTOR_MATCH`**, **`IP_MATCH_ONLY`**, and **`INSUFFICIENT_IDENTITY`**. Clarified that same IP does not equal same actor. |

---

## 4. Final Architecture Decisions

| Decision Area | Final Recommendation | Rationale & Justification |
| :--- | :--- | :--- |
| **A. Detection Execution Architecture** | **Dedicated ECS Fargate Worker (Option C)** for AWS Production;<br>**In-Process Engine (Option A)** for Local CI/Testing | Decouples detection CPU/memory overhead from student-facing API latency; enables independent horizontal auto-scaling based on queue depth. |
| **B. Event Delivery Mechanism** | **Amazon SQS (Standard Queue with KMS SSE + Worker Deduplication)** for Production;<br>**In-Process `asyncio.Queue`** for Local CI | SQS provides point-to-point delivery, native consumer backpressure, built-in dead-letter queues (DLQ) for malformed poison events, low operational complexity, and native KMS encryption. |
| **C. Correlation State Architecture** | **Amazon ElastiCache for Redis 7 (ZSET, non-authoritative)** for Production;<br>**In-Memory Ring Buffer (`collections.deque`)** for Local CI | Redis sorted sets allow efficient sliding-window range queries across distributed workers. Redis is strictly non-authoritative; PostgreSQL `audit_logs` remains the sole immutable system of record. |
| **D. CloudTrail Ingestion Mechanism** | **CloudWatch Logs Subscription Filter** streaming CloudTrail KMS events to the B-SEA telemetry log group | Provides near real-time, managed log streaming with low latency and zero Lambda maintenance overhead compared to S3 batch polling. |
| **E. Legacy Security Service** | **Leave `backend/app/modules/security/service.py` strictly unchanged** in Phase 3C-5C | Avoids cross-module regressions during 5C. Formal deprecation, database refactoring, and UI migration are deferred to Phase 5D. |

---

## 5. Durable Audit-Chain-to-SQS Dispatch Model

Phase 3C-5C explicitly **does NOT introduce a transactional outbox table**. Database models and Alembic migrations are strictly frozen.

Instead, the production event delivery pipeline operates via **Durable Audit-Chain-to-SQS Dispatch**:
```
Client Request
      ↓
API Business Logic
      ↓
PostgreSQL Transaction (Mode A or Mode B)
      ↓
AuditLog Committed to Database (AUTHORITATIVE SYSTEM OF RECORD)
      ↓
Post-Commit Asynchronous SQS Dispatcher
      ↓
Amazon SQS Standard Queue (bsea-production-security-events)
```

### Core Invariants & Guarantees
1. **Authoritative Persistence**: PostgreSQL audit persistence is strictly authoritative. Detection consumes durably persisted audit events.
2. **Defensible Delivery Guarantee**: Every audit event successfully committed to PostgreSQL remains durably available for subsequent detection dispatch, subject to continued database and dispatcher availability.
3. **No Exactly-Once Delivery Claim**: The 5C design does NOT provide transactional-outbox semantics. SQS provides at-least-once delivery; network retries or process restarts may cause duplicate messages.
4. **Dispatcher Checkpointing**: The dispatcher tracks its read position against `AuditLog.id` / `AuditLog.created_at` using in-memory cursors or transient Redis keys (`bsea:dispatcher:checkpoint`), without modifying immutable audit tables.
5. **Crash Recovery Scenario**:
   - `AuditLog` row commits successfully to PostgreSQL.
   - The API task or dispatcher crashes before SQS dispatch succeeds.
   - The detection event is temporarily absent from SQS.
   - Upon recovery or failover, the dispatcher resumes scanning committed `AuditLog` records from the last verified checkpoint and publishes the missing event to SQS.
   - The dispatcher **NEVER modifies, mutates, or marks immutable audit history**.

---

## 6. SQS Delivery Semantics & Dead-Letter Queue

1. **Queue Configuration**: Amazon SQS Standard Queue (`bsea-production-security-events`) encrypted at rest using an AWS KMS Customer Managed Key (CMK).
2. **Delivery Characteristics**:
   - **At-Least-Once Delivery**: SQS guarantees delivery of every message at least once, but duplicate deliveries can occur under network partitions or consumer visibility timeouts.
   - **Loose Ordering**: Standard SQS does not guarantee strict FIFO ordering. The detection engine does not rely on SQS arrival order; all correlation and sliding-window logic sorts events by their normalized canonical UTC `timestamp`.
3. **Visibility Timeout & Crash Handling**:
   - Visibility timeout is set to $30\text{s}$.
   - If a detection worker crashes during evaluation, the visibility timeout lapses and SQS re-delivers the message to a surviving worker.
4. **Dead-Letter Queue (DLQ) & Poison Event Isolation**:
   - Dead-Letter Queue: `bsea-production-security-events-dlq` (Retention: 14 days).
   - Redrive Policy: `maxReceiveCount = 5`.
   - Malformed JSON or unparseable event payloads that repeatedly trigger unhandled validation errors are permanently diverted to the DLQ after 5 attempts, preventing pipeline stalling without crashing workers.

---

## 7. Worker Idempotency & Deduplication

Because SQS operates with at-least-once delivery, worker-side deduplication and idempotency are mandatory.

### Deduplication Mechanism
1. **Event Identity**: Every event carries a globally unique `event_id` (UUIDv4) originated by `AuditLog.id`.
2. **Transient Deduplication Cache**:
   - Detection workers maintain an event deduplication window using Redis key `bsea:dedup:{event_id}` with a TTL of $600\text{s}$ (10 minutes).
   - In prototype mode, deduplication uses a fixed-size `collections.OrderedDict` LRU set (capacity $100,000$ IDs).
   - If `SET NX` fails, the event is recognized as a duplicate and silently acknowledged (`DeleteMessage`) without duplicate rule evaluation.
3. **Signal Idempotency Hash**:
   $$\text{SignalHash} = \text{SHA256}(\text{rule\_id} + \text{primary\_dimension\_value} + \text{window\_bucket})$$
   Where `window_bucket = floor(timestamp / time_window_seconds)`. This guarantees that even if overlapping events are processed concurrently by separate workers, only one advisory `SecuritySignal` is generated per window bucket.

---

## 8. Redis Correlation and Degraded Mode

Redis 7 (Amazon ElastiCache Multi-AZ) is used exclusively for transient sliding-window correlation state.

### 8.1 Non-Authoritative Principle
- PostgreSQL `audit_logs` is the **sole authoritative system of record**.
- Redis is strictly an ephemeral performance accelerator for temporal aggregation ($O(\log N)$ range queries).
- Redis state is **NEVER** authoritative for examination security, candidate status, or audit integrity.

### 8.2 Degraded Correlation Failure Model
When Redis experiences an outage, network partition, or failover, the detection system transitions into **Degraded Mode**:

```
[Normal Mode: Redis Available]
      ↓
Shared Multi-Worker Redis ZSETs
      ↓
Complete Distributed Sliding-Window Correlation
      ↓
Standard Advisory Telemetry

──────────────────────────────────────────────────────────────────

[Degraded Mode: Redis Unavailable]
      ↓
Workers Fall Back to Bounded Local Memory (Ring Buffer: N=50,000)
      ↓
Detection Operates with REDUCED CORRELATION COVERAGE
      ↓
Telemetry Emits: degraded_correlation=True
      ↓
NO Authentication Change
NO Authorization Change
NO Candidate Blocking
NO Audit Quarantine
NO Database Mutation
```

### Explicit Consequences of Degraded Mode
1. **Reduced Correlation Coverage**: In a multi-worker ECS Fargate cluster, a worker relying on local memory only observes events routed to its specific instance. Cross-worker sequences (e.g., 5 failures on Worker 1 followed by success on Worker 2) may be missed.
2. **Delayed or Partial Detections**: Temporal window aggregations may report partial counts until Redis recovers.
3. **Fail-Safe Core Security**: Core examination operations (candidate logins, question decryptions, submissions) proceed with **zero interruption**. Under **INVARIANT 2 and 15**, detection degradation cannot bypass or weaken core examination authorization controls.
4. **No Authoritative Memory Claims**: Local worker memory is explicitly non-authoritative and bounded ($N=50,000$ events); it does not attempt to synchronize across workers during Redis downtime.

---

## 9. CloudTrail KMS Management-Event Correlation

Application-side KMS operations (`_audit_kms_operation`) are reconciled with AWS CloudTrail KMS event streams.

### 9.1 Architectural Pipeline
```
AWS KMS (Sign / Decrypt / GenerateDataKey)
      ↓
AWS CloudTrail (API Management Events)
      ↓
Amazon CloudWatch Logs
      ↓
Subscription Filter (Pattern: { $.eventSource = "kms.amazonaws.com" })
      ↓
Detection / Correlation Reconciliation Engine
```

### 9.2 Reconciliation Dimensions
Correlation reconciles application-side audit records with CloudTrail records using:
- `kms_request_id` (AWS request identifier returned in API response headers).
- `kms_key_id` / KMS Key ARN.
- `operation` (e.g., `Sign`, `GenerateDataKey`, `Decrypt`).
- `timestamp` tolerance window ($\pm 60\text{s}$ to accommodate clock skew).
- `caller_identity` / IAM ARN.
- `status` / `errorCode`.

### 9.3 Four Explicit Reconciliation States

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                        CLOUDTRAIL / KMS RECONCILIATION STATES                           │
├──────────────────────┬──────────────────────────────────────────────────────────────────┤
│ STATE                │ MEANING & SEMANTICS                                              │
├──────────────────────┼──────────────────────────────────────────────────────────────────┤
│ CORRELATED           │ Application KMS event perfectly matches a CloudTrail KMS event   │
│                      │ by kms_request_id, key_arn, timestamp (±60s), and operation.     │
├──────────────────────┼──────────────────────────────────────────────────────────────────┤
│ UNRESOLVED           │ Application event is within the CloudTrail ingestion window      │
│                      │ (< 15 mins old); reconciliation is pending CloudTrail delivery.  │
├──────────────────────┼──────────────────────────────────────────────────────────────────┤
│ MISSING_EVIDENCE     │ CloudTrail event not found after > 15 minutes. May indicate      │
│                      │ CloudTrail trail latency or local mock execution in CI/testing.  │
├──────────────────────┼──────────────────────────────────────────────────────────────────┤
│ CONFLICTING_EVIDENCE │ CloudTrail record exists with different actor ARN, denied status,│
│                      │ or unexpected encryption context. Potential security anomaly.    │
└──────────────────────┴──────────────────────────────────────────────────────────────────┘
```

### Critical CloudTrail Correlation Rule
**Missing or delayed CloudTrail evidence alone is insufficient to classify activity as malicious.** AWS CloudTrail delivery latency (typically 1 to 15 minutes) is a standard operational characteristic of cloud logging pipelines. Missing CloudTrail evidence reflects transport delay or external service latency, not an active cryptographic attack.

---

## 10. Rule A-J Final Definitions

Ten deterministic detection rules are formally defined for Phase 3C-5C. **None are implemented in code yet.**

### RULE-A: Repeated Authentication Failures Followed by Success
- **Rationale**: Detects brute-force credential guessing that eventually succeeds.
- **Trigger**: $\ge 5$ `LOGIN_FAILURE` events within 300s followed by 1 `LOGIN` (SUCCESS).
- **Severity**: `HIGH` | **Window**: 300s.
- **Evidence**: Failure and success `audit_log_id`s, identity correlation strength.
- **False-Positive Risk**: Legitimate user retrying multiple password typos before success.
- **Implementation Status**: **AVAILABLE NOW** (`app/modules/auth/service.py`).

### RULE-B: Repeated Authorization Denials Followed by Privileged Access
- **Rationale**: Detects authorization probing, role escalation, or IDOR vulnerability probing followed by successful access.
- **Trigger**: $\ge 3$ `ACCESS_DENIED` events on sensitive resources within 600s followed by `ACCESS_GRANTED` on same `actor_id`.
- **Severity**: `HIGH` | **Window**: 600s.
- **Evidence**: Denial `audit_log_id`s, grant `audit_log_id`.
- **False-Positive Risk**: Reviewer accessing unassigned questions before admin completes assignment.
- **Implementation Status**: **AVAILABLE NOW** (`app/modules/questions/service.py`).

### RULE-C: High-Frequency Question-Access Denials
- **Rationale**: Detects unauthorized attempts to scrape unreleased papers or brute-force question IDs.
- **Trigger**: $\ge 10$ `CANDIDATE_ACCESS_DENIED_UNRELEASED` or `ACCESS_DENIED` within 60s from same `session_id` or `device_id`.
- **Severity**: `CRITICAL` | **Window**: 60s.
- **Evidence**: Sequence of denial `audit_log_id`s, `trace_id`s, `session_id`.
- **False-Positive Risk**: CBT secure browser network reconnection retry loop.
- **Implementation Status**: **AVAILABLE NOW** (`app/api/v1/candidates.py`).

### RULE-D: Multiple Distinct Accounts Associated with Same Device/Context
- **Rationale**: Detects proxy test-taking, impersonation, or candidate credential sharing at a test center.
- **Trigger**: $\ge 3$ distinct `actor_id` logins from same `device_id` within 900s.
- **Severity**: `HIGH` | **Window**: 900s.
- **Evidence**: Distinct `actor_id` set, single `device_id`, login `audit_log_id`s.
- **False-Positive Risk**: Shared workstation in a test lab used legitimately by multiple candidates sequentially.
- **Implementation Status**: **AVAILABLE NOW** (`CandidateSession.device_fingerprint`).

### RULE-E: Break-Glass Scope Comparison & Misuse
- **Rationale**: Detects misuse of emergency Break-Glass authorization to access examination papers outside approved scope.
- **Trigger**: `BREAK_GLASS_ACTIVATED` followed by access event evaluated as `OUT_OF_SCOPE` within 1800s.
- **Severity**: `CRITICAL` | **Window**: 1800s.
- **Evidence**: `BreakGlassRequest.id`, accessed `resource_id`, scope mismatch metadata.
- **False-Positive Risk**: Legitimate emergency requiring broader paper review than initially stated.
- **Implementation Status**: Core fields **AVAILABLE NOW**; question-to-exam child lookup cache **REQUIRES IMPLEMENTATION SUPPORT**.

### RULE-F: Break-Glass Activation Followed by Audit Anomaly
- **Rationale**: Detects insider attempting to disable or suppress audit logging following emergency access.
- **Trigger**: `BREAK_GLASS_ACTIVATED` followed by evidence state `CONFIRMED_MISSING` within observation deadline ($300\text{s}$).
- **Severity**: `CRITICAL` | **Window**: 600s.
- **Evidence**: `BreakGlassRequest.id`, observation window timestamps, confirmed gap.
- **False-Positive Risk**: Downstream database network hiccup during emergency use.
- **Implementation Status**: **AVAILABLE NOW** (`app/modules/break_glass/service.py` & `AuditLog`).

### RULE-G: Repeated KMS Cryptographic Failures
- **Rationale**: Detects cryptographic tampering, unauthorized key usage attempts, or compromised IAM credentials.
- **Trigger**: $\ge 3$ KMS failures (`KMS_SECURITY_EVENT_FAILURE` or `AccessDeniedException`) within 300s.
- **Severity**: `CRITICAL` | **Window**: 300s.
- **Evidence**: KMS operation names, `kms_key_id`, error codes, `kms_request_id` where available.
- **False-Positive Risk**: Expired IAM temporary credentials or KMS policy replication lag during key rotation.
- **Implementation Status**: **AVAILABLE NOW** (`app/crypto/kms_interface.py`).

### RULE-H: Audit Integrity Verification Failure Correlated with Security Events
- **Rationale**: Detects active audit tampering or database modification following unauthorized activities.
- **Trigger**: Deep chain verifier status `FAIL` (`bsea_audit_verifier_status == fail`) correlated with any `ACCESS_DENIED` within preceding 3600s.
- **Severity**: `CRITICAL` | **Window**: 3600s.
- **Evidence**: Verifier failure sequence range, tampered link ID, denial `audit_log_id`s.
- **False-Positive Risk**: Unquarantined poison event (benign malformation from dirty migration).
- **Implementation Status**: **AVAILABLE NOW** (`app/modules/audit/service.py`).

### RULE-I: Rate-Limit Probing Sequence Followed by Sensitive Access
- **Rationale**: Detects an adversary mapping API rate limits, backing off, and successfully accessing sensitive resources.
- **Trigger**: $\ge 5$ rate-limit rejections within 300s followed by successful access to `/api/v1/exams/*` or `/api/v1/questions/*` from same `ip_hash`.
- **Severity**: `MEDIUM` | **Window**: 600s.
- **Evidence**: Rate-limit rejections count, successful access `audit_log_id`, `ip_hash`.
- **False-Positive Risk**: High-volume legitimate batch operations or CBT station retry bursts.
- **Implementation Status**: **AVAILABLE NOW** (`app/core/telemetry_middleware.py`).

### RULE-J: Sealer Degradation & Pipeline Starvation
- **Rationale**: Detects denial-of-service against the audit sealing pipeline (lock hoarding or queue starvation).
- **Trigger**: Evaluated via exact Boolean logic: $(A \land B) \lor C$.
- **Severity**: `HIGH` | **Window**: 900s.
- **Evidence**: Backlog record count, oldest unsealed record ID and timestamp, sealer run statuses.
- **False-Positive Risk**: Huge legitimate exam submission burst (healthy sealer catches up within minutes).
- **Implementation Status**: **AVAILABLE NOW** (`bsea_audit_sealer_lag_events`, sealer metrics).

---

## 11. Rule-A Identity Correlation Semantics

Rev-03 eliminates false equivalence between network IP addresses and actor identities by formalizing three discrete correlation strengths:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        RULE-A IDENTITY CORRELATION STRENGTHS                           │
├──────────────────────┬─────────────────────────────────────────────────────────────────┤
│ LEVEL                │ CONDITIONS & SEMANTICS                                          │
├──────────────────────┼─────────────────────────────────────────────────────────────────┤
│ ACTOR_MATCH          │ STRONG CORRELATION:                                             │
│                      │ Both failure events and subsequent success event contain        │
│                      │ identical, non-null actor_id values. Direct account credential  │
│                      │ attack confirmed.                                               │
├──────────────────────┼─────────────────────────────────────────────────────────────────┤
│ IP_MATCH_ONLY        │ WEAKER CORRELATION:                                             │
│                      │ actor_id is unavailable on failures (e.g., unregistered user    │
│                      │ usernames), but all events share identical ip_hash. Correlates  │
│                      │ strictly as network-source evidence. Engine DOES NOT claim      │
│                      │ same IP equals same actor.                                      │
├──────────────────────┼─────────────────────────────────────────────────────────────────┤
│ INSUFFICIENT_IDENTITY│ UNCORRELATED:                                                   │
│                      │ Neither actor_id nor ip_hash provides consistent linkage across │
│                      │ failure and success events. Rule-A does not fire.               │
└──────────────────────┴─────────────────────────────────────────────────────────────────┘
```

### Cardinality Protection
The values `ACTOR_MATCH`, `IP_MATCH_ONLY`, and `INSUFFICIENT_IDENTITY` participate strictly in structured log evidence payloads. They are **NEVER** emitted as metric dimensions or Prometheus labels.

---

## 12. Rule-F Evidence State Machine

To prevent transient network delays from triggering critical false alarms, Rule-F enforces a 5-state evidence lifecycle:

```
[BREAK_GLASS_ACTIVATED Event Observed]
                  │
                  ▼
          State: EXPECTED
(Post-activation examination access audit events are expected)
                  │
        ┌─────────┴─────────┐
        ▼                   ▼
Event arrives within 60s?   No event after 60s?
        │                   │
        ▼                   ▼
 State: RECEIVED      State: DELAYED
 (Audited cleanly;    (Within acceptable propagation window)
  Rule-F NO-OP)             │
                            ▼
              Elapsed time between 60s and 300s?
                            │
                            ▼
                    State: UNRESOLVED
             (Awaiting worker retry or queue drain)
                            │
                            ▼
              Elapsed time > 300s without audit event,
              OR explicit audit insertion error logged?
                            │
                            ▼
                 State: CONFIRMED_MISSING
              (CRITICAL SECURITY SIGNAL FIRED)
```

Only state **`CONFIRMED_MISSING`** triggers the Rule-F detection signal.

---

## 13. Rule-E Scope Evaluation

Rule-E validates whether access following Break-Glass activation respects the authorized scope.

### 13.1 Scope Comparison Dimensions
- **Approved Scope Definition**:
  - `BreakGlassRequest.scope`: Enum value (`EMERGENCY_PAPER_ASSEMBLY`, `SECURITY_INCIDENT_INVESTIGATION`, `SYSTEM_DISASTER_RECOVERY`, `CENTRE_EMERGENCY_ACCESS`).
  - `BreakGlassRequest.exam_id`: Target examination identifier.
  - `BreakGlassRequest.valid_from` & `valid_until`: Authorized temporal window.
- **Actual Access Event**:
  - `AuditLog.resource_type`: e.g., `exam`, `question`, `blueprint`.
  - `AuditLog.resource_id`: Target resource UUID.
  - `AuditLog.action`: e.g., `READ_QUESTION`, `ASSEMBLE_PAPER`.
  - `AuditLog.timestamp`: Event execution timestamp.

### 13.2 Evaluation States
1. **`MATCH`**: Access occurred within `[valid_from, valid_until]`, referenced approved `exam_id` (or child questions belonging to it), and matched approved action.
2. **`OUT_OF_SCOPE`**: Access occurred outside the valid time window, targeted an unapproved `exam_id`, or executed an action incompatible with approved scope.
3. **`UNRESOLVED`**: Resource hierarchy cannot be determined (e.g., question-to-exam child cache miss).

### 13.3 Content Isolation Guarantee
Zero question text, answer keys, candidate answers, or paper plaintext participate in or enter detection state. Comparison evaluates exclusively against resource identifiers and enum types.

---

## 14. Rule-J Exact Boolean Logic

Rule-J detects denial-of-service, queue starvation, or lock hoarding against the audit sealing pipeline.

### 14.1 Metric Component Definitions
- $A$: `backlog_records > 1000` (Unsealed queue has accumulated more than 1 full standard epoch, as standard epoch size is 1,000 links).
- $B$: `(sealer_failures >= 3 OR sealer_lock_timeouts >= 5)` within a 900s window.
- $C$: `oldest_unsealed_age_seconds > 1800` (Oldest unsealed event exceeds 30 minutes, violating sealing SLA).

### 14.2 Exact Trigger Expression
$$\mathbf{RULE\_J\_TRIGGER} = (A \land B) \lor C$$

Expanded logic:
```
(
    backlog_records > 1000
    AND
    (
        sealer_failures >= 3
        OR
        sealer_lock_timeouts >= 5
    )
)
OR
(
    oldest_unsealed_age_seconds > 1800
)
```

### Rationale for Expression Structure
- High `backlog_records` alone during a massive exam submission wave is normal transient operational load, not an attack. If the sealer is running normally, a backlog of 2,000 will be sealed within minutes.
- Only when high backlog ($A$) is accompanied by repeated failures or lock timeouts ($B$) does it indicate pipeline starvation.
- Condition $C$ acts as a safety ceiling: if unsealed records sit for over 30 minutes regardless of backlog size, an alert is warranted.
- Backlog record count is an integer count and is **never referred to as "lag"**.

---

## 15. Metric Cardinality Mathematics

Phase 3C-5C adheres strictly to compile-time bounded label domains:

### 15.1 Finite Label Domains
- `rule_id` $\in$ `{"RULE-A", "RULE-B", "RULE-C", "RULE-D", "RULE-E", "RULE-F", "RULE-G", "RULE-H", "RULE-I", "RULE-J", "other"}` (Size = 11)
- `severity` $\in$ `{"LOW", "MEDIUM", "HIGH", "CRITICAL"}` (Size = 4)
- `mode` $\in$ `{"shadow", "active"}` (Size = 2)
- `result` $\in$ `{"match", "no_match", "error"}` (Size = 3)
- `status` $\in$ `{"correlated", "unresolved", "missing", "conflicting"}` (Size = 4)

### 15.2 Mathematical Cardinality Table

| Metric Name | Type | Labels | Formula | Base Series | Expanded Series |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `bsea_detection_signals_total` | Counter | `rule_id`, `severity`, `mode` | $11 \times 4 \times 2$ | **88** | 88 |
| `bsea_detection_rule_evaluations_total` | Counter | `rule_id`, `result` | $11 \times 3$ | **33** | 33 |
| `bsea_cloudtrail_reconciliation_total` | Counter | `status` | 4 | **4** | 4 |
| `bsea_detection_engine_lag_seconds` | Gauge | *None* | 1 | **1** | 1 |
| **TOTAL NEW 5C SERIES** | | | | **126 base** | **126 expanded** |

### 15.3 Aggregate Telemetry Bounds
- **Phase 3C-5B Baseline**: 520 base series (1,390 expanded series with histogram buckets).
- **Phase 3C-5C Additions**: 126 base series (126 expanded series; zero histograms added).
- **Total Combined System Telemetry**:
  $$\text{Total Base Time Series} = 520 + 126 = \mathbf{646}$$
  $$\text{Total Expanded Time Series} = 1,390 + 126 = \mathbf{1,516}$$
- **Precise Architectural Claim**: The currently defined metric label domains are explicitly bounded to 646 base series across Phase 3C-5B and Phase 3C-5C. High-cardinality values (`actor_id`, `candidate_id`, `session_id`, `device_id`, `trace_id`, `request_id`, `audit_log_id`, `ip_hash`, `IP`, `exam_id`, `question_id`, `signal_id`) are **strictly prohibited** as metric labels.

---

## 16. Security Invariants

Phase 3C-5C enforces 15 immutable security invariants:

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                 PHASE 3C-5C MANDATORY SECURITY INVARIANTS                              │
├────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ INVARIANT 1  : Detection must never weaken authentication or authorization controls.                   │
│ INVARIANT 2  : Detection engine failure must fail open for user traffic (fail-safe observational).     │
│ INVARIANT 3  : Detection engine must NEVER modify, mutate, or delete immutable audit history.          │
│ INVARIANT 4  : Detection must never alter KMS cryptographic key state or bypass KMS policies.          │
│ INVARIANT 5  : Detection must NOT automatically quarantine content or audit events in Phase 3C-5C.     │
│ INVARIANT 6  : Detection must NOT automatically block candidates, IPs, devices, or administrative accounts.│
│ INVARIANT 7  : Initial detection operates strictly in SHADOW MODE (advisory telemetry only).           │
│ INVARIANT 8  : Every detection signal must provide an explainable, auditable evidence chain.           │
│ INVARIANT 9  : Detection rules must be deterministic, reproducible, and strictly versioned.            │
│ INVARIANT 10 : High-cardinality identifiers must NEVER become metric dimensions or label values.       │
│ INVARIANT 11 : Sensitive examination content (questions, answers) must NEVER enter detection telemetry.│
│ INVARIANT 12 : Detection must never require or inspect plaintext question-paper material.              │
│ INVARIANT 13 : A detection signal is an ADVISORY OBSERVATION, NOT a confirmed security incident.       │
│ INVARIANT 14 : Missing correlation evidence must be recorded explicitly rather than guessed or assumed.│
│ INVARIANT 15 : Core examination security controls must remain completely decoupled from detection.     │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 17. Failure Semantics

Under **INVARIANTS 2 and 15**, detection failure cannot degrade core examination controls.

| Component Fault | Impact on Core Examination | Impact on Detection Engine | Handling & Recovery |
| :--- | :--- | :--- | :--- |
| **PostgreSQL Slowdown** | Core auth/exam operations proceed per existing DB pool limits | Event polling throttled | Delays event processing; drops non-critical correlation cache; never blocks exam writes |
| **Redis Outage** | Candidate exams switch to fail-soft local sessions (Phase 3C-1) | Operates in Degraded Mode (local memory) | Emits `degraded_correlation=True`; reduced cross-worker coverage; 0 exam impact |
| **KMS API Outage** | Exam decryption fails closed (core requirement) | KMS correlation logs errors | Records `KMS_UNAVAILABLE` signal; does not crash app |
| **CloudTrail Unavailable** | Zero impact on exams | Reconciliation marked `MISSING_EVIDENCE` | Does not generate critical alert |
| **SQS Unavailable** | API commits audit log normally; queue emission fails soft | Workers receive no events | Logged as `TELEMETRY_DISPATCH_FAULT`; zero student exam disruption |
| **Detection Worker Crash** | **ZERO IMPACT** on exams | Worker restarts via ECS supervisor | SQS visibility timeout lapses; surviving workers re-consume messages |
| **Out-of-Order Events** | No impact | Temporal buffer uses canonical timestamp | Events buffered in a 60-second jitter window before rule evaluation |
| **Duplicate Events** | Idempotency keys in API | Engine deduplicates by `event_id` | Duplicate `event_id` discarded as `DUPLICATE_EVENT` |
| **Poison Event Ingestion** | No impact | Schema validation fails | Routed to Dead-Letter Queue (DLQ) after 5 retries without crashing workers |

---

## 18. Prototype vs Production Boundary

| Architectural Dimension | Local Test Environment / Prototype | AWS Target Production Architecture |
| :--- | :--- | :--- |
| **Event Delivery** | In-process `asyncio.Queue` | Amazon SQS (Standard queue with KMS SSE) |
| **Detection Workers** | In-process asynchronous task | Dedicated ECS Fargate tasks with auto-scaling |
| **Correlation State** | In-memory `collections.deque` ring buffer | Amazon ElastiCache for Redis 7 (Multi-AZ ZSETs) |
| **Database** | Local PostgreSQL 16 on `localhost:5432` | Amazon RDS PostgreSQL 16 Multi-AZ + RDS Proxy |
| **KMS Provider** | `MockKMS` (AES-256-GCM + Ed25519) | AWS KMS Customer Managed Keys (CMKs) |
| **CloudTrail Feed** | Mock synthetic CloudTrail JSON feed | CloudWatch Logs Subscription Filter from CloudTrail |
| **Failure Handling** | Fail-safe in-process logging | SQS DLQ + CloudWatch Alarms + SNS Notifications |

---

## 19. Test Matrix (T01-T20)

When implementation is authorized, validation must satisfy the 20-test matrix:
- **T01**: Event Normalization complete mapping from Audit, Auth, and CBT.
- **T02**: Rule Evaluation Determinism (100% byte-for-byte identical signal output).
- **T03**: Rule Versioning & Policy Metadata verification.
- **T04**: Shadow Mode Assurance (zero accounts locked, zero HTTP 403 blocks).
- **T05**: Evidence Graph Integrity (references valid `audit_log_id`s; zero question text present).
- **T06**: Temporal Window Expiration.
- **T07**: Burst Window Matching (Rule-A fires on 5 failures + 1 success).
- **T08**: Event Deduplication (duplicate `event_id`s discarded).
- **T09**: Out-of-Order Event Handling (jitter buffer orders by event timestamp).
- **T10**: Missing Correlation Fields Graceful Degradation.
- **T11**: Stale Correlation State Purging.
- **T12**: CloudTrail `CORRELATED` Status Verification.
- **T13**: CloudTrail `UNRESOLVED` Status Verification.
- **T14**: CloudTrail `MISSING_EVIDENCE` Status Verification.
- **T15**: CloudTrail `CONFLICTING_EVIDENCE` Status Verification.
- **T16**: Metric Cardinality Compile-Time Invariants ($\le 126$ base series).
- **T17**: Sensitive Data & Secret Leakage Isolation.
- **T18**: Detection Engine Crash Fail-Safe (core exam traffic proceeds normally).
- **T19**: Multi-Worker Race & Idempotency Hash Deduplication.
- **T20**: Zero Autonomous Blocking / Zero Database Mutation Verification.

---

## 20. Deferred Work

The following items are **strictly out of scope** for Phase 3C-5C and deferred to future authorized phases:
- **Phase 5D — Security Incident Management & Case Workflow**:
  - `security_incidents` database table and Alembic migrations.
  - SecOps case triage dashboard, analyst assignments, and status transitions (`OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`).
  - Formal deprecation and migration away from legacy `SecurityService` (`backend/app/modules/security/service.py`).
- **Phase 5E — Policy-Governed Containment (Active Mode Transition)**:
  - Dual-custody containment workflows (human-in-the-loop candidate session termination).
  - Automated emergency paper replacement protocols.
- **Phase 5F — Enterprise SIEM & SOC Integration**:
  - Direct integration into AWS Security Lake, Splunk, or OpenSearch.
  - PagerDuty and incident response escalation webhooks.

---

## 21. Final Architecture Decision Table

| Architecture Dimension | Evaluated Options | Final Decision | Justification |
| :--- | :--- | :--- | :--- |
| **Detection Engine Execution** | A: In-Process FastAPI<br>B: Dedicated ECS Worker<br>C: Dedicated Worker + SQS | **Dedicated ECS Worker + SQS (Prod)**<br>**In-Process (Local CI)** | Decouples detection load from API; resolves multi-task visibility gaps. |
| **Event Delivery Bus** | A: In-Process Queue<br>B: EventBridge<br>C: Amazon SQS | **Amazon SQS (Prod)**<br>**In-Process Queue (Local CI)** | Proven point-to-point delivery, native consumer backpressure, built-in DLQ, low operational complexity. |
| **Correlation State** | A: In-Memory Ring Buffer<br>B: PostgreSQL Queries<br>C: ElastiCache Redis 7 ZSET | **ElastiCache Redis 7 ZSET (Prod)**<br>**In-Memory Ring Buffer (Local CI)** | $O(\log N)$ sliding-window queries across workers; non-authoritative; zero DB write lock contention. |
| **CloudTrail Ingestion** | A: S3 Batch / Lambda<br>B: CloudWatch Logs Subscription Filter<br>C: CloudTrail Lake SQL | **CloudWatch Logs Subscription Filter** | Low latency, managed log streaming, zero Lambda maintenance overhead. |
| **Legacy Security Service** | A: Deprecate/Remove in 5C<br>B: Refactor to 5C Engine<br>C: Leave Untouched | **Leave Untouched in 5C** | Freezes existing baseline; avoids risky cross-module regressions; defers migration to 5D. |

---

## 22. Implementation File List (For Future Authorization)

### Proposed New Files (Phase 3C-5C Implementation Scope)
- `backend/app/modules/detection/__init__.py`: Package exports.
- `backend/app/modules/detection/models.py`: Immutable models (`SecurityEventNormalized`, `SecuritySignal`, `DetectionRuleDefinition`).
- `backend/app/modules/detection/normalizer.py`: Event normalization mapping from AuditLog, Auth, and CBT.
- `backend/app/modules/detection/engine.py`: Deterministic rule evaluation engine.
- `backend/app/modules/detection/rules.py`: Canonical rule definitions (RULE-A through RULE-J).
- `backend/app/modules/detection/correlation.py`: In-memory ring buffer (prototype) and Redis ZSET (production) correlation manager.
- `backend/app/modules/detection/cloudtrail.py`: Asynchronous CloudTrail/KMS reconciliation engine.
- `backend/tests/security/test_phase3c5c_detection.py`: Complete implementation of matrix T01–T20.

### Proposed Modified File
- `backend/app/core/metrics.py`: Registering 4 bounded detection metrics ($\le 126$ base series).

### Strictly Frozen Files (NO CHANGES PERMITTED)
- `backend/app/core/models.py`: **FROZEN.**
- `backend/alembic/`: **FROZEN.**
- `backend/app/modules/security/service.py`: **FROZEN.**
- `backend/app/modules/audit/sealer.py`: **FROZEN.**
- `backend/app/modules/audit/quarantine.py`: **FROZEN.**
- `backend/app/crypto/kms_interface.py`: **FROZEN.**
- `terraform/`: **FROZEN.**

---

## 23. Explicit Implementation Preconditions

Phase 3C-5C implementation may NOT begin until all of the following preconditions are met:
1. Formal user review and explicit written approval of Rev-03 architecture.
2. Verification that git baseline remains `d6d430f929caa90ef8f0390abeceaa362c302ace` (`HEAD == origin/main`).
3. Verification that regression baseline remains 220 passed, 5 skipped, 0 failed.
4. Absolute commitment to Shadow Mode: zero automated blocking, zero automated quarantine, zero database mutations.

---
**STATUS: ARCHITECTURE APPROVED FOR IMPLEMENTATION PENDING USER AUTHORIZATION**  
*Repository code remains strictly frozen. No code changes, migrations, or git operations will be executed without explicit authorization.*
