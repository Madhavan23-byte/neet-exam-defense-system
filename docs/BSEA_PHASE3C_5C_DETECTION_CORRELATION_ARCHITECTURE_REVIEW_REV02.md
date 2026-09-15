# B-SEA Phase 3C-5C — Detection & Correlation Foundation
## Forensic Architecture & Design Review (Rev-02)

| Document Metadata | Authoritative Specification |
| :--- | :--- |
| **Document ID** | `BSEA-ARCH-3C-5C-REV02` |
| **System** | Bharat Secure Examination Architecture (B-SEA) |
| **Component** | Security Intelligence, Correlation Engine & Shadow Detection |
| **Accepted Baseline** | `d6d430f929caa90ef8f0390abeceaa362c302ace` (`HEAD == origin/main`) |
| **Regression Baseline** | 220 passed, 5 skipped, 0 failed (225 collected) |
| **Current Status** | **DRAFT FOR FORENSIC ARCHITECTURE REVIEW (CODE FREEZE STRICTLY PRESERVED)** |
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
Durable Event Distribution (Amazon SQS in Prod / Async Queue in Proto)
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

### Core Architectural Decisions in Rev-02
1. **Multi-Worker Distributed Architecture**: Reconciles Rev-01 by strictly distinguishing the single-process test prototype from the multi-instance AWS ECS Fargate production target. Production event distribution uses **Amazon SQS** with post-commit dispatch, consumer backpressure, and worker-side idempotency.
2. **Strict Shadow Mode**: Detection in Phase 3C-5C is strictly observational and advisory. Under no circumstances will a detection signal automatically terminate a session, lock an account, block an IP, cancel an exam, revoke credentials, or trigger cryptographic quarantine.
3. **Fail-Safe & Non-Authoritative**: The detection engine operates outside the critical transaction path of high-stakes examination workflows. Telemetry failure, correlation engine crash, or database slowdown cannot degrade, delay, or bypass authentication, authorization, or question delivery security controls. Redis and SQS are strictly non-authoritative; PostgreSQL `audit_logs` remains the sole immutable system of record.
4. **Exact Metric Cardinality**: Proves mathematically that Phase 3C-5C adds exactly **126 base time series** (and 126 expanded series), expanding the total system metric footprint from 520 base (1,390 expanded) to **646 base (1,516 expanded)**, with zero unbounded labels.
5. **No Incident Management DB & Zero Legacy Tampering**: Phase 3C-5C intentionally defers incident case-management schemas (`security_incidents` table) to Phase 5D. The existing prototype `SecurityService` (`backend/app/modules/security/service.py`) remains **strictly untouched and un-deprecated** in 5C.

---

## 2. Baseline

The architecture and design review is strictly anchored to the accepted baseline:
- **Repository Commit**: `d6d430f929caa90ef8f0390abeceaa362c302ace`
- **Git Branch**: `main` (`HEAD == origin/main`)
- **Working Tree**: Clean (zero modified tracked files)
- **Regression Suite**: 220 passed, 5 skipped, 0 failed (225 total tests collected)
- **Database Target**: Amazon RDS PostgreSQL 16 Multi-AZ with RDS Proxy (NOT Amazon Aurora)

---

## 3. Current-State Findings (Fact-Based Codebase Audit)

A rigorous inspection of the repository confirms existing event generation, schemas, and security boundaries:

### 3.1 Event Generation Points in Baseline

| Domain | Emitted Events | Location in Codebase | Authority & Destination |
| :--- | :--- | :--- | :--- |
| **Authentication** | `LOGIN`, `LOGIN_FAILURE`, `LOGIN_BLOCKED`, `MFA_SETUP`, `MFA_SUCCESS`, `MFA_FAILURE`, `CANDIDATE_LOGIN_FAILED`, `CANDIDATE_SESSION_STARTED`, `CONCURRENT_SESSION_ATTEMPT` | `app/modules/auth/service.py`<br>`app/api/v1/candidates.py` | `AuditLog` (Mode A/B), Argon2id verification, Redis token cache, Structured Logs |
| **Authorization Denials** | `ACCESS_DENIED`, `ACCESS_EXPIRED`, `ACCESS_REVOKED`, `BREAK_GLASS_ACCESS_DENIED`, `CANDIDATE_ACCESS_DENIED_UNRELEASED`, `RELEASE_APPROVAL_BLOCKED` | `app/modules/questions/service.py`<br>`app/modules/break_glass/service.py`<br>`app/modules/release/service.py` | `AuditLog` (Mode B isolated commit), HTTP 403 Forbidden |
| **Rate Limiting** | HTTP 429 Rejection | `app/core/telemetry_middleware.py`<br>`slowapi` limiter | `bsea_rate_limit_exceeded_total` metric, Structured HTTP log |
| **Question Access** | `QUESTION_DELIVERED`, `QUESTION_VIEWED`, `QUESTION_ENCRYPTED`, `QUESTION_LIST_ACCESSED`, `BULK_QUESTION_ACCESS` | `app/api/v1/candidates.py`<br>`app/modules/questions/service.py` | `AuditLog` (Mode A/B), ephemeral AES-256 session key decryption |
| **Break-Glass** | `BREAK_GLASS_REQUESTED`, `BREAK_GLASS_APPROVAL_SUBMITTED`, `BREAK_GLASS_REJECTED`, `BREAK_GLASS_QUORUM_ACHIEVED`, `BREAK_GLASS_ACTIVATED`, `BREAK_GLASS_EXPIRED`, `BREAK_GLASS_REVOKED`, `BREAK_GLASS_PAPER_ASSEMBLED` | `app/modules/break_glass/service.py` | `AuditLog`, `BreakGlassRequest`, `BreakGlassApproval`, Multi-party quorum |
| **Audit Sealer** | `SEAL_SUCCESS`, `SEAL_NOOP`, `SEAL_LOCKED`, `SEAL_FAILED` | `app/modules/audit/sealer.py` | `audit_epoch_seals` table, KMS Ed25519 signatures, `bsea_audit_sealer_runs_total` |
| **Audit Verifier** | Deep chain verification results (`PASS`, `FAIL`, `UNRESOLVED`, `STALE`) | `app/modules/audit/service.py` (`deep_chain_verifier`) | `bsea_audit_verifier_status` metric, structured logs |
| **Quarantine** | `POISON_EVENT_QUARANTINED` | `app/modules/audit/quarantine.py`<br>`app/modules/audit/sealer.py` | `audit_poison_quarantine` table, dual-custody authorization nonce |
| **KMS Operations** | `KMS_ENCRYPT`, `KMS_DECRYPT`, `KMS_SIGN`, `KMS_VERIFY`, `KMS_DERIVE_SESSION_KEY`, `KMS_ROTATE_KEY_QUERY`, `KMS_SIGNING_KEY_ROTATED` | `app/crypto/kms_interface.py` (`_audit_kms_operation`) | Structured logs with `cloudtrail_correlation` metadata block |

### 3.2 Schema & Context Availability
- **`AuditLog` (`models.py:603`)**: Contains `id`, `event_type`, `actor_id`, `actor_role`, `resource_type`, `resource_id`, `action`, `result`, `ip_hash`, `device_id`, `event_metadata`, `risk_score`, `event_hash`, `trace_id`, `kms_request_id`, `created_at`, `timestamp`. PostgreSQL triggers block `UPDATE` and `DELETE`.
- **`CandidateSession` (`models.py:485`)**: Contains `candidate_id`, `exam_id`, `form_id`, `centre_id`, `session_token_hash`, `status`, `ip_hash`, `device_fingerprint`, `tab_switch_count`, `security_violations`. Partial index prevents concurrent active sessions.
- **`BreakGlassRequest` (`models.py:875`)**: Contains `scope` (`BreakGlassScope`), `exam_id`, `status`, `target_centre_id`, `reason`, `valid_from`, `valid_until`, `approved_at`, `activated_at`, `revoked_at`.
- **Contextvars (`logging.py`)**: `CURRENT_TRACE_ID` (W3C 32-hex format) and `CURRENT_REQUEST_ID` (UUIDv4) are propagated through all asynchronous request flows.

---

## 4. Goals

1. **Normalized Security Event Pipeline**: Standardize disparate events into a single in-memory contract (`SecurityEventNormalized`).
2. **Multi-Dimensional Correlation Across Tasks**: Correlate events across actors, sessions, devices, resources, and sliding temporal windows in a multi-instance ECS Fargate architecture.
3. **Deterministic, Versioned Rule Engine**: Pure, reproducible, explainable rule execution without heuristic scoring or ML models.
4. **Strict Shadow Mode**: Emit detection signals as advisory telemetry without autonomous containment or user disruption.
5. **Explainable Evidence Graphs**: Link each detection signal directly to immutable `audit_log_id` records and W3C `trace_id` traces without copying question or answer content.
6. **Asynchronous CloudTrail/KMS Correlation**: Reconcile delayed AWS CloudTrail data with local KMS calls using four explicit states (`CORRELATED`, `UNRESOLVED`, `MISSING_EVIDENCE`, `CONFLICTING_EVIDENCE`).
7. **Strict Cardinality Defense**: Enforce compile-time bounds on all detection metric dimensions, adding exactly 126 base series.

---

## 5. Non-Goals

The following capabilities are **strictly deferred or forbidden** in Phase 3C-5C:
1. **No Autonomous Mitigation**: No account lockouts, candidate evictions, IP blocks, or exam terminations.
2. **No Automated Audit Quarantine**: Automated quarantine of poison audit records without dual-operator signatures is prohibited.
3. **No Incident Management DB**: No `security_incidents` table, triage workflows, or ticketing schemas (deferred to Phase 5D).
4. **No Machine Learning Anomaly Detection**: No probabilistic scoring, clustering, or stochastic algorithms.
5. **No SIEM/SOC Replacement**: B-SEA will not build a SIEM; signals integrate into standard CloudWatch and SNS pipes.
6. **No Audit Ledger or KMS Redesign**: Immutability triggers, hash chain math, sealer logic, and KMS wrappers remain frozen.
7. **No Plaintext Examination Content Ingestion**: The detection engine will never inspect or store question text or answer keys.
8. **No Legacy Service Deprecation in 5C**: `backend/app/modules/security/service.py` is left unchanged.

---

## 6. Security Invariants

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

## 7. Event Normalization

Disparate event sources are parsed into a normalized internal data structure.

### 7.1 Data Availability Breakdown

| Field | Target Type | Status in Codebase | Source | Strategy in 3C-5C |
| :--- | :--- | :--- | :--- | :--- |
| `event_id` | `str` (UUID) | **AVAILABLE NOW** | `AuditLog.id`, generated UUID | Direct mapping |
| `event_type` | `str` | **AVAILABLE NOW** | `AuditLog.event_type`, log tags | Canonical string lookup |
| `timestamp` | `datetime` (UTC) | **AVAILABLE NOW** | `AuditLog.created_at`, ISO 8601 | Normalized UTC timestamp |
| `actor_id` | `Optional[str]` | **AVAILABLE NOW** | `AuditLog.actor_id`, `User.id` | Retained in normalized event |
| `actor_role` | `Optional[str]` | **AVAILABLE NOW** | `AuditLog.actor_role`, JWT claims | Mapped to finite role set |
| `resource_type` | `Optional[str]` | **AVAILABLE NOW** | `AuditLog.resource_type` | Finite resource domain |
| `resource_id` | `Optional[str]` | **AVAILABLE NOW** | `AuditLog.resource_id` | Retained in normalized event |
| `action` | `Optional[str]` | **AVAILABLE NOW** | `AuditLog.action`, HTTP verb | Standardized verb |
| `result` | `str` | **AVAILABLE NOW** | `AuditLog.result` (`AuditResult`) | `SUCCESS`, `FAILURE`, `DENIED`, `BLOCKED`, `ERROR` |
| `trace_id` | `Optional[str]` | **AVAILABLE NOW** | `CURRENT_TRACE_ID` contextvar | W3C 32-hex string |
| `request_id` | `Optional[str]` | **AVAILABLE NOW** | `CURRENT_REQUEST_ID` contextvar | UUIDv4 string |
| `audit_log_id` | `Optional[str]` | **AVAILABLE NOW** | `CURRENT_AUDIT_LOG_ID` contextvar | References `audit_logs.id` |
| `session_id` | `Optional[str]` | **AVAILABLE NOW (CBT)** | `CandidateSession.id` | Passed in CBT session events |
| `device_id` | `Optional[str]` | **AVAILABLE NOW** | `AuditLog.device_id`, fingerprint | Sanitized identifier |
| `ip_hash` | `Optional[str]` | **AVAILABLE NOW** | `AuditLog.ip_hash`, client IP | 64-char SHA-256 hash |
| `kms_request_id` | `Optional[str]` | **AVAILABLE NOW** | `AuditLog.kms_request_id` | AWS KMS response header ID |
| `source_subsystem` | `str` | **AVAILABLE NOW** | Event origin | `API`, `AUTH`, `CBT`, `KMS`, `SEALER`, `VERIFIER` |
| `policy_version` | `str` | **AVAILABLE NOW** | Static specification | `BSEA-DETECTION-v1` |

### 7.2 Normalized Event Data Contract

```python
@dataclass(frozen=True)
class SecurityEventNormalized:
    event_id: str
    event_type: str
    timestamp: datetime
    source_subsystem: str
    result: str  # SUCCESS, FAILURE, DENIED, BLOCKED, ERROR
    actor_id: Optional[str] = None
    actor_role: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    session_id: Optional[str] = None
    device_id: Optional[str] = None
    ip_hash: Optional[str] = None
    trace_id: Optional[str] = None
    request_id: Optional[str] = None
    audit_log_id: Optional[str] = None
    kms_request_id: Optional[str] = None
    policy_version: str = "BSEA-DETECTION-v1"
    metadata: Dict[str, Any] = field(default_factory=dict)
```

---

## 8. Distributed Event Architecture

In an AWS production deployment, B-SEA executes across multiple ECS Fargate tasks behind an Application Load Balancer. If Task A processes several login failures while Task B processes a subsequent successful login, an in-process memory model will fail to correlate the sequence.

### 8.1 Architectural Evaluation of Event Delivery Candidates

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                               EVENT DELIVERY CANDIDATE EVALUATION                                      │
├──────────────────────┬─────────────────────────┬─────────────────────────┬─────────────────────────────┤
│ Evaluation Axis      │ Option A: In-Process    │ Option B: EventBridge   │ Option C: Amazon SQS (REC)  │
├──────────────────────┼─────────────────────────┼─────────────────────────┼─────────────────────────────┤
│ Multi-Task Delivery  │ FAILS across ECS tasks  │ Supported via rules     │ Supported via worker queue  │
│ Durability           │ Memory only (volatile)  │ At-least-once (24h)     │ Durable disk (up to 14 days)│
│ Consumer Backpressure│ None (drops on surge)   │ Throttled delivery      │ Native consumer polling     │
│ Poison Handling / DLQ│ Process crash / lost    │ Native DLQ              │ Native DLQ + Redrive Policy │
│ Encryption at Rest   │ N/A (RAM)               │ KMS SSE                 │ KMS SSE (CMK)               │
│ Latency              │ < 1 ms                  │ 50 - 500 ms             │ 10 - 50 ms                  │
│ Operational Cost     │ Free                    │ $1.00 / million events  │ $0.40 / million requests    │
│ Testing Alignment    │ Excellent for unit test │ Requires LocalStack     │ Local mockable in Python    │
└──────────────────────┴─────────────────────────┴─────────────────────────┴─────────────────────────────┘
```

### 8.2 Architectural Decision: Dual-Target Model
- **Prototype / Local Testing**: In-process event distribution using `asyncio.Queue` and synchronous pipeline evaluation, guaranteeing 100% unit test determinism without external services.
- **Production AWS Architecture**: Dedicated **Amazon SQS Queue** (`bsea-production-security-events.fifo` or standard queue with worker-side deduplication). API tasks emit events post-transaction commit to SQS. Dedicated ECS Fargate detection workers consume the queue with consumer backpressure and dead-letter queue (DLQ) isolation.

---

## 9. Correlation Architecture

Correlation reconstructs causal patterns across distributed events using spatial and temporal pivots.

### 9.1 Correlation Dimension Taxonomy

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   CORRELATION DIMENSION TAXONOMY                                       │
├──────────────────────────┬──────────────────────────┬──────────────────────────┬───────────────────────┤
│ PRIMARY CORRELATION KEY  │ SECONDARY CORRELATION KEY│      EVIDENCE ONLY       │ NEVER IN METRICS (BAN)│
├──────────────────────────┼──────────────────────────┼──────────────────────────┼───────────────────────┤
│ • actor_id               │ • exam_id                │ • audit_log_id           │ • actor_id / user_id  │
│ • session_id             │ • resource_id            │ • request_id             │ • candidate_id        │
│ • device_id              │ • ip_hash                │ • kms_request_id         │ • session_id          │
│ • trace_id               │ • actor_role             │ • full event metadata    │ • device_id           │
│                          │                          │ • raw timestamps         │ • trace_id / req_id   │
│                          │                          │                          │ • ip_hash / IP address│
│                          │                          │                          │ • question_id / exam_id│
└──────────────────────────┴──────────────────────────┴──────────────────────────┴───────────────────────┘
```

### 9.2 Correlation Windows & Non-Authoritative State
1. **Sliding Windows**:
   - `W1_BURST` (60s): High-frequency brute force, rapid denial floods.
   - `W2_TACTICAL` (300s): Credential stuffing, privilege escalation attempts.
   - `W3_OPERATIONAL` (900s): Break-glass anomaly sequences, sealer degradation vs backlog.
   - `W4_SESSION` (3600s): Cross-session device hopping, slow-and-low exfiltration.
2. **State Storage & Authority Rules**:
   - **Local Prototype**: In-memory ring buffer (`collections.deque`) keyed by `SHA256(dimension + value)` with lazy TTL expiration.
   - **AWS Production**: Amazon ElastiCache for Redis 7 using sorted sets (`ZSET`) keyed by `bsea:corr:{dim}:{hash}` with score as epoch millisecond timestamp and automated `EXPIRE`.
   - **Non-Authority Invariant**: Redis is strictly a performance cache for temporal aggregation. Redis state is **NEVER** authoritative for examination security. If Redis crashes, workers fall back to local in-memory buffers; core exam execution is completely unaffected.

---

## 10. Detection Rule Engine

The rule engine is pure, stateless, reproducible, and auditable. It does not use stochastic weights or machine learning.

### 10.1 Rule Specification Contract

```python
@dataclass(frozen=True)
class DetectionRuleDefinition:
    rule_id: str                          # e.g., "RULE-A"
    rule_version: str                      # e.g., "1.0.0"
    title: str                            # Human-readable title
    description: str                      # Detailed detection rationale
    severity: str                         # LOW, MEDIUM, HIGH, CRITICAL
    enabled: bool                         # Active toggle
    mode: str                             # "SHADOW" (mandatory in 5C)
    time_window_seconds: int              # Window duration (60, 300, 900, 3600)
    primary_dimension: str                # actor_id, session_id, device_id, etc.
    threshold: int                        # Event count threshold
    event_conditions: Dict[str, Any]      # Filter predicates
    evidence_requirements: List[str]      # Required fields for signal generation
    policy_version: str = "BSEA-RULES-v1"
```

---

## 11. Rule Catalog A-J

Ten candidate rules are specified below. **None are implemented in application code yet.**

### RULE-A: Repeated Authentication Failures Followed by Success
- **Rationale**: Detects brute-force credential stuffing that eventually succeeds.
- **Trigger**: $\ge 5$ `LOGIN_FAILURE` events within 300s followed by 1 `LOGIN` (SUCCESS) on same `actor_id` or `ip_hash`.
- **Severity**: `HIGH` | **Window**: 300s.
- **Evidence**: List of failure `audit_log_id`s and success `audit_log_id`.
- **False-Positive Risk**: User with forgotten password trying multiple typos before remembering.
- **Implementation Status**: **AVAILABLE NOW** (`app/modules/auth/service.py`).

### RULE-B: Repeated Authorization Denials Followed by Privileged Access
- **Rationale**: Detects authorization probing, role escalation, or IDOR vulnerability probing followed by successful access.
- **Trigger**: $\ge 3$ `ACCESS_DENIED` events on sensitive resources within 600s followed by `ACCESS_GRANTED` on same `actor_id`.
- **Severity**: `HIGH` | **Window**: 600s.
- **Evidence**: List of denial `audit_log_id`s and grant `audit_log_id`.
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
- **Evidence**: Set of distinct `actor_id`s, single `device_id`, login `audit_log_id`s.
- **False-Positive Risk**: Shared workstation in a test lab used legitimately by multiple candidates sequentially.
- **Implementation Status**: **AVAILABLE NOW** (`CandidateSession.device_fingerprint`).

### RULE-E: Break-Glass Scope Comparison & Misuse
- **Rationale**: Detects misuse of emergency Break-Glass authorization to access examination papers outside approved scope.
- **Scope Model**: Compares `BreakGlassRequest.scope`, `exam_id`, and `valid_until` against access event `resource_type`, `resource_id`, and `action`.
  - States: `MATCH`, `OUT_OF_SCOPE`, `UNRESOLVED`.
  - Content Isolation: Zero question text or answer keys are copied; only IDs and scope enums participate.
- **Trigger**: `BREAK_GLASS_ACTIVATED` followed by access event evaluated as `OUT_OF_SCOPE` within 1800s.
- **Severity**: `CRITICAL` | **Window**: 1800s.
- **Evidence**: `BreakGlassRequest.id`, accessed `resource_id`, scope mismatch metadata.
- **False-Positive Risk**: Legitimate emergency requiring broader paper review than initially stated.
- **Implementation Status**: Core fields **AVAILABLE NOW**; question-to-exam child lookup cache **REQUIRES IMPLEMENTATION SUPPORT**.

### RULE-F: Break-Glass Activation Followed by Audit Anomaly
- **Rationale**: Detects insider attempting to disable or suppress audit logging following emergency access.
- **Audit Evidence States**:
  - `EXPECTED`: Break-Glass session active; post-activation audit events expected.
  - `RECEIVED`: Verified audit log referencing session arrived in `AuditLog`.
  - `DELAYED`: Event not yet observed, but elapsed time $\le 60\text{s}$ (within ingestion window).
  - `UNRESOLVED`: Elapsed time between $60\text{s}$ and $300\text{s}$ (waiting on worker retry).
  - `CONFIRMED_MISSING`: Elapsed time $> 300\text{s}$ without expected audit records, or explicit audit insertion failure logged.
- **Trigger**: `BREAK_GLASS_ACTIVATED` followed by evidence state `CONFIRMED_MISSING` within observation deadline.
- **Severity**: `CRITICAL` | **Window**: 600s (deadline 300s).
- **Evidence**: `BreakGlassRequest.id`, observation window start/end timestamps, confirmed gap.
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
- **Precise Metrics Separation**:
  - `backlog_records`: Unsealed audit records count ($N$).
  - `oldest_unsealed_age_seconds`: Age in seconds of oldest unsealed audit log ($T_{\text{age}}$).
  - `sealer_failures`: Count of `status="failed"` sealer runs.
  - `sealer_lock_timeouts`: Count of `status="locked"` sealer runs.
- **Trigger**: Condition A (`backlog_records > 1000`, exceeding 1 standard epoch) **AND** Condition B (`sealer_failures >= 3` OR `sealer_lock_timeouts >= 5`) within 900s, **AND/OR** Condition C (`oldest_unsealed_age_seconds > 1800s`).
- **Severity**: `HIGH` | **Window**: 900s.
- **Evidence**: Backlog record count, oldest unsealed record ID and timestamp, sealer run statuses.
- **False-Positive Risk**: Huge legitimate exam submission burst (healthy sealer catches up within minutes).
- **Implementation Status**: **AVAILABLE NOW** (`bsea_audit_sealer_lag_events`, sealer metrics).

---

## 12. Rule Evidence Model

Under **INVARIANTS 8, 11, and 12**, detection signals do not duplicate examination content.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        EVIDENCE GRAPH TOPOLOGY                         │
├────────────────────────────────────────────────────────────────────────┤
│                           SecuritySignal                               │
│                                 │                                      │
│               ┌─────────────────┴──────────────────┐                   │
│               ▼                                    ▼                   │
│        Matched Conditions                 Evidence References          │
│    (Count: 5, Threshold: 5)             (Pointers to Immutable Logs)   │
│               │                                    │                   │
│               │                     ┌──────────────┼──────────────┐    │
│               ▼                     ▼              ▼              ▼    │
│         Rule Definition       audit_log_id      trace_id     request_id│
│        (RULE-A, v1.0.0)             │              │              │    │
│                                     ▼              ▼              ▼    │
│                             AuditLog Row      CloudWatch     Access Log│
│                           (Database Record)   (JSON Logs)    (ALB Log) │
└────────────────────────────────────────────────────────────────────────┘
```

### Prohibited Content in Evidence
- **Question Bodies & Descriptions**: Strictly excluded.
- **Option Text & Option Randomization Seeds**: Strictly excluded.
- **Answer Keys**: Strictly excluded.
- **Candidate Responses**: Strictly excluded.
- **Passwords, Tokens, Session Keys, DEKs, Private Keys**: Strictly excluded.

---

## 13. Security Signal Model

A detection signal is a structured, immutable notification emitted to telemetry.

```python
@dataclass(frozen=True)
class SecuritySignal:
    signal_id: str                      # Unique UUIDv4
    rule_id: str                        # e.g., "RULE-A"
    rule_version: str                   # e.g., "1.0.0"
    detected_at: datetime               # UTC timestamp
    severity: str                       # LOW, MEDIUM, HIGH, CRITICAL
    confidence: float                   # 0.0 to 1.0 (deterministic confidence)
    mode: str                           # "SHADOW"
    correlation_keys: Dict[str, str]    # Matched keys (actor_id, session_id, ip_hash)
    evidence_references: List[str]      # List of AuditLog IDs and Trace IDs
    event_count: int                    # Total matched events
    window_seconds: int                 # Evaluation window
    policy_version: str                 # e.g., "BSEA-RULES-v1"
    explanation: str                    # Human-readable explanation of matched conditions
```

### Critical Semantic Disambiguation
```
┌───────────────────────────────────────────────────────────────────────────────────────┐
│                           SECURITY SIGNAL SEMANTICS                                    │
├───────────────────────────────────────────────────────────────────────────────────────┤
│ DETECTION SIGNAL  : An automated advisory observation that a deterministic pattern    │
│                     matched within a defined correlation window.                      │
│        ≠                                                                              │
│ SECURITY INCIDENT : A verified security condition requiring human triage, forensic    │
│                     investigation, and institutional escalation (Phase 5D).           │
│        ≠                                                                              │
│ CONFIRMED ATTACK  : A legally or forensically proven hostile exploit attempt against   │
│                     the examination integrity.                                        │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 14. Shadow Mode

**Shadow Mode is mandatory in Phase 3C-5C.**

```
Event Stream ───► Normalizer ───► Rule Engine ───► SecuritySignal ───► Log / Metric / Alert
                                                        │
                                                        ▼
                                           ┌────────────────────────┐
                                           │  AUTONOMOUS RESPONSE?  │
                                           │       STRICTLY NO      │
                                           └────────────────────────┘
```

### Prohibited Autonomous Actions in Shadow Mode
1. Account locking or credential invalidation.
2. Candidate examination session termination or submission blocking.
3. IP address or CIDR blocking at firewall/WAF/ALB.
4. Device fingerprint blacklisting.
5. Automatic poison audit quarantine.
6. Question invalidation or emergency paper replacement.
7. Modifying KMS cryptographic state or audit hash chains.

---

## 15. CloudTrail/KMS Correlation

Application-side KMS operations (`_audit_kms_operation`) are reconciled with AWS CloudTrail KMS event streams. Because CloudTrail events experience an unavoidable **1 to 15-minute delivery delay**, correlation must be explicitly asynchronous.

### 15.1 Four Explicit Reconciliation States

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
│                      │ CloudTrail trail failure or local mock execution in CI/testing.  │
├──────────────────────┼──────────────────────────────────────────────────────────────────┤
│ CONFLICTING_EVIDENCE │ CloudTrail record exists with different actor ARN, denied status,│
│                      │ or unexpected encryption context. Potential security anomaly.    │
└──────────────────────┴──────────────────────────────────────────────────────────────────┘
```

Under **INVARIANT 14**, missing CloudTrail evidence must **never** be automatically classified as an attack.

---

## 16. Failure Semantics

Under **INVARIANTS 2 and 15**, detection is strictly observational and non-authoritative.

| Component Outage / Fault | Impact on Core Examination | Impact on Detection Engine | Handling & Recovery Semantics |
| :--- | :--- | :--- | :--- |
| **PostgreSQL DB Slowdown** | Core auth/exam operations proceed according to existing DB pool limits | Detection engine query throttled | Detection delays event polling; drops non-critical correlation cache; never blocks exam writes |
| **Redis Outage** | Candidate exams switch to fail-soft local memory sessions (per Phase 3C-1) | Multi-worker correlation degrades to single-task local ring buffer | In-memory fallback; signals marked `degraded_correlation=True` |
| **KMS API Outage** | Exam decryption fails closed (core security requirement) | KMS correlation logs errors | Records `KMS_UNAVAILABLE` signal; does not crash app |
| **CloudTrail Unavailable** | Zero impact on exams | Reconciliation marked `MISSING_EVIDENCE` | Does not generate critical alert |
| **SQS / Event Queue Unavailable** | API commits audit log normally; queue emission fails soft | Detection worker receives no events | Logged as `TELEMETRY_DISPATCH_FAULT`; zero API interruption |
| **Detection Worker Crash** | **ZERO IMPACT** on student exams or admin access | Worker restarts via ECS task supervisor | Reconnects to SQS; resumes from unacknowledged messages |
| **Out-of-Order / Skewed Events** | No impact | Temporal buffer uses event `timestamp`, not arrival order | Events buffered in a 60-second jitter window before terminal rule evaluation |
| **Duplicate Events** | Idempotency keys in API | Correlation engine deduplicates by `event_id` | Duplicate `event_id` discarded as `DUPLICATE_EVENT` |
| **Poison Event Ingestion** | No impact | Schema validation fails | Poison event routed to Dead-Letter Queue (DLQ) without crash |

---

## 17. Distributed Execution

```
           ALB (Round-Robin / IP-Hash)
            │                     │
            ▼                     ▼
     ECS Fargate Task 1    ECS Fargate Task 2
     (B-SEA API Worker 1)  (B-SEA API Worker 2)
            │                     │
            ▼                     ▼
    PostgreSQL 16 (RDS) ──► Amazon SQS (Durable Event Stream)
                                  │
                                  ▼
                        ECS Detection Worker(s)
                                  │
                                  ▼
                        Amazon ElastiCache Redis
                       (Non-Authoritative ZSETs)
```

1. **Transactional Outbox / Post-Commit Dispatch**: API workers write immutable audit records to PostgreSQL in Mode A/B transactions. Upon successful commit, events are dispatched asynchronously to SQS.
2. **Detection Worker Consumer**: Dedicated ECS Fargate detection workers poll SQS, update Redis sliding-window ZSETs using atomic pipelines, evaluate rules, and acknowledge messages (`DeleteMessage`).
3. **Worker Crash Recovery**: If a detection worker crashes mid-evaluation, the message visibility timeout expires and SQS re-delivers the event to a surviving worker. Idempotency hashes prevent duplicate signal generation.

---

## 18. Data Minimization

1. **Zero Examination Plaintext**: Signals, evidence references, queues, and caches never store question bodies, answer keys, or candidate responses.
2. **Zero Secret Storage**: Never store passwords, password hashes, JWTs, DEKs, or private keys.
3. **PII Isolation**: `actor_id` and `ip_hash` are pseudo-anonymous identifiers. Actual candidate names, phone numbers, and emails are never fetched into detection state.
4. **Retention Rules**:
   - In-memory ring buffer: Max 3,600s (1 hour).
   - Redis ZSETs: TTL 7,200s (2 hours).
   - Structured Signals in CloudWatch: 90-day retention.
   - SQS Queue retention: 4 days (DLQ 14 days).

---

## 19. Metric Cardinality Mathematics

Phase 3C-5C adheres strictly to the bounded metric architecture defined in Phase 3C-5B.

### 19.1 Compile-Time Label Domains
```python
ALLOWED_DETECTION_RULES: Set[str] = {
    "RULE-A", "RULE-B", "RULE-C", "RULE-D", "RULE-E",
    "RULE-F", "RULE-G", "RULE-H", "RULE-I", "RULE-J",
    "other"
}  # Finite domain size = 11

ALLOWED_DETECTION_SEVERITIES: Set[str] = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}  # Finite domain size = 4
ALLOWED_DETECTION_MODES: Set[str] = {"shadow", "active"}  # Finite domain size = 2
ALLOWED_EVALUATION_RESULTS: Set[str] = {"match", "no_match", "error"}  # Finite domain size = 3
ALLOWED_CORRELATION_STATUSES: Set[str] = {"correlated", "unresolved", "missing", "conflicting"}  # Finite domain size = 4
```

### 19.2 Mathematical Upper Bounds for 5C Metrics

| Metric Name | Type | Labels | Domain Dimensions | Base Series Formula | Base Cardinality | Expanded Series |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `bsea_detection_signals_total` | Counter | `rule_id`, `severity`, `mode` | $11 \times 4 \times 2$ | $11 \times 4 \times 2$ | **88** | 88 |
| `bsea_detection_rule_evaluations_total`| Counter | `rule_id`, `result` | $11 \times 3$ | $11 \times 3$ | **33** | 33 |
| `bsea_cloudtrail_reconciliation_total`| Counter | `status` | 4 | 4 | **4** | 4 |
| `bsea_detection_engine_lag_seconds` | Gauge | *None* | 1 | 1 | **1** | 1 |
| **TOTAL NEW 5C SERIES** | | | | | **126 base** | **126 expanded** |

### 19.3 Aggregate Telemetry Footprint (5B + 5C)
- **Phase 3C-5B Baseline**: **520 base series** (**1,390 expanded series** with histogram buckets).
- **Phase 3C-5C Additions**: **126 base series** (**126 expanded series**; zero histograms added).
- **Total Combined B-SEA Telemetry**:
  $$\text{Total Base Series} = 520 + 126 = \mathbf{646}$$
  $$\text{Total Expanded Series} = 1,390 + 126 = \mathbf{1,516}$$
- **Memory Overhead**: $126 \times 2\text{ KB} \approx 252\text{ KB}$ RAM. Zero risk of metric cardinality explosion.

---

## 20. Performance Model

To maintain scientific credibility, B-SEA does not make unverified absolute claims such as "zero overhead" or "unlimited throughput".

1. **Throughput Expectations**:
   - Detection worker throughput is bound by Redis ZSET insertion latency ($O(\log N)$) and rule evaluation overhead ($O(K)$ where $K$ is event count in window).
   - Expected single-worker evaluation throughput: $\approx 2,500$ events/sec.
2. **Backpressure & Queue Depth**:
   - SQS provides durable buffering during peak exam submission waves.
   - If SQS queue depth exceeds 10,000 messages, CloudWatch alarms trigger ECS Fargate auto-scaling to launch additional detection workers.
3. **Memory Footprint**:
   - In prototype mode, memory is capped at $N=50,000$ events ($\approx 25\text{ MB}$ RAM).
   - In production, Redis ZSET memory is capped by TTL-based key eviction.

---

## 21. Privacy & Retention

- **Detection Signals**: Retained in CloudWatch Logs for 90 days.
- **Evidence References**: Contain only UUIDs and hashes; no student personal data.
- **Audit Logs**: Authoritative 7-year statutory retention in PostgreSQL.
- **SQS Messages**: Default retention 4 days; DLQ retention 14 days.

---

## 22. Test Strategy

When Phase 3C-5C implementation is authorized, validation must satisfy the following 20-test matrix:

| Test ID | Category | Invariant & Scenario Verified | Expected Pass Criteria |
| :--- | :--- | :--- | :--- |
| **T01** | Normalization | Normalizes AuditLog, Auth, and CBT events | Complete mapping; zero field corruption |
| **T02** | Determinism | Re-evaluates Rules A-J on static event sets | Identical output across repeated runs |
| **T03** | Versioning | Bumps rule version; verifies policy metadata | Output reflects new version; old rules uncorrupted |
| **T04** | Shadow Mode | Injects high-severity attacks | Signals emitted; zero accounts locked; 0 blocks |
| **T05** | Evidence Graph | Validates `evidence_references` match real DB rows | Every ID exists; zero exam text present |
| **T06** | Window Expiry | Injects events outside window $W$ | Rule does not fire; state purges cleanly |
| **T07** | Burst Matching | Injects 5 failures in 30s followed by 1 success | Rule-A fires with `confidence=1.0` |
| **T08** | Deduplication | Injects duplicate `event_id`s | Engine deduplicates; count not falsely inflated |
| **T09** | Out-of-Order | Injects events with scrambled timestamps | Jitter buffer orders by event timestamp |
| **T10** | Missing Fields | Feeds events with null `actor_id` or `device_id` | Degrades gracefully; logs missing evidence |
| **T11** | Stale Cleanup | Cleans keys older than window $W$ | Expired entries purged from ring buffer / Redis |
| **T12** | CloudTrail Correlated | Feeds application event + matching CloudTrail record | Status reports `CORRELATED` |
| **T13** | CloudTrail Unresolved | Feeds fresh KMS event (< 15 mins old) | Status reports `UNRESOLVED` |
| **T14** | CloudTrail Missing | Feeds KMS event > 15 mins old without CloudTrail | Status reports `MISSING_EVIDENCE` |
| **T15** | CloudTrail Conflict | Feeds matching RequestId with conflicting IAM ARN | Status reports `CONFLICTING_EVIDENCE` |
| **T16** | Cardinality Bounds | Validates all emitted labels belong to finite sets | All labels $\in$ allowed domains; zero unbounded series |
| **T17** | Data Isolation | Scans emitted signals for question text / secrets | 100% clean; zero secret leaks |
| **T18** | Engine Crash Fail-Safe| Injects unhandled exception into detection engine | Core API continues serving candidate exams normally |
| **T19** | Multi-Worker Race | Two concurrent workers evaluate overlapping streams | Idempotency hash prevents duplicate signals |
| **T20** | Zero Block Verif. | Worst-case attack simulation across all 10 rules | Zero candidate sessions interrupted; 0 DB changes |

---

## 23. Threat Model

| Threat Actor / Vector | Attack Technique | Impact on Detection | B-SEA Architectural Defense |
| :--- | :--- | :--- | :--- |
| **Malicious Candidate** | API flood to exhaust correlation memory | Telemetry flood, memory pressure | Bounded ring buffers; rate limiter drops requests before normalization |
| **Rogue Administrator** | Attempt to delete audit records to hide activity | Evidence destruction | PostgreSQL triggers block `DELETE`; hash chain breaks if tampered |
| **Insider Adversary** | Tampering with detection rules to blind SecOps | Detection blindness | Rules are version-controlled in Git; immutable policy version in signals |
| **Low-and-Slow Attacker** | Actions spaced just outside sliding window | Rule evasion | Multi-tier correlation windows ($W_1=1\text{m}$, $W_2=5\text{m}$, $W_3=15\text{m}$, $W_4=1\text{h}$) |
| **Poison Event Flood** | Submitting malformed JSON to crash normalizer | Denial of detection | Strict Pydantic validation; malformed events routed to DLQ |

---

## 24. Production vs Prototype

| Architectural Dimension | Local Test Environment / Prototype | AWS Target Production Architecture |
| :--- | :--- | :--- |
| **Event Delivery** | In-process `asyncio.Queue` | Amazon SQS (Durable queue with KMS SSE) |
| **Detection Workers** | In-process asynchronous task | Dedicated ECS Fargate tasks with auto-scaling |
| **Correlation State** | In-memory `collections.deque` ring buffer | Amazon ElastiCache for Redis 7 (Multi-AZ ZSETs) |
| **Database** | Local PostgreSQL 16 on `localhost:5432` | Amazon RDS PostgreSQL 16 Multi-AZ + RDS Proxy |
| **KMS Provider** | `MockKMS` (AES-256-GCM + Ed25519) | AWS KMS Customer Managed Keys (CMKs) |
| **CloudTrail Feed** | Mock synthetic CloudTrail JSON feed | CloudWatch Logs Subscription Filter from CloudTrail |
| **Failure Mode** | Fail-safe in-process logging | SQS DLQ + CloudWatch Alarms + SNS Notifications |

---

## 25. Implementation Boundary

When implementation authorization is granted, modifications will be strictly confined to:

### Proposed New Files (Phase 3C-5C Implementation Scope)
- `backend/app/modules/detection/` [NEW DIRECTORY]
  - `__init__.py`: Package export.
  - `models.py`: Immutable models (`SecurityEventNormalized`, `SecuritySignal`, `DetectionRuleDefinition`).
  - `normalizer.py`: Event normalization mapping from AuditLog, Auth, and CBT.
  - `engine.py`: Deterministic rule evaluation engine.
  - `rules.py`: Canonical rule definitions (RULE-A through RULE-J).
  - `correlation.py`: In-memory ring buffer (prototype) and Redis ZSET (production) correlation manager.
  - `cloudtrail.py`: Asynchronous CloudTrail/KMS reconciliation engine.
- `backend/tests/security/test_phase3c5c_detection.py` [NEW TEST SUITE]
  - Complete implementation of matrix T01–T20.

### Proposed Modified Files
- `backend/app/core/metrics.py`: Registering 4 bounded detection metrics ($\le 126$ base series).

### Strictly Frozen Files (NO CHANGES PERMITTED)
- `backend/app/core/models.py`: **FROZEN.** No schema changes.
- `backend/alembic/`: **FROZEN.** No migrations.
- `backend/app/modules/security/service.py`: **FROZEN.** Left untouched; deprecation deferred.
- `backend/app/modules/audit/sealer.py`: **FROZEN.** Cryptographic sealer pipeline unchanged.
- `backend/app/modules/audit/quarantine.py`: **FROZEN.** Dual-custody quarantine unchanged.
- `backend/app/crypto/kms_interface.py`: **FROZEN.** KMS wrapper unchanged.
- `terraform/`: **FROZEN.** No infrastructure changes.

---

## 26. Deferred Work

- **Phase 5D — Security Incident Management & Case Workflow**:
  - `security_incidents` database table and migrations.
  - SecOps case triage dashboard, analyst assignments, and status transitions (`OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`).
  - Formal deprecation and database migration away from legacy `SecurityService`.
- **Phase 5E — Policy-Governed Containment (Active Mode Transition)**:
  - Dual-custody containment workflows (human-in-the-loop candidate session termination).
  - Automated emergency paper replacement protocols.
- **Phase 5F — Enterprise SIEM & SOC Integration**:
  - Direct integration into AWS Security Lake, Splunk, or OpenSearch.
  - PagerDuty and incident response escalation webhooks.

---

## 27. Risks

1. **Risk: False Positives Causing Alarm Fatigue**:
   - *Mitigation*: Mandatory Shadow Mode; zero paging alerts until thresholds are validated against real exam load.
2. **Risk: SQS Message Lag During Exam Concourse**:
   - *Mitigation*: ECS auto-scaling triggers when queue depth $> 10,000$; API write path decoupled from queue consumption.
3. **Risk: Multi-AZ Redis Outage**:
   - *Mitigation*: Non-authoritative fail-soft fallback to worker local memory; exams continue without interruption.
4. **Risk: Clock Skew Across Distributed Tasks**:
   - *Mitigation*: AWS Time Sync Service (NTP) enforced across all Fargate tasks; 60s jitter window before rule evaluation.

---

## 28. Acceptance Criteria

Phase 3C-5C can be formally accepted only when:
1. Architecture document `BSEA_PHASE3C_5C_DETECTION_CORRELATION_ARCHITECTURE_REVIEW_REV02.md` is approved.
2. Complete test suite (220 baseline + 20 Phase 3C-5C tests = 240 tests) passes with 0 failures.
3. Every proposed detection rule (Rules A-J) is deterministic, explainable, and versioned.
4. Shadow mode is verified with 0 automated blocks, 0 account locks, and 0 quarantines.
5. Telemetry cardinality is strictly bounded, proving $\le 126$ additional base time series.
6. Evidence graphs strictly exclude all question plaintext and sensitive materials.
7. CloudTrail/KMS reconciliation correctly reports all four explicit states.
8. Detection engine failure is proven to have zero impact on examination security controls.

---

## 29. Final Architecture Decision

To eliminate ambiguity, Rev-02 formalizes the following explicit architectural decisions:

### Decision A: Detection Execution Architecture
- **Recommendation**: **Dedicated ECS Fargate Detection Worker (Option C)** for AWS Production; **In-Process Background Engine (Option A)** for Local Testing and CI.
- **Rationale**: In-process background tasks fail in a multi-instance ECS Fargate deployment because events from the same actor/session are routed across different tasks. A dedicated worker cleanly decouples detection processing from student-facing API latency and CPU overhead.

### Decision B: Event Delivery Mechanism
- **Recommendation**: **Amazon SQS (Standard Queue with KMS SSE + Worker-Side Deduplication)** for AWS Production; **In-Process `asyncio.Queue`** for Local Testing.
- **Rationale**: Amazon SQS provides proven point-to-point delivery, native consumer backpressure, built-in dead-letter queues (DLQ) for malformed poison events, low operational complexity, and native KMS encryption. EventBridge is over-engineered for point-to-point worker consumption and lacks native backpressure control.

### Decision C: Correlation State Architecture
- **Recommendation**: **Amazon ElastiCache for Redis 7 (ZSET with score=timestamp, non-authoritative)** for AWS Production; **In-Memory Ring Buffer (`collections.deque`)** for Local Testing.
- **Rationale**: Redis ZSETs allow efficient sliding-window range queries across distributed workers. Redis is strictly non-authoritative; PostgreSQL `audit_logs` remains the sole immutable system of record.

### Decision D: CloudTrail Ingestion Mechanism
- **Recommendation**: **CloudWatch Logs Subscription Filter** streaming CloudTrail KMS events to the B-SEA telemetry log group.
- **Rationale**: Subscription filters provide near real-time, managed log streaming with low latency and zero Lambda maintenance overhead compared to S3 batch processing.

### Decision E: Legacy Security Service
- **Recommendation**: **Leave `backend/app/modules/security/service.py` strictly unchanged** in Phase 3C-5C; defer deprecation, refactoring, and database migration to Phase 5D.
- **Rationale**: Avoids risky cross-module regressions during Phase 3C-5C. The new detection engine will be completely independent and modular.

---
*End of Architecture Review Document Rev-02. Repository code remains strictly frozen pending user review and explicit implementation authorization.*
