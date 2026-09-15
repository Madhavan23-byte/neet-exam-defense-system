# B-SEA Phase 3C-5C — Detection & Correlation Foundation
## Forensic Architecture & Design Review (Rev-01)

| Document Metadata | Authoritative Specification |
| :--- | :--- |
| **Document ID** | `BSEA-ARCH-3C-5C-REV01` |
| **System** | Bharat Secure Examination Architecture (B-SEA) |
| **Component** | Security Intelligence, Correlation Engine & Shadow Detection |
| **Accepted Baseline** | `d6d430f929caa90ef8f0390abeceaa362c302ace` (`HEAD == origin/main`) |
| **Regression Baseline** | 220 passed, 5 skipped, 0 failed (225 collected) |
| **Current Status** | **DRAFT FOR FORENSIC ARCHITECTURE REVIEW (CODE FREEZE STRICTLY PRESERVED)** |
| **Operational Phase** | Phase 3C-5C (Building upon Phase 3C-5B Production Observability) |
| **Security Mode** | **STRICT SHADOW MODE (ADVISORY ONLY — ZERO AUTONOMOUS INTERVENTION)** |

---

## 1. Executive Summary

Phase 3C-5B established an immutable, bounded, production-grade **Observability Foundation** for B-SEA, introducing structured JSON logging with 3-tier recursive redaction, W3C distributed tracing, a strictly bounded 16-metric Prometheus registry (520 base time series, 1,390 expanded series, hard ceiling of 1,400), and automated CloudWatch alarms.

While Phase 3C-5B answers *"What is happening in the system right now?"*, **Phase 3C-5C** addresses the higher-order question: ***"Are individual security events part of an anomalous, coordinated, or adversarial pattern?"***

Phase 3C-5C introduces the **Detection & Correlation Foundation** designed under the strict paradigm of:
```
Security Events (Audit/Auth/KMS/App)
       ↓
Event Normalization (Deterministic Internal Schema)
       ↓
Correlation Context (Actor / Session / Device / Resource / Temporal Window)
       ↓
Deterministic Detection Rule Engine (Versioned, Stateless Evaluation)
       ↓
Security Signals (Advisory Detections with Explainable Evidence References)
       ↓
Shadow Mode (Zero Autonomous Blocking / Containment / Alteration)
       ↓
Observability & Alerting (Structured Telemetry, Bounded Metrics & CloudWatch Alarms)
```

### Core Architectural Decisions & Boundaries
1. **Strict Shadow Mode**: Detection in Phase 3C-5C is strictly observational and advisory. Under no circumstances will a detection signal automatically terminate a session, lock an account, block an IP, cancel an exam, revoke credentials, or trigger cryptographic quarantine.
2. **Fail-Safe & Non-Authoritative**: The detection engine operates outside the critical transaction path of high-stakes examination workflows. Telemetry failure, correlation engine crash, or database slowdown cannot degrade, delay, or bypass authentication, authorization, or question delivery security controls.
3. **Evidence-Based & Content-Isolated**: Every generated detection signal links directly to immutable audit logs and correlation identifiers (`trace_id`, `request_id`, `audit_log_id`). Telemetry and evidence contain **zero plaintext question content, zero candidate responses, zero answer keys, and zero cryptographic keys**.
4. **Bounded Telemetry Cardinality**: Metric emissions for detection rules map into strictly finite, compile-time-bounded label domains (`rule_id`, `severity`, `mode`). Unbounded identifiers (`actor_id`, `session_id`, `device_id`, `trace_id`, `ip_hash`) are **strictly prohibited** from metric dimensions.
5. **No Incident Management DB**: Phase 3C-5C intentionally defers incident case-management schemas and triage tables (`security_incidents`) to Phase 5D. Signals are emitted as structured telemetry and transient operational state.

---

## 2. Current-State Inspection (Fact-Based Codebase Audit)

A thorough forensic inspection of the repository at commit `d6d430f929caa90ef8f0390abeceaa362c302ace` confirms the existing security mechanisms, event emission points, and schema definitions.

### 2.1 Existing Event Generation Landscape

| Domain | Event Types Emitted | Emission Location | Authority & Destination |
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

### 2.2 Existing Data Models & Schemas
1. **`AuditLog` (`backend/app/core/models.py:603`)**:
   - Primary key: `id` (UUIDv4).
   - Core fields: `seq`, `event_type`, `actor_id`, `actor_role`, `resource_type`, `resource_id`, `action`, `result` (`AuditResult`), `ip_hash`, `device_id`, `event_metadata` (`JSONB`), `risk_score`, `prev_hash`, `event_hash` (SHA-256), `trace_id`, `kms_request_id`, `created_at`, `timestamp`.
   - Database protection: PostgreSQL triggers prohibit `UPDATE` and `DELETE`.
2. **`AuditChainLink` (`backend/app/core/models.py:655`)**:
   - Contiguous 1-based `chain_seq` linking immutable audit logs via `prev_chain_hash` + `event_hash` -> `chain_hash`.
3. **`AuditEpochSeal` (`backend/app/core/models.py:692`)**:
   - RFC 6962 binary Merkle root and Ed25519 digital signature over contiguous link epochs (`[start_chain_seq, end_chain_seq]`).
4. **`AuditPoisonQuarantine` (`backend/app/core/models.py:729`)**:
   - Dual-custody cryptographic quarantine preventing poison audit events from blocking seal progress.
5. **`CandidateSession` (`backend/app/core/models.py:485`)**:
   - Candidate exam state: `candidate_id`, `exam_id`, `session_token_hash`, `started_at`, `expires_at`, `status`, `ip_hash`, `device_fingerprint`, `tab_switch_count`, `security_violations`. Partial index guarantees one active session per exam.
6. **Legacy Prototype Components**:
   - `SecurityService` (`backend/app/modules/security/service.py`) and `SecurityEvent` / `Incident` tables (`backend/app/core/models.py:777`). These rely on ad-hoc float math (`score += 0.5`) and inline DB writes without deterministic rule versioning, evidence chains, or shadow-mode controls. Phase 3C-5C isolates its foundation from these legacy tables.

### 2.3 Existing Telemetry & Observability Infrastructure (Phase 3C-5B)
- **Tracing Context**: `CURRENT_TRACE_ID` (W3C 32-hex format) and `CURRENT_REQUEST_ID` (UUIDv4) propagated via `contextvars` in `BSEAHttpTelemetryMiddleware`.
- **Data Minimization & Redaction**: Three-tier redaction in `backend/app/core/logging.py` cleans sensitive keywords, scrubs regex patterns (JWT, Argon2 hashes, AWS keys, PEM private keys), and redacts all exam body/answer fields.
- **Metric Catalog**: 16 strictly bounded Prometheus metrics registered in `backend/app/core/metrics.py`.
- **CloudWatch Foundation**: 10 metric alarms, 7 log metric filters, and an SNS alerting topic provisioned via `terraform/modules/cloudwatch_alarms/`.

---

## 3. Phase 3C-5C Goals

1. **Deterministic Event Normalization**: Create an in-memory normalized data contract (`SecurityEventNormalized`) that maps heterogeneous application events (Audit, Auth, CBT, KMS, Break-Glass) into a consistent schema.
2. **Multi-Dimensional Correlation**: Support correlation across 5 temporal and contextual pivots:
   - **Actor Identity**: Correlating actions by administrative users or candidate identities.
   - **Session & Device Context**: Correlating activities sharing `session_id`, `device_id`, or `ip_hash`.
   - **Resource Affinity**: Tracking access patterns to specific exams, forms, or questions.
   - **Distributed Trace Context**: Correlating synchronous actions bound to a single `trace_id` or `request_id`.
   - **Sliding Temporal Windows**: Aggregating events across sliding windows (e.g., 60s, 300s, 600s, 3600s).
3. **Deterministic, Versioned Detection Rule Engine**: Implement stateless, reproducible rule evaluation driven by explicit policy definitions with zero ML hallucinations or ad-hoc scoring.
4. **Shadow Mode Operation**: Emit signals as structured telemetry and advisory alerts without impacting examination continuity or candidates.
5. **Explainable Evidence Graphs**: Bind each signal to verifiable references (`audit_log_id`, timestamps, sequence counts) without duplicating sensitive exam content.
6. **Asynchronous CloudTrail/KMS Correlation**: Reconcile application-level KMS calls with delayed CloudTrail event feeds using four explicit reconciliation states (`CORRELATED`, `UNRESOLVED`, `MISSING_EVIDENCE`, `CONFLICTING_EVIDENCE`).
7. **Strict Cardinality Defense**: Ensure detection telemetry metrics do not introduce unbounded dimensions.

---

## 4. Explicit Non-Goals (Scope Freeze)

To maintain absolute security and architectural integrity, the following are **strictly out of scope** for Phase 3C-5C:

1. **No Autonomous Mitigation or Containment**: No automated account locking, IP blocking, candidate eviction, device ban, exam termination, or question invalidation.
2. **No Automated Audit Quarantine**: Automated quarantine of poison audit records without dual-operator cryptographic signatures is strictly forbidden.
3. **No Incident Management Database**: Phase 3C-5C will NOT create a `security_incidents` table, incident assignment workflows, ticketing integration, or SLA tracking (deferred to Phase 5D).
4. **No Machine Learning Anomaly Detection**: No probabilistic clustering, neural networks, or unexplainable heuristic scoring.
5. **No SIEM or SOC Platform**: B-SEA will not build an in-house SIEM, Splunk clone, or SOC ticketing portal.
6. **No Audit Ledger or Cryptographic Modifications**: No alterations to `AuditLog`, `AuditChainLink`, `AuditEpochSeal`, Merkle tree logic, or KMS signing infrastructure.
7. **No Plaintext Examination Content Ingestion**: The detection engine will never ingest, inspect, or process plaintext question bodies, candidate answers, or answer keys.

---

## 5. Security Invariants

The Phase 3C-5C architecture strictly enforces the following 15 security invariants:

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

## 6. Event Normalization Architecture

Events in B-SEA originate from multiple subsystems: FastAPI ASGI middleware, database audit models, authentication workflows, CBT proctoring sessions, and KMS client wrappers.

### 6.1 Data Availability Matrix (Current vs Future)

| Normalization Field | Target Type | Current State in Baseline | Source in Codebase | Strategy in 3C-5C |
| :--- | :--- | :--- | :--- | :--- |
| `event_id` | `str` (UUID) | **AVAILABLE NOW** | `AuditLog.id`, generated UUID | Direct mapping |
| `event_type` | `str` (Enum) | **AVAILABLE NOW** | `AuditLog.event_type`, logger tags | Canonical string lookup |
| `timestamp` | `datetime` (UTC) | **AVAILABLE NOW** | `AuditLog.created_at`, ISO 8601 | Normalized UTC timestamp |
| `actor_id` | `Optional[str]` | **AVAILABLE NOW** | `AuditLog.actor_id`, `User.id` | Retained in normalized event |
| `actor_role` | `Optional[str]` | **AVAILABLE NOW** | `AuditLog.actor_role`, JWT claims | Mapped to finite role set |
| `resource_type` | `Optional[str]` | **AVAILABLE NOW** | `AuditLog.resource_type` | Finite resource domain |
| `resource_id` | `Optional[str]` | **AVAILABLE NOW** | `AuditLog.resource_id` | Retained in normalized event |
| `action` | `Optional[str]` | **AVAILABLE NOW** | `AuditLog.action`, HTTP method | Standardized verb |
| `result` | `str` (Enum) | **AVAILABLE NOW** | `AuditLog.result` (`AuditResult`) | `SUCCESS`, `FAILURE`, `DENIED`, `BLOCKED`, `ERROR` |
| `trace_id` | `Optional[str]` | **AVAILABLE NOW** | `CURRENT_TRACE_ID` contextvar | W3C 32-hex string |
| `request_id` | `Optional[str]` | **AVAILABLE NOW** | `CURRENT_REQUEST_ID` contextvar | UUIDv4 string |
| `audit_log_id` | `Optional[str]` | **AVAILABLE NOW** | `CURRENT_AUDIT_LOG_ID` contextvar | References `audit_logs.id` |
| `session_id` | `Optional[str]` | **AVAILABLE NOW (CBT)** | `CandidateSession.id` | Passed in CBT events |
| `device_id` | `Optional[str]` | **AVAILABLE NOW** | `AuditLog.device_id`, fingerprint | Sanitized identifier |
| `ip_hash` | `Optional[str]` | **AVAILABLE NOW** | `AuditLog.ip_hash`, client IP hash | 64-char SHA-256 hash |
| `kms_request_id` | `Optional[str]` | **AVAILABLE NOW** | `AuditLog.kms_request_id` | AWS KMS response header ID |
| `source_subsystem` | `str` | **AVAILABLE NOW** | Inferred from event origin | `API`, `AUTH`, `CBT`, `KMS`, `SEALER`, `VERIFIER` |
| `policy_version` | `str` | **AVAILABLE NOW** | `DEFAULT_POLICY_VERSION` | `BSEA-DETECTION-v1` |

### 6.2 Normalized Event Data Contract (`SecurityEventNormalized`)

```python
@dataclass(frozen=True)
class SecurityEventNormalized:
    """
    Authoritative normalized internal security event representation.
    Strictly immutable, memory-efficient, and sanitized of exam content.
    """
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

## 7. Correlation Model & Architecture

Correlation groups related normalized events across space (actors, devices, IP subnets, resources) and time (sliding temporal windows) to reveal multi-step abuse patterns.

### 7.1 Correlation Dimension Taxonomy

To avoid metric cardinality explosion and memory exhaustion, dimensions are categorized into four distinct functional tiers:

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

### 7.2 Correlation Windows & State Tracking
1. **Sliding Time Windows**:
   - `W1_BURST` (60 seconds): Rapid authentication brute-forcing, high-frequency access denials.
   - `W2_TACTICAL` (300 seconds / 5 minutes): Multi-credential spray, MFA bypass attempts, grant escalation races.
   - `W3_OPERATIONAL` (900 seconds / 15 minutes): Break-glass anomaly sequences, sealer degradation vs audit backlog.
   - `W4_SESSION` (3600 seconds / 1 hour): Session hijacking, device hopping, slow-and-low question exfiltration.
2. **State Storage Architecture**:
   - **Prototype Mode**: In-memory ring buffer (`collections.deque`) keyed by correlation hashes (`SHA256(dimension + value)`), bounded to N=50,000 recent events with lazy TTL expiration.
   - **Distributed AWS Production Mode**: Redis 7 sorted sets (`ZSET`) keyed by `bsea:corr:{dimension_type}:{dimension_hash}` with score as epoch millisecond timestamp and automatic `EXPIRE`. PostgreSQL `audit_logs` remains the sole immutable system of record; Redis is purely a transient, non-authoritative sliding-window index.

---

## 8. Deterministic Detection Rule Engine

The detection rule engine is explicitly deterministic, rule-based, and auditable. It does not use stochastic weights or ML scoring.

### 8.1 Rule Definition Specification

```python
@dataclass(frozen=True)
class DetectionRuleDefinition:
    """
    Deterministic specification for an individual detection rule.
    """
    rule_id: str                          # e.g., "RULE-A"
    rule_version: str                      # e.g., "1.0.0"
    title: str                            # Human-readable title
    description: str                      # Detailed detection rationale
    severity: str                         # LOW, MEDIUM, HIGH, CRITICAL
    enabled: bool                         # Active toggle
    mode: str                             # SHADOW (mandatory in 5C)
    time_window_seconds: int              # Window duration (60, 300, 900, 3600)
    primary_dimension: str                # actor_id, session_id, device_id, etc.
    threshold: int                        # Event count or sequence threshold
    event_conditions: Dict[str, Any]      # Filter predicates
    evidence_requirements: List[str]      # Required fields for signal generation
    policy_version: str = "BSEA-RULES-v1"
```

### 8.2 Execution Semantics
- **Stateless Evaluation**: Given an ordered sequence of events within window W, the rule evaluation function `evaluate(events: List[SecurityEventNormalized]) -> Optional[SecuritySignal]` is pure and deterministic.
- **Explainable Evidence**: A rule only fires if all `evidence_requirements` are satisfied in the matched event set. If evidence is missing, the rule either yields a suppressed signal or flags `MISSING_EVIDENCE`.

---

## 9. Candidate Detection Rules (Rules A through J)

Ten candidate rules are specified below for architectural review. **None are implemented in code yet.**

### RULE-A: Repeated Authentication Failures Followed by Success
- **Security Rationale**: Detects brute-force credential stuffing or password guessing that eventually succeeds.
- **Trigger Condition**: >= 5 `LOGIN_FAILURE` events within 300s followed by 1 `LOGIN` (SUCCESS) on the same `actor_id` or `ip_hash`.
- **Severity**: `HIGH`.
- **False-Positive Risks**: Legitimate user forgotten password resetting or retrying multiple typos before success.
- **Detection Window**: 300 seconds.
- **Missing-Data Behavior**: If `actor_id` is unknown in failure (unregistered username), correlation falls back to `ip_hash`.
- **Implementable from Current Events**: **YES** (`app/modules/auth/service.py`).

### RULE-B: Repeated Authorization Denials Followed by Privileged Access
- **Security Rationale**: Detects authorization probing, role escalation, or IDOR vulnerability testing followed by successful access.
- **Trigger Condition**: >= 3 `ACCESS_DENIED` events on sensitive resources within 600s followed by `ACCESS_GRANTED` on the same `actor_id`.
- **Severity**: `HIGH`.
- **False-Positive Risks**: Reviewer attempting to access unassigned questions before administrator completes assignment workflow.
- **Detection Window**: 600 seconds.
- **Missing-Data Behavior**: Requires valid `actor_id`. If `actor_id` is missing, rule does not fire.
- **Implementable from Current Events**: **YES** (`app/modules/questions/service.py`).

### RULE-C: High-Frequency Question-Access Denials
- **Security Rationale**: Detects unauthorized attempts to access unreleased examination papers or brute-force question IDs.
- **Trigger Condition**: >= 10 `CANDIDATE_ACCESS_DENIED_UNRELEASED` or `ACCESS_DENIED` on questions within 60s from the same `session_id` or `device_id`.
- **Severity**: `CRITICAL`.
- **False-Positive Risks**: CBT client network retry loop on bad Wi-Fi reconnect.
- **Detection Window**: 60 seconds.
- **Missing-Data Behavior**: If `session_id` is missing, falls back to `device_id` or `ip_hash`.
- **Implementable from Current Events**: **YES** (`app/api/v1/candidates.py`).

### RULE-D: Multiple Distinct Accounts Associated with Same Device/Context
- **Security Rationale**: Detects proxy test-taking, impersonation, or candidate credential sharing at a test center.
- **Trigger Condition**: >= 3 distinct `actor_id` logins from the same `device_id` or `session_token_hash` within 900s.
- **Severity**: `HIGH`.
- **False-Positive Risks**: Shared proctor workstation or lab computer legitimately used sequentially by multiple candidates with quick proctor turnaround.
- **Detection Window**: 900 seconds.
- **Missing-Data Behavior**: Requires valid non-null `device_id`. If `device_id` is null, rule skips evaluation.
- **Implementable from Current Events**: **YES** (`CandidateSession.device_fingerprint`).

### RULE-E: Break-Glass Request Followed by Unusual Access Activity
- **Security Rationale**: Detects misuse of the emergency Break-Glass protocol to access examination papers outside designated scope.
- **Trigger Condition**: `BREAK_GLASS_ACTIVATED` event followed by question access requests for `exam_id` outside the approved `BreakGlassRequest.scope` within 1800s.
- **Severity**: `CRITICAL`.
- **False-Positive Risks**: Legitimate emergency where broader paper inspection was required but scope metadata was narrowly phrased.
- **Detection Window**: 1800 seconds.
- **Missing-Data Behavior**: Exam ID scope check requires valid `resource_id`.
- **Implementable from Current Events**: **YES** (`app/modules/break_glass/service.py`).

### RULE-F: Break-Glass Activation Followed by Abnormal Audit Pattern
- **Security Rationale**: Detects an insider attempting to suppress audit logging or disable the sealer immediately following emergency access.
- **Trigger Condition**: `BREAK_GLASS_ACTIVATED` followed by any audit insertion failure or absence of audit events during active session.
- **Severity**: `CRITICAL`.
- **False-Positive Risks**: Simultaneous infrastructure network hiccup during legitimate emergency use.
- **Detection Window**: 600 seconds.
- **Missing-Data Behavior**: Requires correlating Break-Glass session with audit heartbeat.
- **Implementable from Current Events**: **YES** (`app/modules/break_glass/service.py` & `AuditLog`).

### RULE-G: Repeated KMS-Related Failures Around Sensitive Operations
- **Security Rationale**: Detects cryptographic tampering, unauthorized key usage attempts, or compromised service roles attempting to decrypt ciphertext.
- **Trigger Condition**: >= 3 KMS failures (`KMS_SECURITY_EVENT_FAILURE` or `AccessDeniedException`) within 300s.
- **Severity**: `CRITICAL`.
- **False-Positive Risks**: Expired AWS IAM role credentials or KMS key policy replication delay during key rotation.
- **Detection Window**: 300 seconds.
- **Missing-Data Behavior**: If AWS `RequestId` is missing from local mock, records local operation name.
- **Implementable from Current Events**: **YES** (`app/crypto/kms_interface.py`).

### RULE-H: Audit Integrity Verification Failure Correlated with Security Events
- **Security Rationale**: Detects active audit tampering or database modification following unauthorized activities.
- **Trigger Condition**: `bsea_audit_verifier_status == fail` or `TAMPERED` audit result correlated with any `ACCESS_DENIED` within preceding 3600s.
- **Severity**: `CRITICAL`.
- **False-Positive Risks**: Unquarantined poison event (benign malformed record from migration).
- **Detection Window**: 3600 seconds.
- **Missing-Data Behavior**: If verifier reports `UNRESOLVED` due to replica lag, rule delays firing until rerun.
- **Implementable from Current Events**: **YES** (`app/modules/audit/service.py`).

### RULE-I: Repeated Rate-Limit Events Followed by Sensitive Access
- **Security Rationale**: Detects an adversary who mapped API rate limits, backed off, and then successfully accessed sensitive administrative endpoints.
- **Trigger Condition**: >= 5 rate-limit rejections within 300s followed by successful access to `/api/v1/exams/*` or `/api/v1/questions/*` from same `ip_hash`.
- **Severity**: `MEDIUM`.
- **False-Positive Risks**: High-volume legitimate administrative batch operations or CBT station sync retries.
- **Detection Window**: 600 seconds.
- **Missing-Data Behavior**: Correlated via `ip_hash` and `actor_id`.
- **Implementable from Current Events**: **YES** (`app/core/telemetry_middleware.py`).

### RULE-J: Sealer/Verifier Degradation Correlated with Audit Backlog Growth
- **Security Rationale**: Detects denial-of-service against the audit sealing pipeline (e.g. queue starvation or lock hoarding).
- **Trigger Condition**: `bsea_audit_sealer_lag_events > 1000` combined with >= 3 consecutive sealer lock timeouts (`status="locked"`) or failures.
- **Severity**: `HIGH`.
- **False-Positive Risks**: Huge exam submission burst generating expected transient backlog.
- **Detection Window**: 900 seconds.
- **Missing-Data Behavior**: Uses Prometheus metric values.
- **Implementable from Current Events**: **YES** (`bsea_audit_sealer_lag_events` & sealer metrics).

---

## 10. Security Signal Model

When a rule fires, it generates a structured, immutable `SecuritySignal`.

```python
@dataclass(frozen=True)
class SecuritySignal:
    """
    Authoritative representation of an advisory security detection signal.
    """
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

## 11. Evidence Model & Sensitive Data Isolation

To comply with **INVARIANT 8, 11, and 12**, detection signals do not copy examination payloads. Instead, they reference immutable records.

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
- **Plaintext Question Bodies**: Strictly excluded.
- **Candidate Answers & Option Randomization Seeds**: Strictly excluded.
- **Answer Keys**: Strictly excluded.
- **Passwords, Tokens, Session Keys, DEKs, Private Keys**: Strictly excluded.

---

## 12. Asynchronous CloudTrail / KMS Correlation

B-SEA Phase 3C-3 established application-side KMS logging (`_audit_kms_operation`). AWS CloudTrail records the control-plane and data-plane side of KMS API calls. However, CloudTrail events arrive with a **1 to 15-minute ingestion lag**.

### 12.1 Four Explicit Reconciliation States

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

Under **INVARIANT 14**, missing CloudTrail evidence must **never** be interpreted as an automatic attack. It reflects the asynchronous nature of AWS log delivery.

---

## 13. Shadow Mode Operational Framework

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

### Prohibited Actions in Shadow Mode
1. Account deactivation or password invalidation.
2. Candidate examination session termination.
3. Candidate exam submission rejection.
4. IP address or CIDR blocking at firewall/ALB/WAF.
5. Device fingerprint blacklisting.
6. Automatic poison audit quarantine.
7. Question invalidation or emergency paper replacement.

---

## 14. Detection Failure Semantics & Fail-Safe Operation

Under **INVARIANT 2 and 15**, detection is non-authoritative.

| Component Outage / Fault | Impact on Core Examination | Impact on Detection Engine | Handling & Recovery Semantics |
| :--- | :--- | :--- | :--- |
| **PostgreSQL DB Slowdown** | Core auth/exam operations proceed according to existing DB pool limits | Detection engine query throttled | Detection delays event polling; drops non-critical correlation cache; never blocks exam writes |
| **Redis Outage** | Candidate exams switch to fail-soft local memory sessions (per Phase 3C-1) | Multi-worker correlation degrades to single-task local ring buffer | In-memory fallback; signals marked `degraded_correlation=True` |
| **KMS API Outage** | Exam decryption fails closed (core security requirement) | KMS correlation logs errors | Records `KMS_UNAVAILABLE` signal; does not crash app |
| **Detection Engine Crash** | **ZERO IMPACT** on student exams or admin access | Detection restarts or remains idle | Unhandled exceptions caught by top-level wrapper; logged as `DETECTION_ENGINE_FAULT` |
| **Out-of-Order / Skewed Events** | No impact | Temporal buffer uses event `timestamp`, not arrival order | Events buffered in a 60-second jitter window before terminal rule evaluation |
| **Duplicate Events** | Idempotency keys in API | Correlation engine deduplicates by `event_id` | Duplicate `event_id` discarded as `DUPLICATE_EVENT` |

---

## 15. Cardinality & Metric Performance Analysis

Phase 3C-5C adheres strictly to the bounded metric architecture defined in Phase 3C-5B.

### 15.1 Proposed Phase 3C-5C Metrics

```python
# Exact compile-time label domains
ALLOWED_DETECTION_RULES: Set[str] = {
    "RULE-A", "RULE-B", "RULE-C", "RULE-D", "RULE-E",
    "RULE-F", "RULE-G", "RULE-H", "RULE-I", "RULE-J",
    "other"
}  # Cardinality = 11

ALLOWED_DETECTION_SEVERITIES: Set[str] = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}  # Cardinality = 4
ALLOWED_DETECTION_MODES: Set[str] = {"shadow", "active"}  # Cardinality = 2
ALLOWED_CORRELATION_STATUSES: Set[str] = {"correlated", "unresolved", "missing", "conflicting"}  # Cardinality = 4
```

### 15.2 Metric Catalog Additions & Mathematical Upper Bounds

| Metric Name | Type | Labels | Label Domain Sizes | Base Time Series |
| :--- | :--- | :--- | :--- | :--- |
| `bsea_detection_signals_total` | Counter | `rule_id`, `severity`, `mode` | 11 x 4 x 2 | **88** |
| `bsea_detection_rule_evaluations_total` | Counter | `rule_id`, `result` (`match`, `no_match`, `error`) | 11 x 3 | **33** |
| `bsea_cloudtrail_reconciliation_total` | Counter | `status` | 4 | **4** |
| `bsea_detection_engine_lag_seconds` | Gauge | *None* | 1 | **1** |
| **Total 5C Metric Expansion** | | | | **126 base series** |

### 15.3 System Total Telemetry Footprint
- **Phase 3C-5B Baseline**: 520 base series (1,390 expanded histogram series).
- **Phase 3C-5C Addition**: 126 base series (0 histograms added).
- **New Aggregate System Total**: 520 + 126 = **646 base time series** (1,390 + 126 = **1,516 expanded series**).
- **Overhead**: Maximum memory footprint of new series ~ 126 x 2 KB ~ 252 KB RAM. Zero risk of memory exhaustion or Prometheus scrape degradation.

---

## 16. Privacy, Data Retention & Secrets Isolation

1. **Zero Secret Storage**: Signals and evidence references never store passwords, password hashes, JWTs, decryption keys, or session tokens.
2. **PII Isolation**: `actor_id` and `ip_hash` are pseudo-anonymous identifiers. Actual candidate names, phone numbers, and emails are never fetched or stored in correlation memory.
3. **Data Retention Policies**:
   - **In-Memory Correlation State**: Retained for a maximum of 3,600 seconds (1 hour) and purged via FIFO ring buffer.
   - **Redis Correlation Sets**: Key TTL set to 7,200 seconds (2 hours).
   - **Emitted Security Signals**: Persisted in structured application logs (CloudWatch Logs) with a **90-day retention** period, matching compliance standards.
   - **Audit Logs (System of Record)**: Immutable, 7-year statutory retention in RDS PostgreSQL, sealed into Ed25519 epoch manifests.

---

## 17. Concurrency & Distributed Execution (Multi-Worker ECS)

In AWS production, B-SEA runs across multiple ECS Fargate tasks behind an Application Load Balancer.

```
           ALB (Round-Robin / IP-Hash)
            │                     │
            ▼                     ▼
     ECS Fargate Task 1    ECS Fargate Task 2
     (B-SEA Worker 1)      (B-SEA Worker 2)
            │                     │
            ├─────────────────────┤
            ▼                     ▼
      Redis 7 Cluster       PostgreSQL 16 (RDS)
   (Non-Authoritative       (Authoritative Audit
    Correlation ZSETs)       and Examination State)
```

1. **Shared Sliding Windows via Redis**: Multi-worker tasks share sliding-window state by executing atomic Redis `ZADD` and `ZRANGEBYSCORE` pipelines.
2. **PostgreSQL as Sole Authority**: Redis is strictly a performance cache for temporal correlation. If Redis becomes unavailable, workers fall back to local in-memory sliding windows. Under no circumstances does Redis become authoritative for exam state.
3. **Evaluation Idempotency**: When multiple workers observe events from the same session or actor, signal generation is deduplicated by calculating an idempotency hash:
   SignalHash = SHA256(rule_id + primary_dimension_value + window_bucket)
   This prevents alert storms when multiple workers process events concurrently.

---

## 18. Observability & Alerting Integration

Phase 3C-5C integrates directly with Phase 3C-5B telemetry pipes:

```
[SecuritySignal Generated]
            │
            ▼
logger.info("SECURITY_SIGNAL: %s", signal.to_json())
            │
            ▼
CloudWatch Logs (Structured Single-Line JSON)
            │
            ▼
CloudWatch Log Metric Filter:
{ $.signal_id = "*" && $.mode = "SHADOW" }
            │
            ▼
CloudWatch Metric Alarm:
"bsea-production-critical-security-signals"
            │
            ▼
SNS Topic: "bsea-production-security-alerts" (KMS Encrypted)
            │
            ▼
SecOps On-Call / Security Email
```

---

## 19. Comprehensive Test Strategy (T01-T20 Matrix)

When Phase 3C-5C implementation is eventually authorized, verification must satisfy the following 20-test matrix:

| Test ID | Test Category | Specification & Invariant Verified | Expected Outcome |
| :--- | :--- | :--- | :--- |
| **T01** | Event Normalization | Normalizes AuditLog, Auth, and CBT events into `SecurityEventNormalized` | Exact field mapping; zero data loss |
| **T02** | Rule Determinism | Evaluates RULE-A through RULE-J with static event datasets | 100% byte-for-byte identical signal output |
| **T03** | Rule Versioning | Evaluates rule under version bump with changed threshold | Proper version reflected in signal metadata |
| **T04** | Shadow Mode Assurance | Emits signals during simulated brute force or privilege escalation | Signals emitted; zero accounts locked; zero HTTP 403 blocks |
| **T05** | Evidence Graph Integrity | Validates that signal `evidence_references` match real `audit_log_id`s | Every ID exists in DB; zero exam text present |
| **T06** | Temporal Window Expiry | Injects events spaced outside window W | Rule does not fire; events expire cleanly |
| **T07** | Burst Window Matching | Injects 5 failures in 30s followed by 1 success | Rule-A fires with `confidence=1.0` |
| **T08** | Duplicate Event Handling | Feeds duplicate `event_id` into correlation engine | Engine deduplicates; threshold not falsely inflated |
| **T09** | Out-of-Order Events | Injects events with scrambled arrival timestamps | Jitter buffer orders by event timestamp correctly |
| **T10** | Missing Correlation Fields| Feeds events with null `actor_id` or `device_id` | Engine degrades gracefully; records missing evidence |
| **T11** | Stale Correlation State | Evaluates cleanup of correlation keys older than window W | Expired entries purged from ring buffer / Redis |
| **T12** | CloudTrail Correlated | Feeds application KMS event + matching CloudTrail record | Signals status `CORRELATED` |
| **T13** | CloudTrail Unresolved | Feeds fresh application KMS event (< 15 mins old) | Signals status `UNRESOLVED` |
| **T14** | CloudTrail Missing | Feeds application KMS event > 15 mins old without CloudTrail | Signals status `MISSING_EVIDENCE` |
| **T15** | CloudTrail Conflicting | Feeds matching RequestId with conflicting IAM ARN | Signals status `CONFLICTING_EVIDENCE` |
| **T16** | Metric Cardinality | Validates that metric labels only take values from finite sets | All labels in allowed domains; zero unbounded series |
| **T17** | Sensitive Data Isolation| Inspects emitted signal JSON and metric tags for exam/secret keywords| 100% clean; zero leaks |
| **T18** | Engine Crash Isolation | Injects unhandled exception into detection engine | API continues serving candidate traffic normally |
| **T19** | Multi-Worker Race | Two concurrent workers evaluate overlapping event streams | Idempotency hash prevents duplicate signals |
| **T20** | Zero Autonomous Block | Simulates worst-case attack scenario under all rules | Zero candidate sessions interrupted; zero DB changes |

---

## 20. Prototype vs Production Architecture

| Dimension | Current Prototype / Local Test Environment | Target AWS Production Architecture |
| :--- | :--- | :--- |
| **Correlation Storage** | In-memory `collections.deque` ring buffer | Amazon ElastiCache for Redis 7 (Multi-AZ) |
| **Database** | Local PostgreSQL 16 on `localhost:5432` | Amazon RDS PostgreSQL 16 Multi-AZ + RDS Proxy |
| **KMS Provider** | `MockKMS` (AES-256-GCM + Ed25519) | AWS KMS Customer Managed Keys (CMKs) |
| **CloudTrail Ingestion** | Mock synthetic CloudTrail JSON feed | CloudWatch Logs subscription filter from CloudTrail Lake |
| **Execution Context** | Single FastAPI process / Pytest async test suite | Multiple ECS Fargate tasks across Multi-AZ subnets |
| **Detection Scaling** | In-process background async task | Dedicated ECS worker or asynchronous event consumer |

---

## 21. Threat Model & Abuse Cases Against Detection

| Threat Actor / Vector | Attack Technique | Impact on Detection | B-SEA Architectural Defense |
| :--- | :--- | :--- | :--- |
| **Malicious Candidate** | Rapid API spamming to overload correlation engine | Telemetry flood, memory pressure | Bounded ring buffers; rate limiter drops requests before normalization |
| **Rogue Administrator** | Attempt to delete audit logs to hide unauthorized access | Evidence destruction | PostgreSQL triggers block `DELETE`; hash chain breaks if tampered |
| **Insider Adversary** | Tampering with detection rules to hide malicious activities | Detection blindness | Rules are code-versioned in Git; immutable policy version in signals |
| **Sophisticated Attacker** | Low-and-slow attacks spaced just outside sliding window | Rule evasion | Multi-tier correlation windows (W1=1m, W2=5m, W3=15m, W4=1h) |
| **State Poisoning** | Ingesting malformed event payloads to crash normalizer | Denial of detection | Strict Pydantic validation; schema errors isolated without crashing app |

---

## 22. Operational Risks & Mitigations

1. **Risk: Alert Fatigue from False Positives**:
   - *Mitigation*: Strictly advisory shadow mode; threshold tuning based on real telemetry before any active alerting is wired to pagers.
2. **Risk: Memory Exhaustion from High-Traffic Exam Surges**:
   - *Mitigation*: Hard memory ceiling on in-memory ring buffers (N=50,000 events); automated dropping of oldest non-security events during load spikes.
3. **Risk: Clock Skew Across Multi-Instance ECS Workers**:
   - *Mitigation*: AWS Time Sync Service (NTP) enforced across all Fargate tasks; temporal jitter window (60s) tolerates minor skew.
4. **Risk: Disruption of Candidate Submissions During Peak Load**:
   - *Mitigation*: Detection runs asynchronously in a decoupled task queue or post-commit event hook; zero locks held on business tables.

---

## 23. Deferred Work (Phases 5D, 5E, 5F)

The following components are deferred to future authorized phases:

- **Phase 5D — Security Incident Management & Case Workflow**:
  - `security_incidents` database table and migrations.
  - SecOps triage dashboard, assignment, investigation notes, and status transitions (`OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`).
- **Phase 5E — Policy-Governed Containment (Active Mode Transition)**:
  - Human-in-the-loop and dual-authorized containment actions.
  - Automated session termination for unambiguous high-severity threats.
- **Phase 5F — Enterprise SIEM & SOC Integration**:
  - Direct ingestion into AWS Security Lake, Splunk, or OpenSearch.
  - PagerDuty and incident response escalation webhooks.

---

## 24. Implementation Boundary & Proposed Code Layout

When implementation authorization is granted in the future, changes will be strictly confined to new, dedicated modules.

### Proposed New Files (Phase 3C-5C Implementation Scope)
- `backend/app/modules/detection/` [NEW DIRECTORY]
  - `__init__.py`: Package export.
  - `models.py`: Pydantic/dataclass models (`SecurityEventNormalized`, `SecuritySignal`, `DetectionRuleDefinition`).
  - `normalizer.py`: Event normalization logic mapping AuditLog, Auth, and CBT events.
  - `engine.py`: Deterministic rule evaluation engine.
  - `rules.py`: Canonical rule catalog (Rules A through J).
  - `correlation.py`: In-memory and Redis sliding-window correlation manager.
  - `cloudtrail.py`: Asynchronous CloudTrail/KMS reconciliation helper.
- `backend/tests/security/test_phase3c5c_detection.py` [NEW TEST SUITE]
  - Complete test implementation of matrix T01-T20.

### Strictly Frozen Files (NO MODIFICATIONS PERMITTED)
- `backend/app/core/models.py` (NO schema changes, NO migrations).
- `backend/app/modules/audit/sealer.py` (Cryptographic sealer frozen).
- `backend/app/modules/audit/quarantine.py` (Dual-custody quarantine frozen).
- `backend/app/crypto/kms_interface.py` (KMS crypto core frozen).
- `backend/alembic/` (NO new migrations).

---

## 25. Acceptance Criteria for Phase 3C-5C

Phase 3C-5C can be formally accepted only when:
1. Architecture document `BSEA_PHASE3C_5C_DETECTION_CORRELATION_ARCHITECTURE_REVIEW_REV01.md` is reviewed and approved.
2. Complete test suite (220 baseline tests + 20 Phase 3C-5C tests = 240 tests) passes with 0 failures.
3. Every proposed detection rule is deterministic, explainable, and versioned.
4. Shadow mode is verified with 0 automated blocks or quarantines.
5. Telemetry cardinality is strictly bounded, proving <= 126 additional base time series.
6. Evidence graphs strictly exclude all question plaintext and examination materials.
7. CloudTrail/KMS reconciliation correctly reports all four explicit states.
8. Detection engine failure is proven to have zero impact on high-stakes examination workflows.

---
*End of Architecture Review Document Rev-01. Code changes remain strictly frozen pending user review and authorization.*
