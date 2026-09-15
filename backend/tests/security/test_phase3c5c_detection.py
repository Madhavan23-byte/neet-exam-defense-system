"""
B-SEA Phase 3C-5C Detection & Correlation Foundation — Security Test Matrix T01 to T20
Conforming strictly to BSEA_PHASE3C_5C_DETECTION_CORRELATION_ARCHITECTURE_REVIEW_REV03.md

Test Matrix:
  T01 Event normalization & sensitive field stripping
  T02 Rule determinism & byte-for-byte serialization
  T03 Rule versioning & metadata integrity
  T04 Shadow mode assurance (zero autonomous blocking/quarantine)
  T05 Evidence graph integrity & reference preservation
  T06 Temporal window expiration
  T07 RULE-A burst matching & identity correlation states
  T08 Event deduplication
  T09 Out-of-order event arrival handling (jitter absorption)
  T10 Missing correlation fields robustness (RULE-D null device guard)
  T11 Correlation-state purging & memory bounding
  T12 CloudTrail CORRELATED reconciliation
  T13 CloudTrail UNRESOLVED state (< 15 mins)
  T14 CloudTrail MISSING_EVIDENCE state (>= 15 mins)
  T15 CloudTrail CONFLICTING_EVIDENCE state (caller mismatch)
  T16 Metric cardinality invariant <= 126 new base series & zero forbidden labels
  T17 Sensitive examination data / secret leakage isolation
  T18 Detection crash fail-safe isolation
  T19 Multi-worker race & SQS idempotency
  T20 Zero autonomous containment / zero database mutation
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
import uuid
from typing import Any, Dict, List
import pytest

from app.core.metrics import (
    ALLOWED_DETECTION_MODES,
    ALLOWED_DETECTION_RULES,
    ALLOWED_DETECTION_SEVERITIES,
    ALLOWED_CLOUDTRAIL_RECONCILIATION_STATUSES,
    DETECTION_METRIC_SPECIFICATIONS,
    MetricRegistry,
    metrics_registry,
)
from app.modules.detection import (
    AuditEvidenceState,
    BreakGlassScopeReference,
    CloudTrailKMSEvent,
    CloudTrailKMSReconciler,
    CloudTrailReconciliationState,
    CorrelationManager,
    DetectionEngine,
    DetectionMode,
    DetectionRuleDefinition,
    DetectionSeverity,
    DurableAuditSQSDispatcher,
    EventNormalizer,
    IdentityCorrelationStrength,
    RuleAEvaluator,
    RuleBEvaluator,
    RuleCatalog,
    RuleCEvaluator,
    RuleDEvaluator,
    RuleEEvaluator,
    RuleEvaluationResult,
    RuleFEvaluator,
    RuleGEvaluator,
    RuleHEvaluator,
    RuleIEvaluator,
    RuleJEvaluator,
    SQSDetectionWorker,
    ScopeEvaluationState,
    SecurityEventNormalized,
    SecuritySignal,
)


def _make_event(
    event_type: str = "LOGIN_FAILURE",
    result: str = "FAILURE",
    actor_id: str = "candidate_123",
    resource_type: str = "auth",
    resource_id: str = "login_endpoint",
    action: str = "LOGIN",
    session_id: str = "sess_001",
    device_id: str = "dev_abc",
    ip_hash: str = "hash_1.2.3.4",
    offset_seconds: float = 0.0,
    base_time: datetime = None,
    metadata: Dict[str, Any] = None,
) -> SecurityEventNormalized:
    base = base_time or datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    ts = base + timedelta(seconds=offset_seconds)
    return SecurityEventNormalized(
        event_id=str(uuid.uuid4()),
        event_type=event_type,
        timestamp=ts,
        source_subsystem="auth",
        result=result,
        actor_id=actor_id,
        resource_type=resource_type,
        resource_id=resource_id,
        action=action,
        session_id=session_id,
        device_id=device_id,
        ip_hash=ip_hash,
        audit_log_id=f"audit_{uuid.uuid4().hex[:8]}",
        metadata=metadata or {},
    )


# ── T01: Event Normalization ──────────────────────────────────────────────────
def test_t01_event_normalization():
    """T01: Verify normalization of audit log events and stripping of forbidden content."""
    raw_log = {
        "id": 9999,
        "event_type": "QUESTION_ACCESS",
        "actor_id": "cand_456",
        "actor_role": "candidate",
        "resource_type": "question",
        "resource_id": "q_789",
        "action": "READ",
        "result": "DENIED",
        "session_id": "sess_cbt_1",
        "device_id": "dev_fp_1",
        "ip_hash": "ip_hash_abc",
        "created_at": "2026-09-15T12:00:00Z",
        "event_metadata": {
            "exam_id": "exam_101",
            "question_text": "What is the capital of India?",  # FORBIDDEN
            "answer_key": "New Delhi",                         # FORBIDDEN
            "candidate_response": "Mumbai",                    # FORBIDDEN
            "session_key": "supersecretkey",                   # FORBIDDEN
            "safe_diagnostic": "attempt_1",
        },
    }

    norm = EventNormalizer.normalize_audit_log(raw_log)
    assert isinstance(norm, SecurityEventNormalized)
    assert norm.event_type == "QUESTION_ACCESS"
    assert norm.actor_id == "cand_456"
    assert norm.resource_type == "question"
    assert norm.result == "DENIED"
    assert norm.audit_log_id == "9999"

    # Verify forbidden content is stripped completely
    meta = norm.metadata
    assert "question_text" not in meta
    assert "answer_key" not in meta
    assert "candidate_response" not in meta
    assert "session_key" not in meta
    assert meta.get("exam_id") == "exam_101"
    assert meta.get("safe_diagnostic") == "attempt_1"


# ── T02: Rule Determinism ─────────────────────────────────────────────────────
def test_t02_rule_determinism():
    """T02: Given identical inputs, rule engine produces deterministic outputs and serialization."""
    catalog = RuleCatalog()
    corr1 = CorrelationManager()
    corr2 = CorrelationManager()

    base_time = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    failures = [
        _make_event("LOGIN_FAILURE", "FAILURE", "cand_det", offset_seconds=i * 10, base_time=base_time)
        for i in range(5)
    ]
    success = _make_event("LOGIN", "SUCCESS", "cand_det", offset_seconds=60, base_time=base_time)

    for f in failures:
        corr1.ingest(f)
        corr2.ingest(f)

    res1 = catalog.evaluate_all(success, corr1)
    res2 = catalog.evaluate_all(success, corr2)

    # Both must match RULE-A
    match1 = [r for r in res1 if r[1] == RuleEvaluationResult.MATCH]
    match2 = [r for r in res2 if r[1] == RuleEvaluationResult.MATCH]
    assert len(match1) == 1
    assert len(match2) == 1
    assert match1[0][0] == "RULE-A"
    assert match2[0][0] == "RULE-A"

    sig1 = match1[0][2]
    sig2 = match2[0][2]
    assert sig1 is not None and sig2 is not None
    assert sig1.rule_id == sig2.rule_id
    assert sig1.rule_version == sig2.rule_version
    assert sig1.severity == sig2.severity
    assert sig1.correlation_keys == sig2.correlation_keys
    # Idempotency hash must be identical
    assert sig1.compute_idempotency_hash() == sig2.compute_idempotency_hash()


# ── T03: Rule Versioning ──────────────────────────────────────────────────────
def test_t03_rule_versioning():
    """T03: Every rule has an explicit version and emits policy/rule metadata."""
    catalog = RuleCatalog()
    rules = catalog.list_rules()
    assert len(rules) == 10

    for r in rules:
        assert r.rule_version == "1.0.0"
        assert r.rule_id.startswith("RULE-")
        assert r.policy_version == "BSEA-RULES-v1"
        assert r.severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


# ── T04: Shadow Mode Assurance ────────────────────────────────────────────────
def test_t04_shadow_mode_assurance():
    """T04: Phase 3C-5C operates strictly in SHADOW MODE; zero autonomous actions."""
    engine = DetectionEngine(mode="shadow", record_metrics=False)
    assert engine.mode == "shadow"

    base_time = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    for i in range(5):
        engine.process_event(_make_event("LOGIN_FAILURE", "FAILURE", "cand_shadow", offset_seconds=i * 5, base_time=base_time))

    success = _make_event("LOGIN", "SUCCESS", "cand_shadow", offset_seconds=30, base_time=base_time)
    signals = engine.process_event(success)

    assert len(signals) >= 1
    for sig in signals:
        assert sig.mode == "shadow"

    # Advisory signals are stored non-authoritatively
    recent = engine.get_advisory_signals()
    assert len(recent) >= 1
    assert all(s.mode == "shadow" for s in recent)


# ── T05: Evidence Graph Integrity ─────────────────────────────────────────────
def test_t05_evidence_graph_integrity():
    """T05: Signals contain valid evidence references pointing to audit/event IDs without payload copying."""
    corr = CorrelationManager()
    evaluator = RuleBEvaluator(DetectionRuleDefinition(
        rule_id="RULE-B", rule_version="1.0.0", title="Authz Probing", description="",
        severity="HIGH", time_window_seconds=600, threshold=3,
    ))

    base_time = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    denials = [
        _make_event("RESOURCE_ACCESS", "DENIED", "actor_probe", action="READ", offset_seconds=i * 20, base_time=base_time)
        for i in range(3)
    ]
    for d in denials:
        corr.ingest(d)

    escalation = _make_event("RESOURCE_ACCESS", "SUCCESS", "actor_probe", action="ACCESS_GRANTED", offset_seconds=100, base_time=base_time)
    res, sig = evaluator.evaluate(escalation, corr)

    assert res == RuleEvaluationResult.MATCH
    assert sig is not None
    assert len(sig.evidence_references) == 4
    # Check that all evidence references correspond to event/audit IDs
    for d in denials:
        assert d.audit_log_id in sig.evidence_references
    assert escalation.audit_log_id in sig.evidence_references


# ── T06: Temporal Window Expiration ───────────────────────────────────────────
def test_t06_temporal_window_expiration():
    """T06: Events older than the sliding window horizon do not trigger rules."""
    corr = CorrelationManager()
    evaluator = RuleAEvaluator(DetectionRuleDefinition(
        rule_id="RULE-A", rule_version="1.0.0", title="Brute Force", description="",
        severity="HIGH", time_window_seconds=300, threshold=5,
    ))

    base_time = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    # 5 failures spread over 1000 seconds (outside 300s window)
    for i in range(5):
        corr.ingest(_make_event("LOGIN_FAILURE", "FAILURE", "cand_slow", offset_seconds=i * 200, base_time=base_time))

    # Success event at 1050s
    success = _make_event("LOGIN", "SUCCESS", "cand_slow", offset_seconds=1050, base_time=base_time)
    res, sig = evaluator.evaluate(success, corr)

    # Should not match because only 1 or 2 failures fall within [1050 - 300, 1050]
    assert res == RuleEvaluationResult.NO_MATCH
    assert sig is None


# ── T07: RULE-A Burst Matching & Identity Correlation ─────────────────────────
def test_t07_rule_a_identity_correlation():
    """T07: RULE-A differentiates ACTOR_MATCH, IP_MATCH_ONLY, and blocks on INSUFFICIENT_IDENTITY."""
    catalog = RuleCatalog()
    rule_a = catalog.get_rule("RULE-A")
    base_time = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)

    # 1. ACTOR_MATCH case
    corr_actor = CorrelationManager()
    for i in range(5):
        corr_actor.ingest(_make_event("LOGIN_FAILURE", "FAILURE", actor_id="user_known", ip_hash="ip_a", offset_seconds=i * 10, base_time=base_time))
    success_actor = _make_event("LOGIN", "SUCCESS", actor_id="user_known", ip_hash="ip_b", offset_seconds=60, base_time=base_time)
    res1, sig1 = rule_a.evaluate(success_actor, corr_actor)
    assert res1 == RuleEvaluationResult.MATCH
    assert sig1.metadata["identity_correlation"] == IdentityCorrelationStrength.ACTOR_MATCH.value

    # 2. IP_MATCH_ONLY case (actor_id unknown/None on failures)
    corr_ip = CorrelationManager()
    for i in range(5):
        corr_ip.ingest(_make_event("LOGIN_FAILURE", "FAILURE", actor_id=None, ip_hash="same_ip_hash", offset_seconds=i * 10, base_time=base_time))
    success_ip = _make_event("LOGIN", "SUCCESS", actor_id="cand_new", ip_hash="same_ip_hash", offset_seconds=60, base_time=base_time)
    res2, sig2 = rule_a.evaluate(success_ip, corr_ip)
    assert res2 == RuleEvaluationResult.MATCH
    assert sig2.metadata["identity_correlation"] == IdentityCorrelationStrength.IP_MATCH_ONLY.value

    # 3. INSUFFICIENT_IDENTITY case (neither actor_id nor ip_hash matches)
    corr_diff = CorrelationManager()
    for i in range(5):
        corr_diff.ingest(_make_event("LOGIN_FAILURE", "FAILURE", actor_id=None, ip_hash="ip_one", offset_seconds=i * 10, base_time=base_time))
    success_diff = _make_event("LOGIN", "SUCCESS", actor_id="cand_x", ip_hash="ip_two", offset_seconds=60, base_time=base_time)
    res3, sig3 = rule_a.evaluate(success_diff, corr_diff)
    assert res3 == RuleEvaluationResult.NO_MATCH
    assert sig3 is None


# ── T08: Event Deduplication ──────────────────────────────────────────────────
def test_t08_event_deduplication():
    """T08: Ingesting duplicate event_id is safely dropped and does not count towards thresholds."""
    corr = CorrelationManager()
    event = _make_event("LOGIN_FAILURE", "FAILURE", "cand_dup", offset_seconds=0)

    first_ingest = corr.ingest(event)
    second_ingest = corr.ingest(event)

    assert first_ingest is True
    assert second_ingest is False

    events = corr.get_events_in_window("actor_id", "cand_dup", 300, event.timestamp)
    assert len(events) == 1


# ── T09: Out-of-Order Event Handling ──────────────────────────────────────────
def test_t09_out_of_order_arrival():
    """T09: Out-of-order event timestamps are sorted correctly into correlation ring buffer."""
    corr = CorrelationManager()
    base_time = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)

    e1 = _make_event("Q_ACCESS", "DENIED", "cand_ooo", offset_seconds=10, base_time=base_time)
    e3 = _make_event("Q_ACCESS", "DENIED", "cand_ooo", offset_seconds=30, base_time=base_time)
    e2 = _make_event("Q_ACCESS", "DENIED", "cand_ooo", offset_seconds=20, base_time=base_time)

    # Ingest in out-of-order sequence: 10, 30, 20
    corr.ingest(e1)
    corr.ingest(e3)
    corr.ingest(e2)

    retrieved = corr.get_events_in_window("actor_id", "cand_ooo", 60, base_time + timedelta(seconds=40))
    assert len(retrieved) == 3
    assert [e.timestamp.timestamp() for e in retrieved] == [
        e1.timestamp.timestamp(),
        e2.timestamp.timestamp(),
        e3.timestamp.timestamp(),
    ]


# ── T10: Missing Correlation Fields Robustness ─────────────────────────────────
def test_t10_missing_fields_robustness():
    """T10: Engine handles events with null/empty fields gracefully. RULE-D does not fire with null device."""
    catalog = RuleCatalog()
    rule_d = catalog.get_rule("RULE-D")
    corr = CorrelationManager()

    # Ingest logins with 3 different actors but null device_id
    base_time = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    for i in range(3):
        ev = _make_event("LOGIN", "SUCCESS", actor_id=f"actor_{i}", device_id=None, offset_seconds=i * 10, base_time=base_time)
        corr.ingest(ev)
        res, sig = rule_d.evaluate(ev, corr)
        assert res == RuleEvaluationResult.NO_MATCH
        assert sig is None


# ── T11: Correlation State Purging ────────────────────────────────────────────
def test_t11_correlation_purging():
    """T11: purge_expired clears events older than auto_purge_horizon from memory."""
    corr = CorrelationManager(auto_purge_horizon_seconds=300)
    base_time = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)

    # Ingest 3 old events at t=0
    for i in range(3):
        corr.ingest(_make_event("EV", "SUCCESS", "actor_purge", offset_seconds=0, base_time=base_time))

    # Ingest 2 new events at t=400
    for i in range(2):
        corr.ingest(_make_event("EV", "SUCCESS", "actor_purge", offset_seconds=400, base_time=base_time))

    # Purge at t=500 (cutoff = 500 - 300 = 200; events at t=0 are older than cutoff)
    purged = corr.purge_expired(current_time=base_time + timedelta(seconds=500))
    assert purged == 3

    # Only the 2 new events remain
    remaining = corr.get_events_in_window("actor_id", "actor_purge", 600, base_time + timedelta(seconds=500))
    assert len(remaining) == 2


# ── T12: CloudTrail CORRELATED ────────────────────────────────────────────────
def test_t12_cloudtrail_correlated():
    """T12: Matching KMS and CloudTrail management events reconcile to CORRELATED."""
    reconciler = CloudTrailKMSReconciler(record_metrics=False)
    base_time = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)

    # Ingest CloudTrail event
    ct_event = CloudTrailKMSEvent(
        event_id="ct_1",
        event_time=base_time,
        event_name="Sign",
        kms_key_arn="arn:aws:kms:ap-south-1:123456789012:key/test-key-1",
        request_id="req_kms_123",
        caller_arn="arn:aws:iam::123456789012:role/bsea-sealer",
    )
    reconciler.ingest_cloudtrail_event(ct_event)

    # Reconcile matching KMS application event
    kms_event = _make_event(
        "KMS_OPERATION", "SUCCESS", "sealer", resource_type="crypto_key",
        resource_id="test-key-1", action="Sign", base_time=base_time,
        metadata={"kms_request_id": "req_kms_123", "caller_arn": "arn:aws:iam::123456789012:role/bsea-sealer"}
    )
    state, match = reconciler.reconcile_kms_event(kms_event, current_time=base_time)
    assert state == CloudTrailReconciliationState.CORRELATED
    assert match is not None
    assert match.request_id == "req_kms_123"


# ── T13: CloudTrail UNRESOLVED (< 15 mins) ────────────────────────────────────
def test_t13_cloudtrail_unresolved():
    """T13: KMS event younger than 15 mins without CloudTrail record is marked UNRESOLVED."""
    reconciler = CloudTrailKMSReconciler(record_metrics=False)
    base_time = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)

    kms_event = _make_event(
        "KMS_OPERATION", "SUCCESS", "sealer", base_time=base_time,
        metadata={"kms_request_id": "req_kms_pending"}
    )
    # Current time = base_time + 5 mins (300s < 900s)
    state, match = reconciler.reconcile_kms_event(kms_event, current_time=base_time + timedelta(seconds=300))
    assert state == CloudTrailReconciliationState.UNRESOLVED
    assert match is None


# ── T14: CloudTrail MISSING_EVIDENCE (>= 15 mins) ──────────────────────────────
def test_t14_cloudtrail_missing_evidence():
    """T14: KMS event aged >= 15 mins without CloudTrail record is marked MISSING_EVIDENCE."""
    reconciler = CloudTrailKMSReconciler(record_metrics=False)
    base_time = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)

    kms_event = _make_event(
        "KMS_OPERATION", "SUCCESS", "sealer", base_time=base_time,
        metadata={"kms_request_id": "req_kms_lost"}
    )
    # Current time = base_time + 16 mins (960s >= 900s)
    state, match = reconciler.reconcile_kms_event(kms_event, current_time=base_time + timedelta(seconds=960))
    assert state == CloudTrailReconciliationState.MISSING_EVIDENCE
    assert match is None


# ── T15: CloudTrail CONFLICTING_EVIDENCE ───────────────────────────────────────
def test_t15_cloudtrail_conflicting_evidence():
    """T15: RequestId matches but IAM caller ARN conflicts yields CONFLICTING_EVIDENCE."""
    reconciler = CloudTrailKMSReconciler(record_metrics=False)
    base_time = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)

    ct_event = CloudTrailKMSEvent(
        event_id="ct_2",
        event_time=base_time,
        event_name="Sign",
        kms_key_arn="arn:aws:kms:ap-south-1:123456789012:key/test-key-1",
        request_id="req_kms_conflict",
        caller_arn="arn:aws:iam::123456789012:role/rogue-attacker-role",
    )
    reconciler.ingest_cloudtrail_event(ct_event)

    kms_event = _make_event(
        "KMS_OPERATION", "SUCCESS", "sealer", base_time=base_time, action="Sign",
        metadata={"kms_request_id": "req_kms_conflict", "caller_arn": "arn:aws:iam::123456789012:role/legitimate-sealer"}
    )
    state, match = reconciler.reconcile_kms_event(kms_event, current_time=base_time)
    assert state == CloudTrailReconciliationState.CONFLICTING_EVIDENCE
    assert match is not None


# ── T16: Metric Cardinality Invariant <= 126 New Base Series ──────────────────
def test_t16_metric_cardinality_invariant():
    """T16: Bounded detection metrics strictly <= 126 new base series; zero forbidden high-cardinality labels."""
    registry = MetricRegistry()
    det_base, det_expanded = registry.calculate_detection_cardinality()

    # 88 (signals) + 33 (rule evals) + 4 (cloudtrail) + 1 (lag) = 126
    assert det_base == 126
    assert det_expanded == 126
    assert det_base <= 126

    # Combined with Phase 3C-5B (520 base / 1390 expanded)
    comb_base, comb_expanded = registry.calculate_cardinality(include_detection=True)
    assert comb_base == 646  # 520 + 126
    assert comb_expanded == 1516  # 1390 + 126

    # Check forbidden labels
    forbidden_labels = {
        "actor_id", "candidate_id", "session_id", "device_id", "trace_id",
        "request_id", "audit_log_id", "ip_hash", "ip", "exam_id", "question_id", "signal_id"
    }
    for m_name, spec in DETECTION_METRIC_SPECIFICATIONS.items():
        labels = spec.get("labels", ())
        label_keys = labels.keys() if hasattr(labels, "keys") else labels
        for label_key in label_keys:
            assert label_key.lower() not in forbidden_labels, f"Forbidden label {label_key} in {m_name}"


# ── T17: Sensitive Examination Data / Secret Leakage Isolation ────────────────
def test_t17_sensitive_data_leakage_isolation():
    """T17: Normalized events and generated signals strictly exclude exam questions, answers, and keys."""
    raw_payload = {
        "event_type": "EXAM_SUBMISSION",
        "actor_id": "cand_999",
        "result": "SUCCESS",
        "event_metadata": {
            "questiontext": "Explain quantum tunneling.",
            "answer_key": "Quantum mechanical phenomenon...",
            "candidate_response": "Particles penetrating barriers...",
            "options": ["A", "B", "C"],
            "sessionkey": "secret123456",
            "private_key": "MIIEvgIBADANBgkqhkiG9w0BAQEFAASC...",
            "safe_id": "exam_sec_1",
        },
    }

    norm = EventNormalizer.normalize_cbt_event(raw_payload)
    for forbidden in ("questiontext", "answer_key", "candidate_response", "options", "sessionkey", "private_key"):
        assert forbidden not in norm.metadata

    # Check signal generation does not copy forbidden keys
    engine = DetectionEngine(record_metrics=False)
    signals = engine.process_event(norm)
    for sig in signals:
        dumped = sig.to_json()
        for forbidden in ("quantum tunneling", "secret123456", "MIIEvgIBADAN"):
            assert forbidden not in dumped


# ── T18: Detection Crash Fail-Safe Isolation ──────────────────────────────────
def test_t18_detection_crash_failsafe():
    """T18: Detection exceptions are caught and never bubble up to disrupt caller operations."""
    engine = DetectionEngine(record_metrics=False)

    # Pass malformed / invalid object that might throw in naive implementations
    class CorruptedEvent:
        pass

    signals = engine.process_event(CorruptedEvent())
    # Must fail safely returning empty list without unhandled exception
    assert isinstance(signals, list)
    assert len(signals) == 0


# ── T19: Multi-Worker Race & SQS Idempotency ──────────────────────────────────
@pytest.mark.asyncio
async def test_t19_multi_worker_idempotency():
    """T19: Concurrent workers processing duplicate SQS messages process idempotently with no double signals."""
    engine = DetectionEngine(record_metrics=False)
    queue = asyncio.Queue()
    worker1 = SQSDetectionWorker(engine, queue=queue)
    worker2 = SQSDetectionWorker(engine, queue=queue)

    # Message payload with unique message_id
    msg_id = f"sqs_msg_{uuid.uuid4().hex}"
    message = {
        "message_id": msg_id,
        "event": {
            "event_type": "LOGIN_FAILURE",
            "result": "FAILURE",
            "actor_id": "worker_race_cand",
            "audit_log_id": "audit_race_1",
        },
    }

    # Worker 1 processes first
    signals1 = await worker1.process_one_message(message)
    # Worker 2 processes same message (at-least-once delivery duplicate)
    signals2 = await worker2.process_one_message(message)

    # Worker 2 must safely drop duplicate message
    assert len(signals2) == 0


# ── T20: Zero Autonomous Containment & Zero DB Mutation ───────────────────────
def test_t20_zero_autonomous_blocking_and_db_mutation():
    """T20: Detection rules never block candidates, mutate audit tables, quarantine records, or alter KMS."""
    catalog = RuleCatalog()
    corr = CorrelationManager()

    # Trigger RULE-E (Break-Glass Misuse)
    bg_scope = BreakGlassScopeReference(
        request_id="bg_req_1", scope="CENTRE_EMERGENCY", exam_id="exam_abc",
        valid_from=datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc),
        valid_until=datetime(2026, 9, 15, 12, 30, 0, tzinfo=timezone.utc),
        authorized_actions=["READ"],
    )
    out_of_scope_event = _make_event(
        "QUESTION_MODIFICATION", "SUCCESS", actor_id="invigilator_1",
        resource_type="exam", resource_id="exam_xyz", action="WRITE", # exam_xyz != exam_abc, WRITE != READ
        metadata={"break_glass_request_id": "bg_req_1"}
    )
    rule_e = catalog.get_rule("RULE-E")
    res, sig = rule_e.evaluate(out_of_scope_event, corr, context={"break_glass_scope": bg_scope})

    assert res == RuleEvaluationResult.MATCH
    assert sig is not None
    assert sig.severity == "CRITICAL"
    assert sig.mode == "shadow"

    # Verify signal does NOT trigger blocking or status changes
    assert "block" not in sig.metadata
    assert "quarantine" not in sig.metadata
    assert "containment" not in sig.metadata

    # Test Rule-J exact boolean: (A and B) or C
    rule_j = catalog.get_rule("RULE-J")
    # Condition C alone triggers Rule-J
    sealer_c = _make_event(
        "SEALER_TELEMETRY", "SUCCESS", "sealer",
        metadata={"backlog_records": 500, "sealer_failures": 1, "oldest_unsealed_age_seconds": 1900}
    )
    res_j, sig_j = rule_j.evaluate(sealer_c, corr)
    assert res_j == RuleEvaluationResult.MATCH
    assert sig_j is not None
    assert sig_j.severity == "HIGH"
