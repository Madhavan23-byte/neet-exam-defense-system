"""
B-SEA Phase 3C-5C Detection & Correlation Foundation — Deterministic Rule Catalog
Conforming strictly to BSEA_PHASE3C_5C_DETECTION_CORRELATION_ARCHITECTURE_REVIEW_REV03.md

Implements deterministic, versioned Rules A through J:
  - RULE-A: Brute-Force Authentication with Success (300s window)
  - RULE-B: Authz Probing with Escalation (600s window)
  - RULE-C: Question Access Denial Flood (60s window)
  - RULE-D: Multi-Account Device Hopping (900s window)
  - RULE-E: Break-Glass Scope Misuse (1800s window)
  - RULE-F: Break-Glass Audit Anomaly (Five-state lifecycle, triggers on CONFIRMED_MISSING)
  - RULE-G: KMS Cryptographic Failure Burst (300s window)
  - RULE-H: Audit Tampering Correlation (3600s window, Verifier FAIL + ACCESS_DENIED)
  - RULE-I: Rate-Limit Probing Sequence (600s window)
  - RULE-J: Sealer Degradation & Backlog (Exact boolean: (A and B) or C)

All evaluations are deterministic, reproducible, and advisory only.
Detection signals NEVER block candidates, quarantine records, or mutate system state.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import uuid

from app.modules.detection.models import (
    AuditEvidenceState,
    BreakGlassScopeReference,
    DetectionRuleDefinition,
    DetectionSeverity,
    IdentityCorrelationStrength,
    RuleEvaluationResult,
    ScopeEvaluationState,
    SecurityEventNormalized,
    SecuritySignal,
)
from app.modules.detection.correlation import CorrelationManager


class BaseRuleEvaluator:
    """Base contract for deterministic detection rules."""

    def __init__(self, definition: DetectionRuleDefinition) -> None:
        self.definition = definition

    @property
    def rule_id(self) -> str:
        return self.definition.rule_id

    @property
    def rule_version(self) -> str:
        return self.definition.rule_version

    def evaluate(
        self,
        event: SecurityEventNormalized,
        correlation_mgr: CorrelationManager,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[RuleEvaluationResult, Optional[SecuritySignal]]:
        raise NotImplementedError


class RuleAEvaluator(BaseRuleEvaluator):
    """
    RULE-A: Brute-Force Authentication with Success
    Window: 300 seconds
    Trigger: >= 5 LOGIN_FAILURE events followed by 1 successful LOGIN.

    Identity correlation:
      - ACTOR_MATCH: Both failure and success events have matching, non-null actor_id.
      - IP_MATCH_ONLY: actor_id unavailable, but matching ip_hash exists.
      - INSUFFICIENT_IDENTITY: Neither actor_id nor ip_hash provides linkage.
      Rule must NOT fire on INSUFFICIENT_IDENTITY.
    """

    def evaluate(
        self,
        event: SecurityEventNormalized,
        correlation_mgr: CorrelationManager,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[RuleEvaluationResult, Optional[SecuritySignal]]:
        # Only evaluate upon successful LOGIN
        if event.event_type != "LOGIN" or event.result != "SUCCESS":
            return RuleEvaluationResult.NO_MATCH, None

        window_seconds = self.definition.time_window_seconds
        ref_time = event.timestamp

        # 1. Check for correlation candidates
        failures: List[SecurityEventNormalized] = []
        correlation_strength = IdentityCorrelationStrength.INSUFFICIENT_IDENTITY
        matched_corr_keys: Dict[str, str] = {}

        # First attempt: Actor ID correlation (Strong)
        if event.actor_id and event.actor_id.lower() not in ("anonymous", "none", "unknown"):
            actor_events = correlation_mgr.get_events_in_window(
                "actor_id", event.actor_id, window_seconds, ref_time
            )
            actor_failures = [
                e for e in actor_events
                if e.event_type in ("LOGIN_FAILURE", "AUTH_FAILED") and e.timestamp < event.timestamp
            ]
            if len(actor_failures) >= self.definition.threshold:
                failures = actor_failures
                correlation_strength = IdentityCorrelationStrength.ACTOR_MATCH
                matched_corr_keys = {"actor_id": event.actor_id}

        # Second attempt: IP match only if actor correlation was not established
        if not failures and event.ip_hash:
            ip_events = correlation_mgr.get_events_in_window(
                "ip_hash", event.ip_hash, window_seconds, ref_time
            )
            ip_failures = [
                e for e in ip_events
                if e.event_type in ("LOGIN_FAILURE", "AUTH_FAILED") and e.timestamp < event.timestamp
            ]
            if len(ip_failures) >= self.definition.threshold:
                failures = ip_failures
                correlation_strength = IdentityCorrelationStrength.IP_MATCH_ONLY
                matched_corr_keys = {"ip_hash": event.ip_hash}

        # INSUFFICIENT_IDENTITY check: Rule MUST NOT fire
        if correlation_strength == IdentityCorrelationStrength.INSUFFICIENT_IDENTITY or len(failures) < self.definition.threshold:
            return RuleEvaluationResult.NO_MATCH, None

        # Build advisory signal
        evidence = [f.audit_log_id or f.event_id for f in failures]
        evidence.append(event.audit_log_id or event.event_id)

        signal = SecuritySignal(
            signal_id=str(uuid.uuid4()),
            rule_id=self.rule_id,
            rule_version=self.rule_version,
            detected_at=event.timestamp,
            severity=self.definition.severity,
            confidence=0.95 if correlation_strength == IdentityCorrelationStrength.ACTOR_MATCH else 0.70,
            mode="shadow",
            correlation_keys=matched_corr_keys,
            evidence_references=evidence,
            event_count=len(failures) + 1,
            window_seconds=window_seconds,
            explanation=(
                f"Brute-force authentication pattern detected: {len(failures)} failures "
                f"followed by successful login within {window_seconds}s. "
                f"Identity correlation: {correlation_strength.value}."
            ),
            metadata={
                "identity_correlation": correlation_strength.value,
                "failure_count": len(failures),
                "success_event_id": event.event_id,
            },
        )
        return RuleEvaluationResult.MATCH, signal


class RuleBEvaluator(BaseRuleEvaluator):
    """
    RULE-B: Authz Probing with Escalation
    Window: 600 seconds
    Trigger: >= 3 ACCESS_DENIED events on sensitive resources followed by ACCESS_GRANTED.
    Requires valid actor identity (non-null, non-anonymous).
    """

    def evaluate(
        self,
        event: SecurityEventNormalized,
        correlation_mgr: CorrelationManager,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[RuleEvaluationResult, Optional[SecuritySignal]]:
        # Trigger condition: ACCESS_GRANTED on sensitive resource
        if event.result != "SUCCESS" or event.action not in ("READ", "WRITE", "EXECUTE", "ACCESS_GRANTED"):
            return RuleEvaluationResult.NO_MATCH, None

        # Actor identity requirement: Must be non-null and not anonymous
        if not event.actor_id or event.actor_id.lower() in ("anonymous", "none", "unknown"):
            return RuleEvaluationResult.NO_MATCH, None

        window_seconds = self.definition.time_window_seconds
        actor_events = correlation_mgr.get_events_in_window(
            "actor_id", event.actor_id, window_seconds, event.timestamp
        )

        denials = [
            e for e in actor_events
            if e.result in ("DENIED", "FAILURE", "BLOCKED") and e.timestamp < event.timestamp
        ]

        if len(denials) < self.definition.threshold:
            return RuleEvaluationResult.NO_MATCH, None

        evidence = [d.audit_log_id or d.event_id for d in denials]
        evidence.append(event.audit_log_id or event.event_id)

        signal = SecuritySignal(
            signal_id=str(uuid.uuid4()),
            rule_id=self.rule_id,
            rule_version=self.rule_version,
            detected_at=event.timestamp,
            severity=self.definition.severity,
            confidence=0.90,
            mode="shadow",
            correlation_keys={"actor_id": event.actor_id},
            evidence_references=evidence,
            event_count=len(denials) + 1,
            window_seconds=window_seconds,
            explanation=(
                f"Authorization probing detected: {len(denials)} access denials "
                f"followed by granted access for actor {event.actor_id} within {window_seconds}s."
            ),
            metadata={
                "actor_id": event.actor_id,
                "denial_count": len(denials),
                "escalated_resource": event.resource_id,
            },
        )
        return RuleEvaluationResult.MATCH, signal


class RuleCEvaluator(BaseRuleEvaluator):
    """
    RULE-C: Question Access Denial Flood
    Window: 60 seconds
    Trigger: >= 10 question access denials from the same session/device correlation context.
    No plaintext question data in signals.
    """

    def evaluate(
        self,
        event: SecurityEventNormalized,
        correlation_mgr: CorrelationManager,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[RuleEvaluationResult, Optional[SecuritySignal]]:
        if event.result not in ("DENIED", "FAILURE", "BLOCKED") or event.resource_type != "question":
            return RuleEvaluationResult.NO_MATCH, None

        window_seconds = self.definition.time_window_seconds
        key_type = "session_id" if event.session_id else ("device_id" if event.device_id else None)
        key_val = event.session_id or event.device_id

        if not key_type or not key_val:
            return RuleEvaluationResult.NO_MATCH, None

        events = correlation_mgr.get_events_in_window(
            key_type, key_val, window_seconds, event.timestamp
        )
        denials = [
            e for e in events
            if e.result in ("DENIED", "FAILURE", "BLOCKED") and e.resource_type == "question"
        ]

        if len(denials) < self.definition.threshold:
            return RuleEvaluationResult.NO_MATCH, None

        evidence = [d.audit_log_id or d.event_id for d in denials]

        signal = SecuritySignal(
            signal_id=str(uuid.uuid4()),
            rule_id=self.rule_id,
            rule_version=self.rule_version,
            detected_at=event.timestamp,
            severity=self.definition.severity,
            confidence=0.85,
            mode="shadow",
            correlation_keys={key_type: key_val},
            evidence_references=evidence,
            event_count=len(denials),
            window_seconds=window_seconds,
            explanation=(
                f"Question access denial flood detected: {len(denials)} denials "
                f"within {window_seconds}s from {key_type}={key_val}."
            ),
            metadata={
                "context_dimension": key_type,
                "denial_count": len(denials),
                "exam_id": event.metadata.get("exam_id"),
            },
        )
        return RuleEvaluationResult.MATCH, signal


class RuleDEvaluator(BaseRuleEvaluator):
    """
    RULE-D: Multi-Account Device Hopping
    Window: 900 seconds
    Trigger: >= 3 distinct actor identities associated with the same valid device fingerprint.
    Requires valid non-null device correlation.
    """

    def evaluate(
        self,
        event: SecurityEventNormalized,
        correlation_mgr: CorrelationManager,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[RuleEvaluationResult, Optional[SecuritySignal]]:
        # Requires valid non-null device_id and actor_id
        if not event.device_id or not event.actor_id:
            return RuleEvaluationResult.NO_MATCH, None

        window_seconds = self.definition.time_window_seconds
        device_events = correlation_mgr.get_events_in_window(
            "device_id", event.device_id, window_seconds, event.timestamp
        )

        # Collect distinct actor IDs on this device
        actor_to_events: Dict[str, List[SecurityEventNormalized]] = {}
        for e in device_events:
            if e.actor_id and e.actor_id.lower() not in ("anonymous", "none", "unknown"):
                actor_to_events.setdefault(e.actor_id, []).append(e)

        distinct_actors = list(actor_to_events.keys())
        if len(distinct_actors) < self.definition.threshold:
            return RuleEvaluationResult.NO_MATCH, None

        evidence = [
            ev.audit_log_id or ev.event_id
            for act_events in actor_to_events.values()
            for ev in act_events
        ]

        signal = SecuritySignal(
            signal_id=str(uuid.uuid4()),
            rule_id=self.rule_id,
            rule_version=self.rule_version,
            detected_at=event.timestamp,
            severity=self.definition.severity,
            confidence=0.88,
            mode="shadow",
            correlation_keys={"device_id": event.device_id},
            evidence_references=evidence,
            event_count=len(evidence),
            window_seconds=window_seconds,
            explanation=(
                f"Multi-account device hopping: {len(distinct_actors)} distinct actors "
                f"used device {event.device_id} within {window_seconds}s."
            ),
            metadata={
                "device_id": event.device_id,
                "distinct_actor_count": len(distinct_actors),
            },
        )
        return RuleEvaluationResult.MATCH, signal


class RuleEEvaluator(BaseRuleEvaluator):
    """
    RULE-E: Break-Glass Scope Misuse
    Window: 1800 seconds
    Trigger: BREAK_GLASS_ACTIVATED followed by access evaluated as OUT_OF_SCOPE.
    Scope evaluation states: MATCH, OUT_OF_SCOPE, UNRESOLVED.
    Never inspect plaintext question content.
    """

    def evaluate(
        self,
        event: SecurityEventNormalized,
        correlation_mgr: CorrelationManager,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[RuleEvaluationResult, Optional[SecuritySignal]]:
        # Requires break-glass session context or break-glass actor
        if not event.metadata.get("break_glass_request_id") and not event.session_id:
            return RuleEvaluationResult.NO_MATCH, None

        bg_scope: Optional[BreakGlassScopeReference] = None
        if context and "break_glass_scope" in context:
            bg_scope = context["break_glass_scope"]
        elif event.metadata.get("scope_spec"):
            raw = event.metadata["scope_spec"]
            bg_scope = BreakGlassScopeReference(
                request_id=event.metadata.get("break_glass_request_id", "unknown"),
                scope=raw.get("scope", "EXAM_SPECIFIC"),
                exam_id=raw.get("exam_id", ""),
                valid_from=event.timestamp,
                valid_until=datetime.fromisoformat(raw["valid_until"]) if "valid_until" in raw else event.timestamp,
                blueprint_id=raw.get("blueprint_id"),
                authorized_actions=raw.get("authorized_actions", []),
            )

        if not bg_scope:
            return RuleEvaluationResult.NO_MATCH, None

        # Evaluate scope
        scope_state = self._evaluate_scope(event, bg_scope)
        if scope_state != ScopeEvaluationState.OUT_OF_SCOPE:
            return RuleEvaluationResult.NO_MATCH, None

        evidence = [event.audit_log_id or event.event_id]

        signal = SecuritySignal(
            signal_id=str(uuid.uuid4()),
            rule_id=self.rule_id,
            rule_version=self.rule_version,
            detected_at=event.timestamp,
            severity=self.definition.severity,
            confidence=0.92,
            mode="shadow",
            correlation_keys={"actor_id": event.actor_id or "unknown"},
            evidence_references=evidence,
            event_count=1,
            window_seconds=self.definition.time_window_seconds,
            explanation=(
                f"Break-glass scope misuse detected: Access to resource {event.resource_id} "
                f"evaluated as OUT_OF_SCOPE against BreakGlassRequest {bg_scope.request_id}."
            ),
            metadata={
                "scope_evaluation_state": scope_state.value,
                "break_glass_request_id": bg_scope.request_id,
                "authorized_scope": bg_scope.scope,
                "attempted_resource": event.resource_id,
                "attempted_action": event.action,
            },
        )
        return RuleEvaluationResult.MATCH, signal

    def _evaluate_scope(
        self, event: SecurityEventNormalized, bg_scope: BreakGlassScopeReference
    ) -> ScopeEvaluationState:
        """Compares event attributes against authorized Break-Glass scope reference."""
        # 1. Temporal boundary check
        if event.timestamp > bg_scope.valid_until:
            return ScopeEvaluationState.OUT_OF_SCOPE

        # 2. Exam ID boundary check
        event_exam = event.metadata.get("exam_id") or (event.resource_id if event.resource_type == "exam" else None)
        if bg_scope.exam_id and event_exam and str(event_exam) != str(bg_scope.exam_id):
            return ScopeEvaluationState.OUT_OF_SCOPE

        # 3. Authorized action check
        if bg_scope.authorized_actions and event.action:
            if event.action not in bg_scope.authorized_actions:
                return ScopeEvaluationState.OUT_OF_SCOPE

        # 4. If resource cannot be verified against scope
        if not event_exam and event.resource_type not in ("exam", "blueprint", "question"):
            return ScopeEvaluationState.UNRESOLVED

        return ScopeEvaluationState.MATCH


class RuleFEvaluator(BaseRuleEvaluator):
    """
    RULE-F: Break-Glass Audit Anomaly
    Five-state evidence lifecycle: EXPECTED, RECEIVED, DELAYED, UNRESOLVED, CONFIRMED_MISSING.
    Only CONFIRMED_MISSING triggers RULE-F.
    Timing:
      - <= 60s: DELAYED
      - > 60s and <= 300s: UNRESOLVED
      - > 300s or explicit audit insertion failure: CONFIRMED_MISSING
    """

    def evaluate(
        self,
        event: SecurityEventNormalized,
        correlation_mgr: CorrelationManager,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[RuleEvaluationResult, Optional[SecuritySignal]]:
        if event.event_type != "BREAK_GLASS_SESSION_CHECK" and not event.metadata.get("break_glass_audit_check"):
            return RuleEvaluationResult.NO_MATCH, None

        elapsed_seconds = float(event.metadata.get("elapsed_seconds", 0.0))
        explicit_failure = bool(event.metadata.get("audit_insertion_failure", False))
        audit_received = bool(event.metadata.get("audit_received", False))

        # Lifecycle state evaluation
        if audit_received:
            state = AuditEvidenceState.RECEIVED
        elif explicit_failure or elapsed_seconds > 300.0:
            state = AuditEvidenceState.CONFIRMED_MISSING
        elif elapsed_seconds > 60.0:
            state = AuditEvidenceState.UNRESOLVED
        else:
            state = AuditEvidenceState.DELAYED

        # Only CONFIRMED_MISSING may trigger RULE-F
        if state != AuditEvidenceState.CONFIRMED_MISSING:
            return RuleEvaluationResult.NO_MATCH, None

        evidence = [event.audit_log_id or event.event_id]

        signal = SecuritySignal(
            signal_id=str(uuid.uuid4()),
            rule_id=self.rule_id,
            rule_version=self.rule_version,
            detected_at=event.timestamp,
            severity=self.definition.severity,
            confidence=0.99 if explicit_failure else 0.85,
            mode="shadow",
            correlation_keys={"actor_id": event.actor_id or "system"},
            evidence_references=evidence,
            event_count=1,
            window_seconds=self.definition.time_window_seconds,
            explanation=(
                f"Break-glass audit anomaly detected: Expected audit evidence state is "
                f"CONFIRMED_MISSING (elapsed: {elapsed_seconds}s, explicit failure: {explicit_failure})."
            ),
            metadata={
                "evidence_lifecycle_state": state.value,
                "elapsed_seconds": elapsed_seconds,
                "explicit_failure": explicit_failure,
            },
        )
        return RuleEvaluationResult.MATCH, signal


class RuleGEvaluator(BaseRuleEvaluator):
    """
    RULE-G: KMS Cryptographic Failure Burst
    Window: 300 seconds
    Trigger: >= 3 relevant KMS security failures.
    Does not weaken KMS controls or modify KMS state.
    """

    def evaluate(
        self,
        event: SecurityEventNormalized,
        correlation_mgr: CorrelationManager,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[RuleEvaluationResult, Optional[SecuritySignal]]:
        is_kms_failure = (
            event.source_subsystem == "kms" or
            "kms" in event.event_type.lower() or
            event.event_type in ("KMS_SECURITY_EVENT_FAILURE", "KMS_OPERATION_FAILED")
        ) and event.result in ("FAILURE", "DENIED", "ERROR")

        if not is_kms_failure:
            return RuleEvaluationResult.NO_MATCH, None

        window_seconds = self.definition.time_window_seconds
        key_id = event.resource_id or "global_kms"
        kms_events = correlation_mgr.get_events_in_window(
            "resource_id", key_id, window_seconds, event.timestamp
        )

        failures = [
            e for e in kms_events
            if e.result in ("FAILURE", "DENIED", "ERROR") and (
                e.source_subsystem == "kms" or "kms" in e.event_type.lower() or
                e.event_type in ("KMS_SECURITY_EVENT_FAILURE", "KMS_OPERATION_FAILED")
            )
        ]

        if len(failures) < self.definition.threshold:
            return RuleEvaluationResult.NO_MATCH, None

        evidence = [f.audit_log_id or f.event_id for f in failures]

        signal = SecuritySignal(
            signal_id=str(uuid.uuid4()),
            rule_id=self.rule_id,
            rule_version=self.rule_version,
            detected_at=event.timestamp,
            severity=self.definition.severity,
            confidence=0.90,
            mode="shadow",
            correlation_keys={"resource_id": key_id},
            evidence_references=evidence,
            event_count=len(failures),
            window_seconds=window_seconds,
            explanation=(
                f"KMS cryptographic failure burst: {len(failures)} security failures "
                f"observed for key/subsystem {key_id} within {window_seconds}s."
            ),
            metadata={
                "kms_key_id": key_id,
                "failure_count": len(failures),
            },
        )
        return RuleEvaluationResult.MATCH, signal


class RuleHEvaluator(BaseRuleEvaluator):
    """
    RULE-H: Audit Tampering Correlation
    Window: 3600 seconds
    Trigger: Deep verifier FAIL correlated with relevant recent ACCESS_DENIED evidence.
    Verifier UNRESOLVED remains unresolved and must NOT fire.
    Detection must never modify verifier/audit state.
    """

    def evaluate(
        self,
        event: SecurityEventNormalized,
        correlation_mgr: CorrelationManager,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[RuleEvaluationResult, Optional[SecuritySignal]]:
        # Verifier result check: Must be explicit verifier failure
        if event.event_type != "AUDIT_VERIFICATION" or event.result != "FAILURE":
            return RuleEvaluationResult.NO_MATCH, None

        window_seconds = self.definition.time_window_seconds
        all_window_events = correlation_mgr.get_events_in_window(
            "actor_id", event.actor_id or "admin", window_seconds, event.timestamp
        )
        if not all_window_events and event.session_id:
            all_window_events = correlation_mgr.get_events_in_window(
                "session_id", event.session_id, window_seconds, event.timestamp
            )

        denials = [
            e for e in all_window_events
            if e.result in ("DENIED", "FAILURE", "BLOCKED") and e.event_type != "AUDIT_VERIFICATION"
        ]

        if not denials:
            return RuleEvaluationResult.NO_MATCH, None

        evidence = [d.audit_log_id or d.event_id for d in denials]
        evidence.append(event.audit_log_id or event.event_id)

        signal = SecuritySignal(
            signal_id=str(uuid.uuid4()),
            rule_id=self.rule_id,
            rule_version=self.rule_version,
            detected_at=event.timestamp,
            severity=self.definition.severity,
            confidence=0.96,
            mode="shadow",
            correlation_keys={"actor_id": event.actor_id or "system"},
            evidence_references=evidence,
            event_count=len(evidence),
            window_seconds=window_seconds,
            explanation=(
                f"Audit tampering correlation: Deep verifier FAIL correlated with "
                f"{len(denials)} prior access denial events within {window_seconds}s."
            ),
            metadata={
                "verifier_result": "FAIL",
                "denial_count": len(denials),
            },
        )
        return RuleEvaluationResult.MATCH, signal


class RuleIEvaluator(BaseRuleEvaluator):
    """
    RULE-I: Rate-Limit Probing Sequence
    Window: 600 seconds
    Trigger: >= 5 rate-limit rejections followed by sensitive resource access.
    Correlation may use ip_hash or actor_id (neither may become metric dimensions).
    """

    def evaluate(
        self,
        event: SecurityEventNormalized,
        correlation_mgr: CorrelationManager,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[RuleEvaluationResult, Optional[SecuritySignal]]:
        # Trigger on sensitive resource access
        if event.result != "SUCCESS" or event.resource_type not in ("exam", "question", "admin", "auth", "keys"):
            return RuleEvaluationResult.NO_MATCH, None

        window_seconds = self.definition.time_window_seconds
        key_type = "ip_hash" if event.ip_hash else ("actor_id" if event.actor_id else None)
        key_val = event.ip_hash or event.actor_id

        if not key_type or not key_val:
            return RuleEvaluationResult.NO_MATCH, None

        events = correlation_mgr.get_events_in_window(
            key_type, key_val, window_seconds, event.timestamp
        )
        rl_rejections = [
            e for e in events
            if e.event_type in ("RATE_LIMIT_EXCEEDED", "RATE_LIMITED") and e.timestamp < event.timestamp
        ]

        if len(rl_rejections) < self.definition.threshold:
            return RuleEvaluationResult.NO_MATCH, None

        evidence = [r.audit_log_id or r.event_id for r in rl_rejections]
        evidence.append(event.audit_log_id or event.event_id)

        signal = SecuritySignal(
            signal_id=str(uuid.uuid4()),
            rule_id=self.rule_id,
            rule_version=self.rule_version,
            detected_at=event.timestamp,
            severity=self.definition.severity,
            confidence=0.82,
            mode="shadow",
            correlation_keys={key_type: key_val},
            evidence_references=evidence,
            event_count=len(rl_rejections) + 1,
            window_seconds=window_seconds,
            explanation=(
                f"Rate-limit probing sequence: {len(rl_rejections)} rate-limit rejections "
                f"followed by access to {event.resource_type}:{event.resource_id} within {window_seconds}s."
            ),
            metadata={
                "dimension": key_type,
                "rejection_count": len(rl_rejections),
            },
        )
        return RuleEvaluationResult.MATCH, signal


class RuleJEvaluator(BaseRuleEvaluator):
    """
    RULE-J: Sealer Degradation & Backlog
    Exact Boolean expression:
      RULE-J = (A and B) or C
    where:
      A = backlog_records > 1000
      B = (sealer_failures >= 3) or (sealer_lock_timeouts >= 5)
      C = oldest_unsealed_age_seconds > 1800
    Do not call backlog_records 'lag'.
    """

    def evaluate(
        self,
        event: SecurityEventNormalized,
        correlation_mgr: CorrelationManager,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[RuleEvaluationResult, Optional[SecuritySignal]]:
        if event.event_type != "SEALER_TELEMETRY" and not event.metadata.get("sealer_telemetry"):
            return RuleEvaluationResult.NO_MATCH, None

        meta = event.metadata
        backlog_records = int(meta.get("backlog_records", 0))
        sealer_failures = int(meta.get("sealer_failures", 0))
        sealer_lock_timeouts = int(meta.get("sealer_lock_timeouts", 0))
        oldest_unsealed_age_seconds = float(meta.get("oldest_unsealed_age_seconds", 0.0))

        # Evaluate exact boolean expression
        cond_a = backlog_records > 1000
        cond_b = (sealer_failures >= 3) or (sealer_lock_timeouts >= 5)
        cond_c = oldest_unsealed_age_seconds > 1800.0

        rule_j_match = (cond_a and cond_b) or cond_c

        if not rule_j_match:
            return RuleEvaluationResult.NO_MATCH, None

        evidence = [event.audit_log_id or event.event_id]

        signal = SecuritySignal(
            signal_id=str(uuid.uuid4()),
            rule_id=self.rule_id,
            rule_version=self.rule_version,
            detected_at=event.timestamp,
            severity=self.definition.severity,
            confidence=0.98,
            mode="shadow",
            correlation_keys={"subsystem": "audit_sealer"},
            evidence_references=evidence,
            event_count=1,
            window_seconds=self.definition.time_window_seconds,
            explanation=(
                f"Sealer degradation & backlog triggered: ((backlog_records={backlog_records} > 1000 "
                f"AND (failures={sealer_failures} >= 3 OR lock_timeouts={sealer_lock_timeouts} >= 5)) "
                f"OR oldest_unsealed_age={oldest_unsealed_age_seconds}s > 1800s)."
            ),
            metadata={
                "backlog_records": backlog_records,
                "sealer_failures": sealer_failures,
                "sealer_lock_timeouts": sealer_lock_timeouts,
                "oldest_unsealed_age_seconds": oldest_unsealed_age_seconds,
                "cond_a": cond_a,
                "cond_b": cond_b,
                "cond_c": cond_c,
            },
        )
        return RuleEvaluationResult.MATCH, signal


class RuleCatalog:
    """
    Deterministic catalog and registry of detection rules A through J.
    Provides reproducible rule registration, retrieval, and batch evaluation.
    """

    def __init__(self) -> None:
        self._rules: Dict[str, BaseRuleEvaluator] = {}
        self._initialize_default_rules()

    def _initialize_default_rules(self) -> None:
        self.register_rule(RuleAEvaluator(DetectionRuleDefinition(
            rule_id="RULE-A", rule_version="1.0.0",
            title="Brute-Force Authentication with Success",
            description=">= 5 LOGIN_FAILURE events followed by successful LOGIN within 300s.",
            severity=DetectionSeverity.HIGH.value, time_window_seconds=300, threshold=5,
        )))
        self.register_rule(RuleBEvaluator(DetectionRuleDefinition(
            rule_id="RULE-B", rule_version="1.0.0",
            title="Authz Probing with Escalation",
            description=">= 3 ACCESS_DENIED events on sensitive resources followed by ACCESS_GRANTED within 600s.",
            severity=DetectionSeverity.HIGH.value, time_window_seconds=600, threshold=3,
        )))
        self.register_rule(RuleCEvaluator(DetectionRuleDefinition(
            rule_id="RULE-C", rule_version="1.0.0",
            title="Question Access Denial Flood",
            description=">= 10 question access denials from same session/device within 60s.",
            severity=DetectionSeverity.MEDIUM.value, time_window_seconds=60, threshold=10,
        )))
        self.register_rule(RuleDEvaluator(DetectionRuleDefinition(
            rule_id="RULE-D", rule_version="1.0.0",
            title="Multi-Account Device Hopping",
            description=">= 3 distinct actor identities on same valid device fingerprint within 900s.",
            severity=DetectionSeverity.HIGH.value, time_window_seconds=900, threshold=3,
        )))
        self.register_rule(RuleEEvaluator(DetectionRuleDefinition(
            rule_id="RULE-E", rule_version="1.0.0",
            title="Break-Glass Scope Misuse",
            description="BREAK_GLASS_ACTIVATED followed by access evaluated as OUT_OF_SCOPE within 1800s.",
            severity=DetectionSeverity.CRITICAL.value, time_window_seconds=1800, threshold=1,
        )))
        self.register_rule(RuleFEvaluator(DetectionRuleDefinition(
            rule_id="RULE-F", rule_version="1.0.0",
            title="Break-Glass Audit Anomaly",
            description="Five-state evidence lifecycle triggers signal only on CONFIRMED_MISSING (>300s or explicit failure).",
            severity=DetectionSeverity.CRITICAL.value, time_window_seconds=600, threshold=1,
        )))
        self.register_rule(RuleGEvaluator(DetectionRuleDefinition(
            rule_id="RULE-G", rule_version="1.0.0",
            title="KMS Cryptographic Failure Burst",
            description=">= 3 relevant KMS security failures within 300s.",
            severity=DetectionSeverity.HIGH.value, time_window_seconds=300, threshold=3,
        )))
        self.register_rule(RuleHEvaluator(DetectionRuleDefinition(
            rule_id="RULE-H", rule_version="1.0.0",
            title="Audit Tampering Correlation",
            description="Deep verifier FAIL correlated with relevant recent ACCESS_DENIED evidence within 3600s.",
            severity=DetectionSeverity.CRITICAL.value, time_window_seconds=3600, threshold=1,
        )))
        self.register_rule(RuleIEvaluator(DetectionRuleDefinition(
            rule_id="RULE-I", rule_version="1.0.0",
            title="Rate-Limit Probing Sequence",
            description=">= 5 rate-limit rejections followed by sensitive resource access within 600s.",
            severity=DetectionSeverity.MEDIUM.value, time_window_seconds=600, threshold=5,
        )))
        self.register_rule(RuleJEvaluator(DetectionRuleDefinition(
            rule_id="RULE-J", rule_version="1.0.0",
            title="Sealer Degradation & Backlog",
            description="Exact boolean expression: (backlog > 1000 and (failures >= 3 or timeouts >= 5)) or oldest_unsealed > 1800s.",
            severity=DetectionSeverity.HIGH.value, time_window_seconds=300, threshold=1,
        )))

    def register_rule(self, evaluator: BaseRuleEvaluator) -> None:
        self._rules[evaluator.rule_id] = evaluator

    def get_rule(self, rule_id: str) -> Optional[BaseRuleEvaluator]:
        return self._rules.get(rule_id)

    def list_rules(self) -> List[DetectionRuleDefinition]:
        return [evaluator.definition for evaluator in self._rules.values()]

    def evaluate_all(
        self,
        event: SecurityEventNormalized,
        correlation_mgr: CorrelationManager,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[Tuple[str, RuleEvaluationResult, Optional[SecuritySignal]]]:
        """
        Evaluates all registered rules against the event and correlation state in deterministic order.
        """
        results: List[Tuple[str, RuleEvaluationResult, Optional[SecuritySignal]]] = []
        for rule_id in sorted(self._rules.keys()):
            evaluator = self._rules[rule_id]
            try:
                result, signal = evaluator.evaluate(event, correlation_mgr, context)
                results.append((rule_id, result, signal))
            except Exception as exc:
                results.append((rule_id, RuleEvaluationResult.ERROR, None))
        return results
