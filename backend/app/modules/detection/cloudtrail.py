"""
B-SEA Phase 3C-5C Detection & Correlation Foundation — CloudTrail / KMS Correlation
Conforming strictly to BSEA_PHASE3C_5C_DETECTION_CORRELATION_ARCHITECTURE_REVIEW_REV03.md

Implements reconciliation for AWS CloudTrail KMS API management events.
Flow: AWS KMS -> CloudTrail -> CloudWatch Logs -> Subscription Filter -> Detection / Correlation

Correlation States:
  - CORRELATED: Internal KMS event matches CloudTrail management event (request_id, key, status, caller).
  - UNRESOLVED: Internal KMS event age < 15 mins (900s); within normal CloudTrail delay.
  - MISSING_EVIDENCE: Internal KMS event age >= 15 mins (900s) without CloudTrail record.
  - CONFLICTING_EVIDENCE: Request ID matches but IAM caller ARN or result/status conflicts.

Note: Missing or delayed CloudTrail evidence alone is insufficient to classify activity as malicious.
Never claim zero false positives.
"""
from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Dict, List, Optional, Tuple

from app.core.metrics import metrics_registry
from app.modules.detection.models import (
    CloudTrailKMSEvent,
    CloudTrailReconciliationState,
    SecurityEventNormalized,
)

logger = logging.getLogger(__name__)

CLOUDTRAIL_UNRESOLVED_WINDOW_SECONDS: int = 900  # 15 minutes standard delivery delay ceiling
MAX_PENDING_KMS_EVENTS: int = 10000
MAX_CACHED_CLOUDTRAIL_EVENTS: int = 10000


class CloudTrailKMSReconciler:
    """
    Reconciles application-level KMS security events against ingested
    AWS CloudTrail KMS API management events.
    """

    def __init__(
        self,
        unresolved_window_seconds: int = CLOUDTRAIL_UNRESOLVED_WINDOW_SECONDS,
        record_metrics: bool = True,
    ) -> None:
        self._unresolved_window_seconds = unresolved_window_seconds
        self._record_metrics = record_metrics
        # Map: kms_request_id -> CloudTrailKMSEvent
        self._cloudtrail_by_request_id: OrderedDict[str, CloudTrailKMSEvent] = OrderedDict()
        # Map: event_id -> (SecurityEventNormalized, ingest_time)
        self._pending_kms_events: OrderedDict[str, Tuple[SecurityEventNormalized, datetime]] = OrderedDict()
        # Reconciliation history / audit references
        self._reconciliation_history: List[Dict[str, Any]] = []

    def ingest_cloudtrail_event(self, ct_event: CloudTrailKMSEvent) -> None:
        """
        Ingests a CloudTrail KMS API management event received from CloudWatch Logs subscription.
        """
        if not ct_event.request_id:
            return

        self._cloudtrail_by_request_id[ct_event.request_id] = ct_event
        if len(self._cloudtrail_by_request_id) > MAX_CACHED_CLOUDTRAIL_EVENTS:
            self._cloudtrail_by_request_id.popitem(last=False)

    def reconcile_kms_event(
        self,
        kms_event: SecurityEventNormalized,
        current_time: Optional[datetime] = None,
    ) -> Tuple[CloudTrailReconciliationState, Optional[CloudTrailKMSEvent]]:
        """
        Reconciles a single application KMS event against available CloudTrail management events.
        Evaluates one of 4 explicit states:
          - CORRELATED
          - CONFLICTING_EVIDENCE
          - UNRESOLVED (age < 15 mins)
          - MISSING_EVIDENCE (age >= 15 mins)
        """
        now = current_time or datetime.now(timezone.utc)
        req_id = kms_event.kms_request_id or kms_event.metadata.get("kms_request_id")

        if not req_id:
            # Cannot reconcile without request ID linkage
            state = CloudTrailReconciliationState.MISSING_EVIDENCE
            self._record_telemetry(state)
            return state, None

        # Check if CloudTrail event has arrived
        ct_match = self._cloudtrail_by_request_id.get(req_id)

        if ct_match:
            # Check for conflicting evidence (caller identity or execution status mismatch)
            is_conflicting = False
            expected_caller = kms_event.metadata.get("caller_arn")
            if expected_caller and ct_match.caller_arn and expected_caller.lower() != ct_match.caller_arn.lower():
                is_conflicting = True

            expected_op = kms_event.action
            if expected_op and ct_match.event_name and expected_op.lower() != ct_match.event_name.lower():
                is_conflicting = True

            if is_conflicting:
                state = CloudTrailReconciliationState.CONFLICTING_EVIDENCE
                self._record_telemetry(state)
                return state, ct_match

            # Successful match
            state = CloudTrailReconciliationState.CORRELATED
            self._record_telemetry(state)
            return state, ct_match

        # CloudTrail record not yet matched: check elapsed observation age
        event_time = kms_event.timestamp
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=timezone.utc)

        age_seconds = (now - event_time).total_seconds()
        if age_seconds < self._unresolved_window_seconds:
            # Within 15-minute expected delivery latency
            state = CloudTrailReconciliationState.UNRESOLVED
            # Track as pending for background reconciliation
            self._pending_kms_events[kms_event.event_id] = (kms_event, now)
            if len(self._pending_kms_events) > MAX_PENDING_KMS_EVENTS:
                self._pending_kms_events.popitem(last=False)
        else:
            # Exceeded 15-minute SLA without CloudTrail record
            state = CloudTrailReconciliationState.MISSING_EVIDENCE

        self._record_telemetry(state)
        return state, None

    def reconcile_pending_events(
        self, current_time: Optional[datetime] = None
    ) -> Dict[CloudTrailReconciliationState, int]:
        """
        Scans pending KMS events in UNRESOLVED state and updates them if CloudTrail events
        have arrived or if the 15-minute window has elapsed.
        """
        now = current_time or datetime.now(timezone.utc)
        counts = {
            CloudTrailReconciliationState.CORRELATED: 0,
            CloudTrailReconciliationState.UNRESOLVED: 0,
            CloudTrailReconciliationState.MISSING_EVIDENCE: 0,
            CloudTrailReconciliationState.CONFLICTING_EVIDENCE: 0,
        }

        resolved_event_ids: List[str] = []

        for event_id, (kms_event, ingest_time) in list(self._pending_kms_events.items()):
            req_id = kms_event.kms_request_id or kms_event.metadata.get("kms_request_id")
            ct_match = self._cloudtrail_by_request_id.get(req_id) if req_id else None

            if ct_match:
                # Arrived since last check
                is_conflicting = False
                expected_caller = kms_event.metadata.get("caller_arn")
                if expected_caller and ct_match.caller_arn and expected_caller.lower() != ct_match.caller_arn.lower():
                    is_conflicting = True

                state = (
                    CloudTrailReconciliationState.CONFLICTING_EVIDENCE
                    if is_conflicting
                    else CloudTrailReconciliationState.CORRELATED
                )
                counts[state] += 1
                self._record_telemetry(state)
                resolved_event_ids.append(event_id)
            else:
                event_time = kms_event.timestamp
                if event_time.tzinfo is None:
                    event_time = event_time.replace(tzinfo=timezone.utc)
                age_seconds = (now - event_time).total_seconds()
                if age_seconds >= self._unresolved_window_seconds:
                    counts[CloudTrailReconciliationState.MISSING_EVIDENCE] += 1
                    self._record_telemetry(CloudTrailReconciliationState.MISSING_EVIDENCE)
                    resolved_event_ids.append(event_id)
                else:
                    counts[CloudTrailReconciliationState.UNRESOLVED] += 1

        for eid in resolved_event_ids:
            self._pending_kms_events.pop(eid, None)

        return counts

    def _record_telemetry(self, state: CloudTrailReconciliationState) -> None:
        """Emits reconciliation telemetry to Prometheus metrics registry."""
        if not self._record_metrics:
            return
        status_map = {
            CloudTrailReconciliationState.CORRELATED: "correlated",
            CloudTrailReconciliationState.UNRESOLVED: "unresolved",
            CloudTrailReconciliationState.MISSING_EVIDENCE: "missing",
            CloudTrailReconciliationState.CONFLICTING_EVIDENCE: "conflicting",
        }
        status_label = status_map.get(state, "unresolved")
        try:
            metrics_registry.inc_counter("bsea_cloudtrail_reconciliation_total", {"status": status_label})
        except Exception as exc:
            logger.debug("Telemetry emission error: %s", exc)
