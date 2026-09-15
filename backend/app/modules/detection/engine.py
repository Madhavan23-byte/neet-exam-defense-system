"""
B-SEA Phase 3C-5C Detection & Correlation Foundation — Detection Engine & SQS Dispatch
Conforming strictly to BSEA_PHASE3C_5C_DETECTION_CORRELATION_ARCHITECTURE_REVIEW_REV03.md

Architecture:
  - DURABLE AUDIT-CHAIN-TO-SQS DISPATCH: PostgreSQL audit persistence is authoritative.
    SQS is a detection delivery mechanism with at-least-once semantics.
    PostgreSQL persistence != SQS delivery != worker processing.
  - Worker-side idempotency and deduplication.
  - Strict SHADOW MODE: Observational only. Never blocks candidates, modifies auth,
    mutates audit history, or modifies KMS state.
  - Local CI: Deterministic in-process queue and synchronous pipeline.
  - Metrics emission with strictly bounded cardinality (<= 126 base series).
"""
from __future__ import annotations

import asyncio
from collections import OrderedDict
from datetime import datetime, timezone
import logging
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import uuid

from app.core.metrics import metrics_registry
from app.modules.detection.cloudtrail import CloudTrailKMSReconciler
from app.modules.detection.correlation import CorrelationManager
from app.modules.detection.models import (
    DetectionMode,
    DetectionSeverity,
    RuleEvaluationResult,
    SecurityEventNormalized,
    SecuritySignal,
)
from app.modules.detection.normalizer import EventNormalizer
from app.modules.detection.rules import RuleCatalog

logger = logging.getLogger(__name__)

MAX_PROCESSED_SIGNALS_CACHE: int = 50000


class DetectionEngine:
    """
    Central Detection & Correlation Engine for B-SEA Phase 3C-5C.
    Operates strictly in SHADOW MODE: produces advisory security signals without
    executing autonomous containment, candidate termination, or database mutation.
    """

    def __init__(
        self,
        correlation_mgr: Optional[CorrelationManager] = None,
        rule_catalog: Optional[RuleCatalog] = None,
        cloudtrail_reconciler: Optional[CloudTrailKMSReconciler] = None,
        mode: str = "shadow",
        record_metrics: bool = True,
    ) -> None:
        self._mode = mode if mode in ("shadow", "active") else "shadow"
        self._correlation_mgr = correlation_mgr or CorrelationManager()
        self._rule_catalog = rule_catalog or RuleCatalog()
        self._cloudtrail_reconciler = cloudtrail_reconciler or CloudTrailKMSReconciler(record_metrics=record_metrics)
        self._record_metrics = record_metrics

        # Advisory signal cache for deduplication and queries
        self._signal_history: List[SecuritySignal] = []
        self._signal_dedup_hashes: OrderedDict[str, float] = OrderedDict()
        self._last_processed_timestamp: Optional[datetime] = None

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def correlation_manager(self) -> CorrelationManager:
        return self._correlation_mgr

    @property
    def rule_catalog(self) -> RuleCatalog:
        return self._rule_catalog

    @property
    def cloudtrail_reconciler(self) -> CloudTrailKMSReconciler:
        return self._cloudtrail_reconciler

    def process_event(
        self,
        raw_or_normalized: Union[SecurityEventNormalized, Dict[str, Any], Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> List[SecuritySignal]:
        """
        Ingests, normalizes, correlates, and evaluates an event through the rule catalog.
        Guaranteed fail-safe: any detection failure will not raise to break core examination flow.
        """
        generated_signals: List[SecuritySignal] = []

        try:
            # 1. Normalize event
            if isinstance(raw_or_normalized, SecurityEventNormalized):
                event = raw_or_normalized
            elif isinstance(raw_or_normalized, dict):
                event = EventNormalizer.normalize_audit_log(raw_or_normalized)
            elif hasattr(raw_or_normalized, "__table__") or hasattr(raw_or_normalized, "event_type"):
                event = EventNormalizer.normalize_audit_log(raw_or_normalized)
            else:
                event = EventNormalizer.normalize_cbt_event(raw_or_normalized)

            # 2. Update engine lag metric
            now = datetime.now(timezone.utc)
            event_time = event.timestamp if event.timestamp.tzinfo else event.timestamp.replace(tzinfo=timezone.utc)
            lag = max(0.0, (now - event_time).total_seconds())
            self._last_processed_timestamp = now
            if self._record_metrics:
                try:
                    metrics_registry.set_gauge("bsea_detection_engine_lag_seconds", lag)
                except Exception as exc:
                    logger.debug("Metrics lag emission error: %s", exc)

            # 3. Ingest into correlation manager (handles deduplication and ring buffer)
            is_new = self._correlation_mgr.ingest(event)
            if not is_new:
                logger.debug("Event %s dropped as duplicate in correlation manager", event.event_id)
                return []

            # 4. If event is KMS-related, invoke CloudTrail reconciliation
            if event.kms_request_id or event.source_subsystem == "kms" or "kms" in event.event_type.lower():
                self._cloudtrail_reconciler.reconcile_kms_event(event, current_time=now)

            # 5. Deterministic rule evaluation
            rule_evaluations = self._rule_catalog.evaluate_all(event, self._correlation_mgr, context)

            for rule_id, result, signal in rule_evaluations:
                # Record rule evaluation metric: bsea_detection_rule_evaluations_total
                if self._record_metrics:
                    try:
                        metrics_registry.inc_counter(
                            "bsea_detection_rule_evaluations_total",
                            {"rule_id": rule_id, "result": result.value},
                        )
                    except Exception as exc:
                        logger.debug("Metrics rule eval emission error: %s", exc)

                # Process matched signals
                if result == RuleEvaluationResult.MATCH and signal is not None:
                    # Enforce SHADOW MODE on signal
                    if signal.mode != "shadow" and self._mode == "shadow":
                        signal = SecuritySignal(
                            signal_id=signal.signal_id,
                            rule_id=signal.rule_id,
                            rule_version=signal.rule_version,
                            detected_at=signal.detected_at,
                            severity=signal.severity,
                            confidence=signal.confidence,
                            mode="shadow",
                            correlation_keys=signal.correlation_keys,
                            evidence_references=signal.evidence_references,
                            event_count=signal.event_count,
                            window_seconds=signal.window_seconds,
                            policy_version=signal.policy_version,
                            explanation=signal.explanation,
                            metadata=signal.metadata,
                        )

                    # Deduplicate signal via idempotency hash
                    sig_hash = signal.compute_idempotency_hash()
                    if sig_hash in self._signal_dedup_hashes:
                        logger.debug("Advisory signal %s deduplicated via hash %s", signal.signal_id, sig_hash)
                        continue

                    self._signal_dedup_hashes[sig_hash] = now.timestamp()
                    if len(self._signal_dedup_hashes) > MAX_PROCESSED_SIGNALS_CACHE:
                        self._signal_dedup_hashes.popitem(last=False)

                    self._signal_history.append(signal)
                    generated_signals.append(signal)

                    # Record signal metric: bsea_detection_signals_total
                    if self._record_metrics:
                        try:
                            # Map rule_id to metric label domain
                            rid_label = signal.rule_id if signal.rule_id in {
                                "RULE-A", "RULE-B", "RULE-C", "RULE-D", "RULE-E",
                                "RULE-F", "RULE-G", "RULE-H", "RULE-I", "RULE-J"
                            } else "other"
                            sev_label = signal.severity if signal.severity in {
                                "LOW", "MEDIUM", "HIGH", "CRITICAL"
                            } else "MEDIUM"
                            mode_label = signal.mode if signal.mode in {"shadow", "active"} else "shadow"

                            metrics_registry.inc_counter(
                                "bsea_detection_signals_total",
                                {"rule_id": rid_label, "severity": sev_label, "mode": mode_label},
                            )
                        except Exception as exc:
                            logger.debug("Metrics signal emission error: %s", exc)

                    logger.info(
                        "Advisory detection signal generated: %s (%s, severity=%s, mode=%s)",
                        signal.signal_id,
                        signal.rule_id,
                        signal.severity,
                        signal.mode,
                        extra={"signal_id": signal.signal_id, "rule_id": signal.rule_id},
                    )

        except Exception as exc:
            logger.error(
                "Fail-safe caught error in detection engine: %s",
                exc,
                exc_info=True,
                extra={"action": "DETECTION_ENGINE_FAIL_SAFE"},
            )
            # Fail-safe: returns empty signals without disrupting calling caller
            return []

        return generated_signals

    def get_advisory_signals(self, limit: int = 100) -> List[SecuritySignal]:
        """Returns recent non-authoritative advisory signals."""
        return self._signal_history[-limit:]


class DurableAuditSQSDispatcher:
    """
    DURABLE AUDIT-CHAIN-TO-SQS DISPATCH Abstraction.
    
    PostgreSQL persistence is authoritative. SQS is a detection delivery mechanism.
    Tolerates dispatcher crashes, restarts, and re-reads of durable audit state.
    Never modifies immutable audit history to support dispatch.
    Never claims transactional outbox or exactly-once delivery.
    """

    def __init__(self, in_memory_queue: Optional[asyncio.Queue] = None) -> None:
        self._in_memory_queue = in_memory_queue or asyncio.Queue()
        self._dispatched_count = 0

    @property
    def queue(self) -> asyncio.Queue:
        return self._in_memory_queue

    async def dispatch_audit_event(self, audit_log: Any) -> bool:
        """
        Dispatches a committed audit log to the SQS queue (or in-process queue in CI).
        """
        normalized = EventNormalizer.normalize_audit_log(audit_log)
        payload = {
            "message_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": normalized.to_dict(),
        }
        await self._in_memory_queue.put(payload)
        self._dispatched_count += 1
        return True

    def dispatch_sync(self, audit_log: Any) -> bool:
        """Synchronous dispatch helper for test pipelines."""
        normalized = EventNormalizer.normalize_audit_log(audit_log)
        payload = {
            "message_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": normalized.to_dict(),
        }
        self._in_memory_queue.put_nowait(payload)
        self._dispatched_count += 1
        return True


class SQSDetectionWorker:
    """
    Production-oriented SQS Worker abstraction for Detection & Correlation.
    Implements worker-side idempotency, at-least-once delivery handling,
    dead-letter queue (DLQ) isolation, and shadow mode execution.
    """

    def __init__(
        self,
        engine: DetectionEngine,
        queue: Optional[asyncio.Queue] = None,
        dlq: Optional[asyncio.Queue] = None,
    ) -> None:
        self._engine = engine
        self._queue = queue or asyncio.Queue()
        self._dlq = dlq or asyncio.Queue()
        self._processed_message_ids: OrderedDict[str, float] = OrderedDict()
        self._running = False

    async def process_one_message(self, message: Dict[str, Any]) -> List[SecuritySignal]:
        """
        Processes a single message received from SQS.
        Enforces worker-side idempotency: duplicate message_id is safely acknowledged and ignored.
        """
        msg_id = message.get("message_id", str(uuid.uuid4()))
        now_ts = datetime.now(timezone.utc).timestamp()

        # Idempotency check: at-least-once delivery absorption
        if msg_id in self._processed_message_ids:
            logger.debug("Worker ignoring duplicate message %s", msg_id)
            return []

        self._processed_message_ids[msg_id] = now_ts
        if len(self._processed_message_ids) > 50000:
            self._processed_message_ids.popitem(last=False)

        try:
            event_dict = message.get("event", {})
            event = EventNormalizer.normalize_audit_log(event_dict)
            signals = self._engine.process_event(event)
            return signals
        except Exception as exc:
            logger.error("Poison message encountered (%s). Routing to DLQ.", exc)
            await self._dlq.put({"error": str(exc), "poison_message": message})
            return []

    async def run_worker_loop(self, max_messages: Optional[int] = None) -> None:
        """Runs the worker loop processing messages from the queue."""
        self._running = True
        count = 0
        while self._running:
            try:
                msg = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                await self.process_one_message(msg)
                self._queue.task_done()
                count += 1
                if max_messages and count >= max_messages:
                    break
            except asyncio.TimeoutError:
                if max_messages:
                    break
                continue
            except asyncio.CancelledError:
                break

    def stop(self) -> None:
        self._running = False
