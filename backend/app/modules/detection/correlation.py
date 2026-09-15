"""
B-SEA Phase 3C-5C Detection & Correlation Foundation — Correlation Manager
Conforming to BSEA_PHASE3C_5C_DETECTION_CORRELATION_ARCHITECTURE_REVIEW_REV03.md
"""
from __future__ import annotations

import bisect
from collections import OrderedDict, deque
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from app.modules.detection.models import SecurityEventNormalized

logger = logging.getLogger("bsea.detection.correlation")

MAX_IN_MEMORY_EVENTS = 50000
MAX_DEDUPLICATION_CACHE = 100000
DEFAULT_PURGE_HORIZON_SECONDS = 3600  # 1 hour


class CorrelationManager:
    """
    Multi-dimensional sliding-window event correlation manager.
    Supports in-memory ring buffer (Local CI/Prototype) and Redis ZSET (Production Target).
    Implements explicit Degraded Mode when Redis is unavailable.
    """

    def __init__(
        self,
        redis_client: Optional[Any] = None,
        max_events: int = MAX_IN_MEMORY_EVENTS,
        auto_purge_horizon: int = DEFAULT_PURGE_HORIZON_SECONDS,
        auto_purge_horizon_seconds: Optional[int] = None,
    ):
        self._redis = redis_client
        self._max_events = max_events
        self._auto_purge_horizon = auto_purge_horizon_seconds if auto_purge_horizon_seconds is not None else auto_purge_horizon
        self._degraded_correlation = False

        # In-memory primary storage: {dim_key: {dim_value: deque([SecurityEventNormalized])}}
        # Dimension keys: "actor_id", "session_id", "device_id", "ip_hash", "exam_id", "all"
        self._in_memory_events: Dict[str, Dict[str, deque[SecurityEventNormalized]]] = {
            "actor_id": {},
            "session_id": {},
            "device_id": {},
            "ip_hash": {},
            "exam_id": {},
            "resource_id": {},
            "all": {"global": deque()},
        }
        self._total_in_memory_count = 0

        # LRU Deduplication Cache: {event_id: timestamp_float}
        self._dedup_cache: OrderedDict[str, float] = OrderedDict()

    @property
    def is_degraded(self) -> bool:
        """Returns True if the correlation manager is operating in Degraded Mode."""
        return self._degraded_correlation

    def set_degraded(self, degraded: bool) -> None:
        """Explicitly toggles degraded correlation status."""
        self._degraded_correlation = degraded

    def _dimension_hash(self, dim: str, val: str) -> str:
        """Hash dimension key and value for Redis indexing."""
        return hashlib.sha256(f"{dim}:{val}".encode("utf-8")).hexdigest()

    def ingest(self, event: SecurityEventNormalized) -> bool:
        """
        Ingests a normalized security event into the correlation state.
        Returns True if newly ingested, False if ignored as duplicate.
        """
        # 1. Deduplication check
        now_ts = datetime.now(timezone.utc).timestamp()
        if event.event_id in self._dedup_cache:
            return False  # Duplicate event silently dropped

        self._dedup_cache[event.event_id] = now_ts
        if len(self._dedup_cache) > MAX_DEDUPLICATION_CACHE:
            self._dedup_cache.popitem(last=False)

        # 2. Redis ingestion (Production path)
        if self._redis is not None and not self._degraded_correlation:
            try:
                self._ingest_redis(event)
            except Exception as exc:
                logger.warning(
                    "Redis correlation fault (%s). Entering Degraded Mode.",
                    exc.__class__.__name__,
                    extra={"action": "CORRELATION_DEGRADED", "error": str(exc)},
                )
                self._degraded_correlation = True

        # 3. In-memory ring buffer ingestion (Prototype & Degraded Mode path)
        self._ingest_in_memory(event)
        return True

    def _ingest_in_memory(self, event: SecurityEventNormalized) -> None:
        """Appends event into in-memory ring buffers maintaining timestamp order."""
        # Evict oldest events if exceeding memory ceiling
        if self._total_in_memory_count >= self._max_events:
            self._purge_oldest_event()

        # Add to global ring buffer
        self._insert_sorted(self._in_memory_events["all"]["global"], event)
        self._total_in_memory_count += 1

        # Add to dimension-specific ring buffers
        dims = [
            ("actor_id", event.actor_id),
            ("session_id", event.session_id),
            ("device_id", event.device_id),
            ("ip_hash", event.ip_hash),
            ("resource_id", event.resource_id),
        ]
        if event.metadata.get("exam_id"):
            dims.append(("exam_id", str(event.metadata["exam_id"])))

        for dim_key, dim_val in dims:
            if dim_val:
                bucket = self._in_memory_events[dim_key].setdefault(str(dim_val), deque())
                self._insert_sorted(bucket, event)

    def _insert_sorted(self, dq: deque[SecurityEventNormalized], event: SecurityEventNormalized) -> None:
        """Inserts event in ascending timestamp order (jitter absorption)."""
        if not dq or event.timestamp >= dq[-1].timestamp:
            dq.append(event)
            return

        # If out of order (arrival jitter), insert in correct position
        temp_list = list(dq)
        timestamps = [e.timestamp for e in temp_list]
        pos = bisect.bisect_right(timestamps, event.timestamp)
        temp_list.insert(pos, event)
        dq.clear()
        dq.extend(temp_list)

    def _purge_oldest_event(self) -> None:
        """Evicts oldest global event across all buckets."""
        global_dq = self._in_memory_events["all"]["global"]
        if not global_dq:
            return
        oldest = global_dq.popleft()
        self._total_in_memory_count -= 1

        # Clean from dimension buckets
        dims = [
            ("actor_id", oldest.actor_id),
            ("session_id", oldest.session_id),
            ("device_id", oldest.device_id),
            ("ip_hash", oldest.ip_hash),
            ("resource_id", oldest.resource_id),
        ]
        if oldest.metadata.get("exam_id"):
            dims.append(("exam_id", str(oldest.metadata["exam_id"])))

        for dim_key, dim_val in dims:
            if dim_val and str(dim_val) in self._in_memory_events[dim_key]:
                bucket = self._in_memory_events[dim_key][str(dim_val)]
                if bucket and bucket[0].event_id == oldest.event_id:
                    bucket.popleft()
                elif oldest in bucket:
                    bucket.remove(oldest)

    def _ingest_redis(self, event: SecurityEventNormalized) -> None:
        """Publishes event to Redis ZSET sliding-window indices."""
        score = event.timestamp.timestamp()
        serialized = json.dumps(event.to_dict())
        pipeline = self._redis.pipeline()

        dims = [
            ("actor_id", event.actor_id),
            ("session_id", event.session_id),
            ("device_id", event.device_id),
            ("ip_hash", event.ip_hash),
            ("resource_id", event.resource_id),
        ]
        if event.metadata.get("exam_id"):
            dims.append(("exam_id", str(event.metadata["exam_id"])))

        for dim_key, dim_val in dims:
            if dim_val:
                rkey = f"bsea:corr:{dim_key}:{self._dimension_hash(dim_key, str(dim_val))}"
                pipeline.zadd(rkey, {serialized: score})
                pipeline.expire(rkey, 7200)

        pipeline.execute()

    def get_events_in_window(
        self,
        dimension_key: str,
        dimension_value: str,
        window_seconds: int,
        reference_time: Optional[datetime] = None,
    ) -> List[SecurityEventNormalized]:
        """
        Retrieves all events matching the dimension within [reference_time - window_seconds, reference_time].
        """
        ref_time = reference_time or datetime.now(timezone.utc)
        start_time = ref_time - timedelta(seconds=window_seconds)

        # Production Redis path if available and not degraded
        if self._redis is not None and not self._degraded_correlation:
            try:
                rkey = f"bsea:corr:{dimension_key}:{self._dimension_hash(dimension_key, dimension_value)}"
                min_score = start_time.timestamp()
                max_score = ref_time.timestamp()
                raw_entries = self._redis.zrangebyscore(rkey, min_score, max_score)
                results: List[SecurityEventNormalized] = []
                for item in raw_entries:
                    data = json.loads(item if isinstance(item, str) else item.decode("utf-8"))
                    from app.modules.detection.normalizer import EventNormalizer
                    results.append(EventNormalizer.normalize_audit_log(data))
                return results
            except Exception as exc:
                logger.warning("Redis read fault; falling back to in-memory: %s", exc)
                self._degraded_correlation = True

        # In-memory retrieval path
        dim_dict = self._in_memory_events.get(dimension_key, {})
        dq = dim_dict.get(str(dimension_value))
        if not dq:
            return []

        matched: List[SecurityEventNormalized] = []
        for e in dq:
            if start_time <= e.timestamp <= ref_time:
                matched.append(e)
            elif e.timestamp > ref_time:
                break
        return matched

    def purge_expired(self, current_time: Optional[datetime] = None) -> int:
        """Purges events older than the auto-purge horizon from in-memory ring buffers."""
        now = current_time or datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=self._auto_purge_horizon)
        global_dq = self._in_memory_events["all"]["global"]
        purged = 0

        while global_dq and global_dq[0].timestamp < cutoff:
            self._purge_oldest_event()
            purged += 1

        return purged
