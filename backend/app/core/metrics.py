"""
B-SEA Production Observability Foundation — Bounded In-Memory Prometheus Metrics
Phase 3C-5B Implementation conforming to BSEA_PHASE3C_5B_ARCHITECTURE_REVIEW_REV02.md
"""
from __future__ import annotations

import threading
import time
from typing import Dict, List, Optional, Set, Tuple, Union

# ── Approved Finite Label Domains (Strict Compile-Time Bounds) ─────────────────
ALLOWED_ENDPOINT_CLASSES: Set[str] = {
    "/api/v1/candidate/auth/login",
    "/api/v1/candidate/auth/session",
    "/api/v1/candidate/exam/start",
    "/api/v1/candidate/exam/submit",
    "/api/v1/candidate/exam/autosave",
    "/api/v1/candidate/questions/get",
    "/api/v1/candidate/questions/answer",
    "/api/v1/auth/login",
    "/api/v1/auth/mfa/verify",
    "/api/v1/exams/create",
    "/api/v1/exams/list",
    "/api/v1/exams/detail",
    "/api/v1/questions/create",
    "/api/v1/questions/assign",
    "/api/v1/questions/review",
    "/api/v1/break-glass/request",
    "/api/v1/break-glass/approve",
    "/api/v1/break-glass/activate",
    "/health/live",
    "/health/ready",
    "other",
}

ALLOWED_METHODS: Set[str] = {"GET", "POST", "PUT", "DELETE"}
ALLOWED_STATUS_CLASSES: Set[str] = {"2xx", "3xx", "4xx", "5xx"}

ALLOWED_AUTH_FAILURE_REASONS: Set[str] = {
    "invalid_credentials",
    "user_locked",
    "mfa_failed",
    "token_expired",
    "rate_limited",
}

ALLOWED_ACTOR_ROLES: Set[str] = {
    "candidate",
    "reviewer",
    "moderator",
    "super_admin",
    "anonymous",
}

ALLOWED_RESOURCE_TYPES: Set[str] = {
    "exam",
    "question",
    "grant",
    "blueprint",
    "break_glass",
}

ALLOWED_AUTHZ_REASONS: Set[str] = {
    "role_unauthorized",
    "grant_missing",
    "grant_expired",
    "ip_mismatch",
    "coi_conflict",
}

ALLOWED_QUESTION_GRANT_DENIAL_REASONS: Set[str] = {
    "unassigned_reviewer",
    "unreleased_question",
    "expired_grant",
    "session_terminated",
}

ALLOWED_BREAK_GLASS_STATUSES: Set[str] = {"requested", "approved", "rejected"}
ALLOWED_BREAK_GLASS_ACTIVATION_STATUSES: Set[str] = {"activated", "revoked", "expired"}
ALLOWED_AUDIT_INGESTION_MODES: Set[str] = {"atomic_worker", "isolated_direct"}
ALLOWED_SEALER_STATUSES: Set[str] = {"success", "locked", "failed", "noop"}
ALLOWED_SEALER_DURATION_STATUSES: Set[str] = {"success", "failed", "noop"}
ALLOWED_VERIFIER_RESULTS: Set[str] = {"pass", "fail", "unresolved", "stale"}
ALLOWED_DEPENDENCIES: Set[str] = {"postgres", "redis", "kms"}

# ── Phase 3C-5C Detection & Correlation Finite Label Domains ──────────────────
ALLOWED_DETECTION_RULES: Set[str] = {
    "RULE-A",
    "RULE-B",
    "RULE-C",
    "RULE-D",
    "RULE-E",
    "RULE-F",
    "RULE-G",
    "RULE-H",
    "RULE-I",
    "RULE-J",
    "other",
}

ALLOWED_DETECTION_SEVERITIES: Set[str] = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}

ALLOWED_DETECTION_MODES: Set[str] = {
    "shadow",
    "active",
}

ALLOWED_EVALUATION_RESULTS: Set[str] = {
    "match",
    "no_match",
    "error",
}

ALLOWED_CLOUDTRAIL_RECONCILIATION_STATUSES: Set[str] = {
    "correlated",
    "unresolved",
    "missing",
    "conflicting",
}

HTTP_LATENCY_BUCKETS: Tuple[float, ...] = (0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)
SEALER_DURATION_BUCKETS: Tuple[float, ...] = (0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)


# ── Metric Domain Registry & Specification ────────────────────────────────────
METRIC_SPECIFICATIONS: Dict[str, Dict[str, Any]] = {
    "bsea_http_requests_total": {
        "type": "counter",
        "help": "Total count of HTTP requests processed by endpoint class, method, and status class.",
        "labels": ("endpoint_class", "method", "status_class"),
        "domains": {
            "endpoint_class": ALLOWED_ENDPOINT_CLASSES,
            "method": ALLOWED_METHODS,
            "status_class": ALLOWED_STATUS_CLASSES,
        },
    },
    "bsea_http_request_duration_seconds": {
        "type": "histogram",
        "help": "HTTP request execution latency in seconds.",
        "labels": ("endpoint_class", "method"),
        "domains": {
            "endpoint_class": ALLOWED_ENDPOINT_CLASSES,
            "method": ALLOWED_METHODS,
        },
        "buckets": HTTP_LATENCY_BUCKETS,
    },
    "bsea_security_auth_failures_total": {
        "type": "counter",
        "help": "Total count of security authentication failures by reason and actor role.",
        "labels": ("reason", "actor_role"),
        "domains": {
            "reason": ALLOWED_AUTH_FAILURE_REASONS,
            "actor_role": ALLOWED_ACTOR_ROLES,
        },
    },
    "bsea_security_authz_denials_total": {
        "type": "counter",
        "help": "Total count of security authorization denials by resource type and reason.",
        "labels": ("resource_type", "reason"),
        "domains": {
            "resource_type": ALLOWED_RESOURCE_TYPES,
            "reason": ALLOWED_AUTHZ_REASONS,
        },
    },
    "bsea_security_rate_limit_rejections_total": {
        "type": "counter",
        "help": "Total count of requests rejected due to rate limiting by endpoint class.",
        "labels": ("endpoint_class",),
        "domains": {
            "endpoint_class": ALLOWED_ENDPOINT_CLASSES,
        },
    },
    "bsea_security_question_grant_denials_total": {
        "type": "counter",
        "help": "Total count of question access grant denials by reason.",
        "labels": ("reason",),
        "domains": {
            "reason": ALLOWED_QUESTION_GRANT_DENIAL_REASONS,
        },
    },
    "bsea_security_break_glass_requests_total": {
        "type": "counter",
        "help": "Total count of emergency break-glass authorization requests by status.",
        "labels": ("status",),
        "domains": {
            "status": ALLOWED_BREAK_GLASS_STATUSES,
        },
    },
    "bsea_security_break_glass_activations_total": {
        "type": "counter",
        "help": "Total count of active emergency break-glass activations by status.",
        "labels": ("status",),
        "domains": {
            "status": ALLOWED_BREAK_GLASS_ACTIVATION_STATUSES,
        },
    },
    "bsea_audit_ingestion_failures_total": {
        "type": "counter",
        "help": "Total count of raw audit event persistence failures by ingestion mode.",
        "labels": ("mode",),
        "domains": {
            "mode": ALLOWED_AUDIT_INGESTION_MODES,
        },
    },
    "bsea_audit_sealer_cycles_total": {
        "type": "counter",
        "help": "Total count of audit sealer execution cycles by status.",
        "labels": ("status",),
        "domains": {
            "status": ALLOWED_SEALER_STATUSES,
        },
    },
    "bsea_audit_sealer_cycle_duration_seconds": {
        "type": "histogram",
        "help": "Audit sealer execution cycle duration in seconds.",
        "labels": ("status",),
        "domains": {
            "status": ALLOWED_SEALER_DURATION_STATUSES,
        },
        "buckets": SEALER_DURATION_BUCKETS,
    },
    "bsea_audit_sealer_backlog_records": {
        "type": "gauge",
        "help": "Current count of unsealed audit chain links pending epoch sealing.",
        "labels": (),
        "domains": {},
    },
    "bsea_audit_sealer_last_epoch_id": {
        "type": "gauge",
        "help": "Latest successfully sealed epoch ID.",
        "labels": (),
        "domains": {},
    },
    "bsea_audit_verifier_status": {
        "type": "gauge",
        "help": "Point-in-time result of 10-point Deep Audit Verifier (1 for active state, 0 otherwise).",
        "labels": ("result",),
        "domains": {
            "result": ALLOWED_VERIFIER_RESULTS,
        },
    },
    "bsea_audit_poison_events_quarantined_total": {
        "type": "gauge",
        "help": "Total count of poison audit events isolated under dual-custody quarantine.",
        "labels": (),
        "domains": {},
    },
    "bsea_dependency_failures_total": {
        "type": "counter",
        "help": "Total count of downstream infrastructure dependency failures by dependency.",
        "labels": ("dependency",),
        "domains": {
            "dependency": ALLOWED_DEPENDENCIES,
        },
    },
}

# ── Phase 3C-5C Detection Metrics Catalog ─────────────────────────────────────
DETECTION_METRIC_SPECIFICATIONS: Dict[str, Dict[str, Any]] = {
    "bsea_detection_signals_total": {
        "type": "counter",
        "help": "Total count of advisory detection signals generated in shadow or active mode.",
        "labels": ("rule_id", "severity", "mode"),
        "domains": {
            "rule_id": ALLOWED_DETECTION_RULES,
            "severity": ALLOWED_DETECTION_SEVERITIES,
            "mode": ALLOWED_DETECTION_MODES,
        },
    },
    "bsea_detection_rule_evaluations_total": {
        "type": "counter",
        "help": "Total count of detection rule evaluations by rule identifier and evaluation result.",
        "labels": ("rule_id", "result"),
        "domains": {
            "rule_id": ALLOWED_DETECTION_RULES,
            "result": ALLOWED_EVALUATION_RESULTS,
        },
    },
    "bsea_cloudtrail_reconciliation_total": {
        "type": "counter",
        "help": "Total count of application KMS to CloudTrail management event reconciliations by status.",
        "labels": ("status",),
        "domains": {
            "status": ALLOWED_CLOUDTRAIL_RECONCILIATION_STATUSES,
        },
    },
    "bsea_detection_engine_lag_seconds": {
        "type": "gauge",
        "help": "Current processing lag in seconds of the detection engine.",
        "labels": (),
        "domains": {},
    },
}

ALL_METRIC_SPECIFICATIONS: Dict[str, Dict[str, Any]] = {
    **METRIC_SPECIFICATIONS,
    **DETECTION_METRIC_SPECIFICATIONS,
}


# ── Thread-Safe In-Memory Metric Storage ──────────────────────────────────────
class MetricRegistry:
    """
    High-performance thread-safe Prometheus metrics registry.
    Enforces strict label domain validation and calculates compile-time cardinality bounds.
    """

    def __init__(self):
        self._lock = threading.Lock()
        # storage: {metric_name: {label_tuple: value_or_histogram_data}}
        self._counters: Dict[str, Dict[Tuple[Tuple[str, str], ...], float]] = {}
        self._gauges: Dict[str, Dict[Tuple[Tuple[str, str], ...], float]] = {}
        self._histograms: Dict[str, Dict[Tuple[Tuple[str, str], ...], Dict[str, Any]]] = {}

        for m_name, spec in ALL_METRIC_SPECIFICATIONS.items():
            if spec["type"] == "counter":
                self._counters[m_name] = {}
            elif spec["type"] == "gauge":
                self._gauges[m_name] = {}
            elif spec["type"] == "histogram":
                self._histograms[m_name] = {}

    def _validate_labels(self, metric_name: str, labels: Dict[str, str]) -> Tuple[Tuple[str, str], ...]:
        """
        Validates that provided labels strictly match the allowed schema and allowed finite values.
        Raises ValueError on unexpected labels or dynamic values (cardinality defense).
        """
        spec = ALL_METRIC_SPECIFICATIONS.get(metric_name)
        if not spec:
            raise ValueError(f"Unknown metric: {metric_name}")

        expected_label_keys = spec["labels"]
        if set(labels.keys()) != set(expected_label_keys):
            raise ValueError(
                f"Metric {metric_name} expects labels {expected_label_keys}, got {tuple(labels.keys())}"
            )

        domains = spec["domains"]
        sorted_items: List[Tuple[str, str]] = []
        for k in sorted(labels.keys()):
            v = str(labels[k])
            allowed_domain = domains.get(k)
            if allowed_domain is not None and v not in allowed_domain:
                raise ValueError(
                    f"Invalid value '{v}' for label '{k}' on metric '{metric_name}'. Allowed: {sorted(allowed_domain)}"
                )
            sorted_items.append((k, v))

        return tuple(sorted_items)

    def inc_counter(self, metric_name: str, labels: Optional[Dict[str, str]] = None, amount: float = 1.0) -> None:
        """Atomically increments a counter metric."""
        if amount < 0:
            raise ValueError("Counter increments must be non-negative")
        lbls = labels or {}
        key = self._validate_labels(metric_name, lbls)
        with self._lock:
            store = self._counters[metric_name]
            store[key] = store.get(key, 0.0) + amount

    def set_gauge(self, metric_name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Sets a gauge metric to a specific value."""
        lbls = labels or {}
        key = self._validate_labels(metric_name, lbls)
        with self._lock:
            store = self._gauges[metric_name]
            store[key] = float(value)

    def observe_histogram(self, metric_name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Records an observation in a histogram metric."""
        lbls = labels or {}
        key = self._validate_labels(metric_name, lbls)
        buckets = METRIC_SPECIFICATIONS[metric_name]["buckets"]
        val = float(value)

        with self._lock:
            store = self._histograms[metric_name]
            if key not in store:
                store[key] = {
                    "buckets": {b: 0 for b in buckets},
                    "sum": 0.0,
                    "count": 0,
                }
            h_data = store[key]
            h_data["sum"] += val
            h_data["count"] += 1
            for b in buckets:
                if val <= b:
                    h_data["buckets"][b] += 1

    def calculate_cardinality(self, include_detection: bool = False) -> Tuple[int, int]:
        """
        Calculates the theoretical upper bound of active time series across registered metrics.
        Returns (total_base_series, total_expanded_prometheus_series).
        When include_detection=False (default), strictly calculates Phase 3C-5B metrics (520 base / 1390 expanded).
        When include_detection=True, calculates combined 5B + 5C metrics (646 base / 1516 expanded).
        """
        target_specs = ALL_METRIC_SPECIFICATIONS if include_detection else METRIC_SPECIFICATIONS
        total_base = 0
        total_expanded = 0

        for m_name, spec in target_specs.items():
            labels = spec["labels"]
            domains = spec["domains"]
            if not labels:
                product = 1
            else:
                product = 1
                for lbl in labels:
                    product *= len(domains[lbl])

            total_base += product

            if spec["type"] == "histogram":
                num_bucket_lines = len(spec["buckets"]) + 3
                total_expanded += product * num_bucket_lines
            else:
                total_expanded += product

        return total_base, total_expanded

    def calculate_detection_cardinality(self) -> Tuple[int, int]:
        """
        Calculates theoretical upper bound for Phase 3C-5C detection metrics only.
        Mathematically enforces:
        bsea_detection_signals_total: 11 * 4 * 2 = 88
        bsea_detection_rule_evaluations_total: 11 * 3 = 33
        bsea_cloudtrail_reconciliation_total: 4
        bsea_detection_engine_lag_seconds: 1
        Total: 88 + 33 + 4 + 1 = 126 base series.
        """
        total_base = 0
        total_expanded = 0
        for m_name, spec in DETECTION_METRIC_SPECIFICATIONS.items():
            labels = spec["labels"]
            domains = spec["domains"]
            if not labels:
                product = 1
            else:
                product = 1
                for lbl in labels:
                    product *= len(domains[lbl])
            total_base += product
            total_expanded += product
        return total_base, total_expanded

    def generate_prometheus_text(self) -> str:
        """
        Serializes all registered metrics into valid Prometheus exposition format (version 0.0.4).
        """
        lines: List[str] = []

        with self._lock:
            for m_name, spec in sorted(ALL_METRIC_SPECIFICATIONS.items()):
                m_type = spec["type"]
                m_help = spec["help"]

                lines.append(f"# HELP {m_name} {m_help}")
                lines.append(f"# TYPE {m_name} {m_type}")

                if m_type == "counter":
                    store_c = self._counters[m_name]
                    if not store_c:
                        # Emit empty baseline if zero increments
                        lines.append(f"{m_name} 0")
                    else:
                        for label_tuple, val in sorted(store_c.items()):
                            lbl_str = ",".join(f'{k}="{v}"' for k, v in label_tuple)
                            if lbl_str:
                                lines.append(f"{m_name}{{{lbl_str}}} {val}")
                            else:
                                lines.append(f"{m_name} {val}")

                elif m_type == "gauge":
                    store_g = self._gauges[m_name]
                    if not store_g:
                        lines.append(f"{m_name} 0")
                    else:
                        for label_tuple, val in sorted(store_g.items()):
                            lbl_str = ",".join(f'{k}="{v}"' for k, v in label_tuple)
                            if lbl_str:
                                lines.append(f"{m_name}{{{lbl_str}}} {val}")
                            else:
                                lines.append(f"{m_name} {val}")

                elif m_type == "histogram":
                    store_h = self._histograms[m_name]
                    buckets = spec["buckets"]
                    if not store_h:
                        lines.append(f"{m_name}_count 0")
                        lines.append(f"{m_name}_sum 0")
                    else:
                        for label_tuple, h_data in sorted(store_h.items()):
                            base_lbl_str = ",".join(f'{k}="{v}"' for k, v in label_tuple)
                            prefix = f"{base_lbl_str}," if base_lbl_str else ""
                            # Emit bucket lines
                            for b in buckets:
                                lines.append(f'{m_name}_bucket{{{prefix}le="{b}"}} {h_data["buckets"][b]}')
                            lines.append(f'{m_name}_bucket{{{prefix}le="+Inf"}} {h_data["count"]}')
                            lines.append(f'{m_name}_sum{{{base_lbl_str}}} {round(h_data["sum"], 4)}')
                            lines.append(f'{m_name}_count{{{base_lbl_str}}} {h_data["count"]}')

        return "\n".join(lines) + "\n"


# ── Global Metrics Registry Singleton ─────────────────────────────────────────
metrics_registry = MetricRegistry()


# ── Helper Route Categorizer ──────────────────────────────────────────────────
def categorize_route(path: str) -> str:
    """
    Normalizes incoming request URL paths into strict, bounded endpoint_class values.
    Prevents cardinality explosion from path parameters (IDs).
    """
    p = path.strip().rstrip("/")
    if not p:
        return "other"

    if p == "/health/live":
        return "/health/live"
    if p == "/health/ready":
        return "/health/ready"

    # Candidate endpoints
    if p.startswith("/api/v1/candidate/auth/login"):
        return "/api/v1/candidate/auth/login"
    if p.startswith("/api/v1/candidate/auth/session") or p.startswith("/api/v1/candidate/auth/me"):
        return "/api/v1/candidate/auth/session"
    if p.startswith("/api/v1/candidate/exam/start"):
        return "/api/v1/candidate/exam/start"
    if p.startswith("/api/v1/candidate/exam/submit"):
        return "/api/v1/candidate/exam/submit"
    if p.startswith("/api/v1/candidate/exam/autosave"):
        return "/api/v1/candidate/exam/autosave"
    if "/candidate/questions/" in p:
        if "answer" in p:
            return "/api/v1/candidate/questions/answer"
        return "/api/v1/candidate/questions/get"

    # Administrative auth & MFA
    if p.startswith("/api/v1/auth/login"):
        return "/api/v1/auth/login"
    if p.startswith("/api/v1/auth/mfa"):
        return "/api/v1/auth/mfa/verify"

    # Exams
    if p.startswith("/api/v1/exams"):
        if "create" in p:
            return "/api/v1/exams/create"
        if p == "/api/v1/exams":
            return "/api/v1/exams/list"
        return "/api/v1/exams/detail"

    # Questions
    if p.startswith("/api/v1/questions"):
        if "assign" in p:
            return "/api/v1/questions/assign"
        if "review" in p or "approve" in p or "reject" in p:
            return "/api/v1/questions/review"
        return "/api/v1/questions/create"

    # Break-glass
    if p.startswith("/api/v1/break-glass"):
        if "approve" in p:
            return "/api/v1/break-glass/approve"
        if "activate" in p or "revoke" in p:
            return "/api/v1/break-glass/activate"
        return "/api/v1/break-glass/request"

    return "other"
