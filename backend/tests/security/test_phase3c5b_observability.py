"""
B-SEA Phase 3C-5B Authoritative Observability & Security Telemetry Test Suite
Complete Test Matrix: T01 – T20

Section Mandates:
1.  T01: Structured compact JSON application logging with mandatory and allowlisted fields.
2.  T02: Strict W3C traceparent parsing with 32 lowercase hex trace_id.
3.  T03: Malformed traceparent rejection and fallback generation.
4.  T04: All-zero trace_id rejection and replacement.
5.  T05: Request ID UUIDv4 format validation, preservation, and fallback generation.
6.  T06: IP address subnet masking (/24 for IPv4, /48 for IPv6, localhost).
7.  T07: Coarse User-Agent categorization without raw string leakage.
8.  T08: Tier-1 sensitive key detection and value redaction.
9.  T09: Tier-2 value regex pattern detection (JWTs, PEM private keys, Bearer tokens).
10. T10: Tier-3 examination content protection (question text, options, answer keys, candidate responses).
11. T11: Recursive nested dictionary and list structure redaction.
12. T12: 16-metric approved catalog conformance (names, types, label sets).
13. T13: Strict label-domain validation preventing dynamic label cardinality injection.
14. T14: Mathematical cardinality proof (base <= 530, expanded <= 1400).
15. T15: Prometheus text formatting and histogram expansion (_bucket, +Inf, _sum, _count).
16. T16: Pre-shared key authentication for /metrics endpoint (X-BSEA-Metrics-Key).
17. T17: Zero-leak verification of /metrics response (no PII, credentials, or exam content).
18. T18: Zero-dependency isolation of /health/live probe (immune to DB/Redis/KMS outages).
19. T19: Sealer operational telemetry isolation (observational only, non-fatal).
20. T20: Telemetry engine failure isolation (metrics/logging exceptions never abort requests or sealer).
"""
import io
import json
import logging
import re
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.core.logging import (
    BSEAJsonFormatter,
    CURRENT_AUDIT_LOG_ID,
    CURRENT_REQUEST_ID,
    CURRENT_TRACE_ID,
    categorize_user_agent,
    parse_or_generate_request_id,
    parse_or_generate_trace_id,
    redact_data,
    sanitize_client_ip,
)
from app.core.metrics import (
    ALLOWED_ACTOR_ROLES,
    ALLOWED_AUDIT_INGESTION_MODES,
    ALLOWED_AUTH_FAILURE_REASONS,
    ALLOWED_AUTHZ_REASONS,
    ALLOWED_BREAK_GLASS_ACTIVATION_STATUSES,
    ALLOWED_BREAK_GLASS_STATUSES,
    ALLOWED_DEPENDENCIES,
    ALLOWED_ENDPOINT_CLASSES,
    ALLOWED_METHODS,
    ALLOWED_QUESTION_GRANT_DENIAL_REASONS,
    ALLOWED_RESOURCE_TYPES,
    ALLOWED_SEALER_DURATION_STATUSES,
    ALLOWED_SEALER_STATUSES,
    ALLOWED_STATUS_CLASSES,
    ALLOWED_VERIFIER_RESULTS,
    METRIC_SPECIFICATIONS,
    MetricRegistry,
    metrics_registry,
)
from app.main import app

settings = get_settings()


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


# ── T01: Structured JSON Application Logging ─────────────────────────────────
def test_T01_structured_json_logging():
    """Verify single-line compact JSON logs with required and contextual fields."""
    formatter = BSEAJsonFormatter(environment="test", app_version="1.0.0")
    logger = logging.getLogger("bsea.test.t01")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    token_trace = CURRENT_TRACE_ID.set("a" * 32)
    token_req = CURRENT_REQUEST_ID.set(str(uuid.uuid4()))
    token_audit = CURRENT_AUDIT_LOG_ID.set(42)

    try:
        logger.info(
            "User authenticated successfully",
            extra={
                "actor_id": "usr-123",
                "actor_role": "ADMIN",
                "resource_type": "USER",
                "resource_id": "usr-123",
                "event_type": "AUTH_LOGIN",
                "action": "LOGIN",
                "result": "SUCCESS",
                "latency_ms": 45.2,
                "client_ip_masked": "192.168.1.0/24",
                "user_agent_category": "STANDARD_BROWSER",
                "unauthorized_dynamic_key": "should_be_dropped",
            },
        )
    finally:
        CURRENT_TRACE_ID.reset(token_trace)
        CURRENT_REQUEST_ID.reset(token_req)
        CURRENT_AUDIT_LOG_ID.reset(token_audit)
        logger.removeHandler(handler)

    output = stream.getvalue().strip()
    assert "\n" not in output, "JSON log must be a single compact line"
    data = json.loads(output)

    # Mandatory fields
    for field in ["timestamp", "level", "service", "environment", "logger", "message", "trace_id", "request_id"]:
        assert field in data, f"Mandatory field '{field}' missing from JSON log"

    assert data["service"] == "bsea-backend"
    assert data["environment"] == "test"
    assert data["level"] == "INFO"
    assert data["trace_id"] == "a" * 32
    assert data["audit_log_id"] == 42
    assert data["actor_id"] == "usr-123"
    assert data["actor_role"] == "ADMIN"
    assert data["client_ip_masked"] == "192.168.1.0/24"
    assert data["user_agent_category"] == "STANDARD_BROWSER"
    assert "unauthorized_dynamic_key" not in data, "Non-allowlisted extra keys must be dropped"


# ── T02: Strict W3C Traceparent Parsing ──────────────────────────────────────
def test_T02_strict_w3c_traceparent():
    """Verify valid 32-hex trace_id parsed correctly from W3C traceparent header."""
    valid_header = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    trace_id = parse_or_generate_trace_id(valid_header)
    assert trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert len(trace_id) == 32
    assert re.fullmatch(r"^[0-9a-f]{32}$", trace_id) is not None


# ── T03: Malformed Traceparent Handling ───────────────────────────────────────
def test_T03_malformed_traceparent_handling():
    """Verify malformed traceparent headers fallback to valid 32-hex token."""
    malformed_headers = [
        None,
        "",
        "not-a-traceparent",
        "00-4bf92f3577b34da6a3ce929d0e0e4736",  # missing fields
        "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",  # invalid version ff
        "00-4bf92f3577b34da6a3ce929d0e0e47zz-00f067aa0ba902b7-01",  # non-hex
        "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",  # uppercase hex
    ]
    for header in malformed_headers:
        trace_id = parse_or_generate_trace_id(header)
        assert len(trace_id) == 32, f"Failed for header: {header}"
        assert re.fullmatch(r"^[0-9a-f]{32}$", trace_id) is not None


# ── T04: All-Zero Trace ID Rejection ─────────────────────────────────────────
def test_T04_all_zero_trace_id_rejected():
    """Verify all-zero trace_id is rejected by W3C specification and replaced."""
    zero_header = "00-00000000000000000000000000000000-00f067aa0ba902b7-01"
    trace_id = parse_or_generate_trace_id(zero_header)
    assert trace_id != "00000000000000000000000000000000"
    assert len(trace_id) == 32
    assert re.fullmatch(r"^[0-9a-f]{32}$", trace_id) is not None


# ── T05: Request ID UUIDv4 Propagation ───────────────────────────────────────
def test_T05_request_id_uuidv4_propagation():
    """Verify valid UUIDv4 is preserved; invalid or missing generates fresh UUIDv4."""
    existing_uuid = "9f8b1c2d-3e4f-4a5b-8c6d-7e8f9a0b1c2d"
    parsed = parse_or_generate_request_id(existing_uuid)
    assert parsed == existing_uuid

    for bad in [None, "", "invalid-uuid", "12345", "not-a-uuid-string"]:
        gen = parse_or_generate_request_id(bad)
        parsed_uuid = uuid.UUID(gen, version=4)
        assert str(parsed_uuid) == gen


# ── T06: IP Subnet Masking ───────────────────────────────────────────────────
def test_T06_ip_subnet_masking():
    """Verify client IP addresses are masked to /24 (IPv4) and /48 (IPv6)."""
    assert sanitize_client_ip("192.168.1.105") == "192.168.1.0/24"
    assert sanitize_client_ip("10.50.200.44") == "10.50.200.0/24"
    assert sanitize_client_ip("127.0.0.1") == "127.0.0.0/24"
    assert sanitize_client_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == "2001:db8:85a3::/48"
    assert sanitize_client_ip("invalid-ip-string") == "0.0.0.0/0"
    assert sanitize_client_ip(None) == "0.0.0.0/0"


# ── T07: User-Agent Categorization ───────────────────────────────────────────
def test_T07_user_agent_categorization():
    """Verify User-Agent mapped to coarse categories without raw string leakage."""
    assert categorize_user_agent("B-SEA-SecureExamBrowser/2.1 (Windows NT 10.0)") == "CBT_SECURE_BROWSER"
    assert categorize_user_agent("SafeExamBrowser/3.3.0") == "CBT_SECURE_BROWSER"
    assert categorize_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36") == "STANDARD_BROWSER"
    assert categorize_user_agent("curl/7.68.0") == "CLI_TOOL"
    assert categorize_user_agent("python-requests/2.28.1") == "CLI_TOOL"
    assert categorize_user_agent("") == "UNKNOWN"
    assert categorize_user_agent(None) == "UNKNOWN"


# ── T08: Tier-1 Sensitive Key Redaction ──────────────────────────────────────
def test_T08_tier1_sensitive_key_redaction():
    """Verify sensitive dictionary keys are redacted before emission."""
    sensitive_dict = {
        "username": "candidate_1",
        "password": "SuperSecretPassword123!",
        "token": "secret-session-token",
        "jwt": "eyJhbGciOi...",
        "api_key": "bsea_live_key_9988",
        "private_key": "secret_key_material",
        "dek": "raw_dek_bytes",
        "kek": "raw_kek_bytes",
        "cookie": "session_cookie_value",
        "authorization": "Bearer token123",
    }
    redacted = redact_data(sensitive_dict)
    assert redacted["username"] == "candidate_1"
    for key in ["password", "token", "jwt", "api_key", "private_key", "dek", "kek", "cookie", "authorization"]:
        assert redacted[key] == "[REDACTED]", f"Key '{key}' was not redacted"


# ── T09: Tier-2 Sensitive Value Regex Redaction ──────────────────────────────
def test_T09_tier2_value_regex_redaction():
    """Verify sensitive value regexes (JWTs, PEM keys, Bearer) are caught under safe keys."""
    innocent_dict = {
        "metadata_note": "Here is token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgN within text",
        "cert_field": "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----",
        "auth_detail": "Bearer mysecrettoken1234567890",
    }
    redacted = redact_data(innocent_dict)
    assert "[REDACTED_JWT]" in redacted["metadata_note"]
    assert "[REDACTED_PRIVATE_KEY]" in redacted["cert_field"]
    assert "[REDACTED_BEARER]" in redacted["auth_detail"]


# ── T10: Tier-3 Examination Content Protection ───────────────────────────────
def test_T10_tier3_exam_content_protection():
    """Verify question text, options, answer keys, candidate responses are protected."""
    exam_dict = {
        "question_text": "What is the primary function of the thymus gland?",
        "options": ["T-cell maturation", "B-cell maturation", "Insulin secretion"],
        "correct_option": "A",
        "answer_key": "A",
        "candidate_response": "T-cell maturation",
        "exam_plaintext": "Plaintext question bank item 42",
        "encrypted_payload": "enc_payload_bytes",
    }
    redacted = redact_data(exam_dict)
    for key in ["question_text", "options", "correct_option", "answer_key", "candidate_response", "exam_plaintext", "encrypted_payload"]:
        assert redacted[key] == "[EXAM_CONTENT_REDACTED]", f"Exam content key '{key}' was not protected"


# ── T11: Recursive Nested Structure Redaction ────────────────────────────────
def test_T11_nested_structure_redaction():
    """Verify deeply nested dicts and lists are recursively traversed and redacted."""
    deep_struct = {
        "batch_id": "b-100",
        "items": [
            {
                "user": {
                    "name": "Operator A",
                    "password": "PlaintextPassword!",
                    "auth_headers": ["Bearer mysecrettoken12345", "innocent_string"],
                },
                "questions": [
                    {
                        "question_id": "q-1",
                        "question_text": "Classified question text here",
                        "nested_data": {"correct_option": "C"},
                    }
                ],
            }
        ],
    }
    redacted = redact_data(deep_struct)
    user = redacted["items"][0]["user"]
    assert user["password"] == "[REDACTED]"
    assert user["auth_headers"][0] == "[REDACTED_BEARER]"
    assert user["auth_headers"][1] == "innocent_string"

    q = redacted["items"][0]["questions"][0]
    assert q["question_text"] == "[EXAM_CONTENT_REDACTED]"
    assert q["nested_data"]["correct_option"] == "[EXAM_CONTENT_REDACTED]"


# ── T12: Metric Catalog Conformance ──────────────────────────────────────────
def test_T12_metric_catalog_conformance():
    """Verify all 16 approved metrics exist with approved types and exact label domains."""
    expected_metrics = {
        "bsea_http_requests_total": ("counter", ("endpoint_class", "method", "status_class")),
        "bsea_http_request_duration_seconds": ("histogram", ("endpoint_class", "method")),
        "bsea_security_auth_failures_total": ("counter", ("reason", "actor_role")),
        "bsea_security_authz_denials_total": ("counter", ("resource_type", "reason")),
        "bsea_security_rate_limit_rejections_total": ("counter", ("endpoint_class",)),
        "bsea_security_question_grant_denials_total": ("counter", ("reason",)),
        "bsea_security_break_glass_requests_total": ("counter", ("status",)),
        "bsea_security_break_glass_activations_total": ("counter", ("status",)),
        "bsea_audit_ingestion_failures_total": ("counter", ("mode",)),
        "bsea_audit_sealer_cycles_total": ("counter", ("status",)),
        "bsea_audit_sealer_cycle_duration_seconds": ("histogram", ("status",)),
        "bsea_audit_sealer_backlog_records": ("gauge", ()),
        "bsea_audit_sealer_last_epoch_id": ("gauge", ()),
        "bsea_audit_verifier_status": ("gauge", ("result",)),
        "bsea_audit_poison_events_quarantined_total": ("gauge", ()),
        "bsea_dependency_failures_total": ("counter", ("dependency",)),
    }
    assert len(METRIC_SPECIFICATIONS) == 16
    for name, (mtype, labels) in expected_metrics.items():
        assert name in METRIC_SPECIFICATIONS, f"Metric '{name}' not found in specifications"
        spec = METRIC_SPECIFICATIONS[name]
        assert spec["type"] == mtype, f"Metric '{name}' type mismatch"
        assert spec["labels"] == labels, f"Metric '{name}' labels mismatch"


# ── T13: Strict Label-Domain Validation ──────────────────────────────────────
def test_T13_strict_label_domain_validation():
    """Verify non-allowlisted label values are rejected with ValueError."""
    reg = MetricRegistry()
    # Invalid endpoint class
    with pytest.raises(ValueError, match="Invalid value 'UNAUTHORIZED_CLASS' for label 'endpoint_class'"):
        reg.inc_counter(
            "bsea_http_requests_total",
            {"endpoint_class": "UNAUTHORIZED_CLASS", "method": "GET", "status_class": "2xx"},
        )

    # Invalid sealer status
    with pytest.raises(ValueError, match="Invalid value 'random_status' for label 'status'"):
        reg.inc_counter("bsea_audit_sealer_cycles_total", {"status": "random_status"})

    # Dynamic injected path as label
    with pytest.raises(ValueError):
        reg.observe_histogram(
            "bsea_http_request_duration_seconds",
            0.15,
            {"endpoint_class": "/api/v1/users/12345/dynamic", "method": "GET"},
        )


# ── T14: Metric Cardinality Invariants ───────────────────────────────────────
def test_T14_metric_cardinality_invariants():
    """Mathematically verify maximum base time series <= 530 and expanded <= 1400."""
    reg = MetricRegistry()
    base_cardinality, expanded_cardinality = reg.calculate_cardinality()

    assert base_cardinality <= 530, f"Base cardinality {base_cardinality} exceeds ceiling 530"
    assert expanded_cardinality <= 1400, f"Expanded cardinality {expanded_cardinality} exceeds ceiling 1400"
    assert base_cardinality == 520, f"Expected exactly 520 base series, calculated {base_cardinality}"
    assert expanded_cardinality == 1390, f"Expected exactly 1390 expanded series, calculated {expanded_cardinality}"


# ── T15: Histogram Expansion Correctness ─────────────────────────────────────
def test_T15_histogram_expansion_correctness():
    """Verify Prometheus text format generates bucket lines, +Inf, _sum, and _count."""
    reg = MetricRegistry()
    reg.observe_histogram(
        "bsea_http_request_duration_seconds",
        0.045,
        {"endpoint_class": "/health/live", "method": "GET"},
    )
    reg.observe_histogram(
        "bsea_http_request_duration_seconds",
        1.2,
        {"endpoint_class": "/health/live", "method": "GET"},
    )

    output = reg.generate_prometheus_text()
    assert "# HELP bsea_http_request_duration_seconds" in output
    assert "# TYPE bsea_http_request_duration_seconds histogram" in output

    # Check buckets
    assert 'bsea_http_request_duration_seconds_bucket{endpoint_class="/health/live",method="GET",le="0.05"} 1' in output
    assert 'bsea_http_request_duration_seconds_bucket{endpoint_class="/health/live",method="GET",le="+Inf"} 2' in output
    assert 'bsea_http_request_duration_seconds_sum{endpoint_class="/health/live",method="GET"} 1.245' in output
    assert 'bsea_http_request_duration_seconds_count{endpoint_class="/health/live",method="GET"} 2' in output


# ── T16: Metrics Endpoint Authentication ─────────────────────────────────────
def test_T16_metrics_endpoint_authentication(client):
    """Verify /metrics requires X-BSEA-Metrics-Key header and returns HTTP 403 on missing/invalid."""
    # 1. No header -> 403 Forbidden
    res_no_auth = client.get("/metrics")
    assert res_no_auth.status_code == 403
    assert res_no_auth.json()["detail"] == "Forbidden: Invalid or missing metrics authorization"

    # 2. Invalid header -> 403 Forbidden
    res_bad_auth = client.get("/metrics", headers={"X-BSEA-Metrics-Key": "invalid-secret-key"})
    assert res_bad_auth.status_code == 403

    # 3. Valid header -> 200 OK
    valid_key = getattr(settings, "metrics_scraper_key", "bsea-metrics-scraper-secret-local")
    res_ok = client.get("/metrics", headers={"X-BSEA-Metrics-Key": valid_key})
    assert res_ok.status_code == 200
    assert "text/plain" in res_ok.headers["content-type"]
    assert "# HELP bsea_http_requests_total" in res_ok.text


# ── T17: Metrics Endpoint Zero-Leak ──────────────────────────────────────────
def test_T17_metrics_endpoint_zero_leak(client):
    """Verify /metrics output contains zero question text, answers, candidate PII, or secrets."""
    valid_key = getattr(settings, "metrics_scraper_key", "bsea-metrics-scraper-secret-local")
    res = client.get("/metrics", headers={"X-BSEA-Metrics-Key": valid_key})
    assert res.status_code == 200
    body = res.text

    forbidden_strings = [
        "BSeaDemo@2026",
        "SuperSecretPassword",
        "BEGIN RSA PRIVATE KEY",
        "eyJhbGciOi",
        "candidate_response",
        "question_text",
        "BSEA-2026-DEMO-001",
        "192.168.1.105",
    ]
    for forbidden in forbidden_strings:
        assert forbidden not in body, f"Forbidden sensitive string '{forbidden}' leaked in /metrics"


# ── T18: Health/Live Zero-Dependency Isolation ────────────────────────────────
def test_T18_health_live_zero_dependency(client):
    """Verify /health/live succeeds even when database, Redis, and KMS are unavailable."""
    with patch("app.api.v1.health.engine", None), \
         patch("app.api.v1.health.check_redis_health", side_effect=RuntimeError("Redis down")), \
         patch("app.api.v1.health.get_kms", side_effect=RuntimeError("KMS down")):

        res = client.get("/health/live")
        assert res.status_code == 200
        payload = res.json()
        assert payload["status"] == "alive"
        assert payload["app"] == settings.app_name


# ── T19: Sealer Telemetry Isolation ──────────────────────────────────────────
@pytest.mark.asyncio
async def test_T19_sealer_telemetry_isolation():
    """Verify sealer operational telemetry updates safely without altering transactions or locks."""
    from app.modules.audit.sealer import AuditSealer, SealerCycleResult

    mock_engine = MagicMock()
    sealer = AuditSealer(mock_engine)

    # 1. Test locked state telemetry
    with patch.object(sealer, "acquire_leadership", new=AsyncMock(return_value=False)):
        res = await sealer.run_once()
        assert res.status == "LOCKED"
        # Confirm counter incremented for 'locked'
        reg_counter = metrics_registry._counters.get("bsea_audit_sealer_cycles_total", {})
        assert reg_counter.get((("status", "locked"),), 0) >= 1

    # 2. Test normal cycle telemetry
    with patch.object(sealer, "acquire_leadership", new=AsyncMock(return_value=True)),          patch.object(sealer, "release_leadership", new=AsyncMock(return_value=True)),          patch.object(sealer, "incorporate_unsealed_events", new=AsyncMock(return_value=0)),          patch.object(sealer, "evaluate_and_seal_epoch", new=AsyncMock(return_value=None)):

        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()
        mock_conn.commit = AsyncMock()
        mock_engine.connect.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_engine.connect.return_value.__aexit__ = AsyncMock(return_value=None)

        res = await sealer.run_once()
        assert res.status == "NOOP"
        reg_counter = metrics_registry._counters.get("bsea_audit_sealer_cycles_total", {})
        assert reg_counter.get((("status", "noop"),), 0) >= 1


# ── T20: Telemetry Failure Isolation ─────────────────────────────────────────
def test_T20_telemetry_failure_isolation(client):
    """Verify failures in logging or metrics engines do not fail requests."""
    # Simulate error in metrics recording
    with patch.object(metrics_registry, "inc_counter", side_effect=RuntimeError("Metrics storage failed")):
        # Request should complete normally and return 200
        res = client.get("/health/live")
        assert res.status_code == 200
        assert res.json()["status"] == "alive"
