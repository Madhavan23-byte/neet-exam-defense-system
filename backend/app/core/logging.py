"""
B-SEA Production Observability Foundation — Structured JSON Logging & Centralized Redaction
Phase 3C-5B Implementation conforming to BSEA_PHASE3C_5B_ARCHITECTURE_REVIEW_REV02.md
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import secrets
import sys
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple, Union

# ── Context Variables for Distributed Tracing ────────────────────────────────
CURRENT_TRACE_ID: ContextVar[str] = ContextVar("current_trace_id", default="00000000000000000000000000000000")
CURRENT_REQUEST_ID: ContextVar[str] = ContextVar("current_request_id", default="")
CURRENT_AUDIT_LOG_ID: ContextVar[Optional[str]] = ContextVar("current_audit_log_id", default=None)

# ── W3C Trace Context Regex (Strict 32 Lowercase Hex) ─────────────────────────
W3C_TRACEPARENT_PATTERN = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$")
VALID_TRACE_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
ALL_ZERO_TRACE_ID = "00000000000000000000000000000000"


def parse_or_generate_trace_id(header_val: Optional[str]) -> str:
    """
    Extracts and validates a W3C trace_id from traceparent header.
    Must be exactly 32 lowercase hex characters and NOT all zeros.
    Generates a fresh secrets.token_hex(16) if missing, malformed, or all zeros.
    """
    if header_val:
        m = W3C_TRACEPARENT_PATTERN.match(header_val.strip())
        if m:
            tid = m.group(1).lower()
            if tid != ALL_ZERO_TRACE_ID:
                return tid
        else:
            clean_tid = header_val.strip().lower()
            if VALID_TRACE_ID_PATTERN.match(clean_tid) and clean_tid != ALL_ZERO_TRACE_ID:
                return clean_tid
    return secrets.token_hex(16)


def parse_or_generate_request_id(header_val: Optional[str]) -> str:
    """
    Extracts and validates a UUIDv4 request_id from X-Request-ID header.
    Generates a fresh UUIDv4 if missing or invalid.
    """
    if header_val:
        try:
            val = uuid.UUID(header_val.strip(), version=4)
            return str(val)
        except Exception:
            pass
    return str(uuid.uuid4())


# ── Privacy & Data Minimization Helpers ───────────────────────────────────────
def sanitize_client_ip(ip_str: Optional[str]) -> Optional[str]:
    """
    Subnet-masks client IP addresses in compliance with B-SEA data minimization:
    - IPv4: host octet masked to zero (e.g., 198.51.100.42 -> 198.51.100.0/24)
    - IPv6: last 80 bits masked to zero (e.g., 2001:db8:85a3:: -> 2001:db8:85a3::/48)
    - Localhost/private loopback preserved
    """
    if not ip_str or ip_str in ("unknown", "testclient"):
        return "0.0.0.0/0"

    clean_ip = ip_str.split(",")[0].strip()
    if clean_ip in ("::1", "localhost"):
        return "127.0.0.0/24"

    try:
        ip_obj = ipaddress.ip_address(clean_ip)
        if ip_obj.version == 4:
            net = ipaddress.ip_network(f"{clean_ip}/24", strict=False)
            return str(net)
        else:
            net = ipaddress.ip_network(f"{clean_ip}/48", strict=False)
            return str(net)
    except Exception:
        return "0.0.0.0/0"


def categorize_user_agent(ua_str: Optional[str]) -> str:
    """
    Maps raw User-Agent strings to coarse non-identifying categories.
    Raw strings are discarded to prevent client fingerprinting leaks.
    """
    if not ua_str or not isinstance(ua_str, str):
        return "UNKNOWN"

    ua_lower = ua_str.lower()
    if any(k in ua_lower for k in ("b-sea", "safeexambrowser", "securebrowser", "cbt")):
        return "CBT_SECURE_BROWSER"
    if any(k in ua_lower for k in ("curl", "httpx", "postman", "python", "requests", "wget")):
        return "CLI_TOOL"
    if any(k in ua_lower for k in ("bot", "crawler", "spider", "scraper")):
        return "BOT_CRAWLER"
    if "mobile" in ua_lower or "android" in ua_lower or "iphone" in ua_lower:
        return "MOBILE_BROWSER"
    if any(k in ua_lower for k in ("mozilla", "chrome", "safari", "firefox", "edge")):
        return "STANDARD_BROWSER"
    return "UNKNOWN"


# ── Centralized Three-Tier Redaction Engine ───────────────────────────────────
SENSITIVE_KEY_SUBSTRINGS = (
    "password",
    "passwd",
    "secret",
    "token",
    "jwt",
    "cookie",
    "authorization",
    "apikey",
    "privatekey",
    "dek",
    "kek",
    "aeskey",
    "sessionkey",
    "dbpassword",
    "redispassword",
    "awssecretaccesskey",
)

EXAM_KEY_SUBSTRINGS = (
    "questiontext",
    "question_text",
    "questioncontent",
    "question_content",
    "answerkey",
    "answer_key",
    "correctoption",
    "correct_option",
    "correctanswer",
    "correct_answer",
    "candidateanswer",
    "candidate_answer",
    "candidateresponse",
    "candidate_response",
    "examplaintext",
    "exam_plaintext",
    "encryptedpayload",
    "encrypted_payload",
    "exambody",
    "options",
)

REGEX_JWT = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*")
REGEX_ARGON2 = re.compile(r"\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+")
REGEX_PEM_KEY = re.compile(r"-----BEGIN\s+(?:[A-Z\s]+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:[A-Z\s]+)?PRIVATE\s+KEY-----")
REGEX_DB_URI = re.compile(r"://([^:]+):([^@]+)@")
REGEX_AWS_KEY = re.compile(r'''(?i)(?:aws_secret_access_key|secret_key)\s*[:=]\s*['"][A-Za-z0-9/+=]{40}['"]''')


def _scrub_string_value(val: str) -> str:
    """Applies Tier 2 regex pattern scrubbing to raw string content."""
    if not val:
        return val

    if "PRIVATE KEY" in val:
        val = REGEX_PEM_KEY.sub("[REDACTED_PRIVATE_KEY]", val)

    if "eyJ" in val:
        val = re.sub(r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*", "[REDACTED_JWT]", val)
    if "bearer" in val.lower():
        val = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9-_.+=/]+", "[REDACTED_BEARER]", val)

    if "$argon2id$" in val:
        val = REGEX_ARGON2.sub("[REDACTED_ARGON2_HASH]", val)

    if "://" in val and "@" in val:
        val = REGEX_DB_URI.sub(r"://\1:[REDACTED_PASSWORD]@", val)

    if "secret" in val.lower():
        val = REGEX_AWS_KEY.sub('aws_secret_access_key="[REDACTED_AWS_SECRET]"', val)

    return val


def redact_data(obj: Any) -> Any:
    """
    Centralized recursive redaction engine (Tiers 1, 2, and 3):
    - Dict keys normalized and matched against sensitive & exam boundaries
    - String values scrubbed with high-precision regexes
    - Nested dicts, lists, and tuples sanitized recursively
    """
    if isinstance(obj, dict):
        cleaned = {}
        for k, v in obj.items():
            k_str = str(k)
            k_norm = k_str.lower().replace("_", "").replace("-", "")
            if any(term in k_norm for term in EXAM_KEY_SUBSTRINGS):
                cleaned[k_str] = "[EXAM_CONTENT_REDACTED]"
            elif any(term in k_norm for term in SENSITIVE_KEY_SUBSTRINGS):
                cleaned[k_str] = "[REDACTED]"
            else:
                cleaned[k_str] = redact_data(v)
        return cleaned

    elif isinstance(obj, list):
        return [redact_data(item) for item in obj]

    elif isinstance(obj, tuple):
        return tuple(redact_data(item) for item in obj)

    elif isinstance(obj, str):
        return _scrub_string_value(obj)

    return obj


# ── Structured JSON Log Formatter ─────────────────────────────────────────────
ALLOWED_LOG_FIELDS = {
    "timestamp",
    "level",
    "service",
    "environment",
    "logger",
    "message",
    "trace_id",
    "request_id",
    "actor_id",
    "actor_role",
    "resource_type",
    "resource_id",
    "event_type",
    "action",
    "result",
    "latency_ms",
    "error_code",
    "exception_type",
    "audit_log_id",
    "client_ip_masked",
    "user_agent_category",
    "deployment_version",
}


class BSEAJsonFormatter(logging.Formatter):
    """
    High-performance single-line compact JSON log formatter.
    Enforces strict field allowlist, injects W3C trace context,
    and applies centralized three-tier redaction before serialization.
    """

    def __init__(self, service: str = "bsea-backend", environment: str = "production", deployment_version: str = "1.0.0", app_version: Optional[str] = None):
        super().__init__()
        self.service = service
        self.environment = environment
        self.deployment_version = app_version or deployment_version
        super().__init__()
        self.service = service
        self.environment = environment
        self.deployment_version = deployment_version

    def format(self, record: logging.LogRecord) -> str:
        try:
            now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            trace_id = getattr(record, "trace_id", None) or CURRENT_TRACE_ID.get()
            if not VALID_TRACE_ID_PATTERN.match(trace_id) or trace_id == ALL_ZERO_TRACE_ID:
                trace_id = parse_or_generate_trace_id(trace_id)

            request_id = getattr(record, "request_id", None) or CURRENT_REQUEST_ID.get()
            if not request_id:
                request_id = parse_or_generate_request_id(None)

            audit_log_id = getattr(record, "audit_log_id", None) or CURRENT_AUDIT_LOG_ID.get()

            raw_message = record.getMessage()
            safe_message = _scrub_string_value(raw_message)

            payload: Dict[str, Any] = {
                "timestamp": now_utc,
                "level": record.levelname,
                "service": self.service,
                "environment": self.environment,
                "logger": record.name,
                "message": safe_message,
                "trace_id": trace_id,
                "request_id": request_id,
            }

            for field in (
                "actor_id",
                "actor_role",
                "resource_type",
                "resource_id",
                "event_type",
                "action",
                "result",
                "latency_ms",
                "error_code",
                "exception_type",
                "client_ip_masked",
                "user_agent_category",
            ):
                val = getattr(record, field, None)
                if val is not None:
                    payload[field] = redact_data(val)

            if audit_log_id is not None:
                payload["audit_log_id"] = audit_log_id

            payload["deployment_version"] = self.deployment_version

            if record.exc_info and record.exc_info[0]:
                payload["exception_type"] = record.exc_info[0].__name__
                if "error_code" not in payload:
                    payload["error_code"] = record.exc_info[0].__name__

            return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)

        except Exception as e:
            fallback = {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "level": "ERROR",
                "service": self.service,
                "environment": self.environment,
                "logger": "bsea.logging.fallback",
                "message": f"Log formatting fault: {str(e)}",
                "trace_id": "00000000000000000000000000000000",
                "request_id": str(uuid.uuid4()),
                "error_code": "FORMATTER_EXCEPTION",
            }
            return json.dumps(fallback, separators=(",", ":"))


def setup_logging(environment: str = "production", level: str = "INFO", app_version: str = "1.0.0") -> None:
    """
    Initializes root and application loggers with BSEAJsonFormatter attached to sys.stdout.
    Default level is INFO; DEBUG is disabled by default in production.
    """
    log_level = getattr(logging, level.upper(), logging.INFO)
    if environment.lower() == "production" and log_level == logging.DEBUG:
        log_level = logging.INFO

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    for h in list(root_logger.handlers):
        root_logger.removeHandler(h)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(log_level)
    formatter = BSEAJsonFormatter(
        service="bsea-backend",
        environment=environment,
        deployment_version=app_version,
    )
    handler.setFormatter(formatter)
    root_logger.addHandler(handler)

    bsea_logger = logging.getLogger("bsea")
    bsea_logger.setLevel(log_level)
