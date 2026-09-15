"""
B-SEA Phase 3C-5C Detection & Correlation Foundation — Event Normalizer
Conforming to BSEA_PHASE3C_5C_DETECTION_CORRELATION_ARCHITECTURE_REVIEW_REV03.md
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional, Union
import uuid

from app.modules.detection.models import SecurityEventNormalized

EXAM_CONTENT_FORBIDDEN_KEYS = (
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
    "sessionkey",
    "session_key",
    "dek",
    "kek",
    "privatekey",
    "private_key",
    "password",
    "jwt",
    "token",
)


def ensure_utc(dt: Optional[Union[datetime, str]]) -> datetime:
    """Ensures timestamp is a UTC timezone-aware datetime object."""
    if dt is None:
        return datetime.now(timezone.utc)
    if isinstance(dt, str):
        try:
            parsed = datetime.fromisoformat(dt)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except Exception:
            return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def sanitize_metadata(meta: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Sanitizes event metadata by stripping any sensitive exam content,
    plaintext question bodies, answers, session keys, or raw secrets.
    """
    if not meta or not isinstance(meta, dict):
        return {}

    cleaned: Dict[str, Any] = {}
    for k, v in meta.items():
        k_norm = str(k).lower().replace("_", "").replace("-", "")
        if any(forbidden in k_norm for forbidden in EXAM_CONTENT_FORBIDDEN_KEYS):
            continue  # Exclude completely from detection state

        if isinstance(v, dict):
            cleaned[k] = sanitize_metadata(v)
        elif isinstance(v, list):
            cleaned[k] = [
                sanitize_metadata(item) if isinstance(item, dict) else str(item)
                for item in v
            ]
        elif isinstance(v, (int, float, bool, str)) or v is None:
            cleaned[k] = v
        else:
            cleaned[k] = str(v)

    return cleaned


class EventNormalizer:
    """
    Deterministic normalizer mapping disparate B-SEA security events
    into the canonical SecurityEventNormalized schema.
    """

    @staticmethod
    def normalize_audit_log(entry: Any) -> SecurityEventNormalized:
        """
        Normalizes an AuditLog model instance or audit log dictionary.
        """
        # Handle SQLAlchemy AuditLog model or dict
        if hasattr(entry, "id"):
            event_id = str(entry.id)
            event_type = str(entry.event_type)
            timestamp = ensure_utc(getattr(entry, "created_at", None) or getattr(entry, "timestamp", None))
            raw_result = getattr(entry, "result", "SUCCESS")
            result_str = raw_result.value if isinstance(raw_result, Enum) else str(raw_result)
            actor_id = getattr(entry, "actor_id", None)
            actor_role = getattr(entry, "actor_role", None)
            resource_type = getattr(entry, "resource_type", None)
            resource_id = getattr(entry, "resource_id", None)
            action = getattr(entry, "action", None)
            ip_hash = getattr(entry, "ip_hash", None)
            device_id = getattr(entry, "device_id", None)
            trace_id = getattr(entry, "trace_id", None)
            kms_request_id = getattr(entry, "kms_request_id", None)
            raw_meta = getattr(entry, "event_metadata", {}) or {}
        else:
            event_id = str(entry.get("id") or entry.get("event_id") or uuid.uuid4())
            event_type = str(entry.get("event_type", "UNKNOWN"))
            timestamp = ensure_utc(entry.get("created_at") or entry.get("timestamp"))
            raw_result = entry.get("result", "SUCCESS")
            result_str = raw_result.value if isinstance(raw_result, Enum) else str(raw_result)
            actor_id = entry.get("actor_id")
            actor_role = entry.get("actor_role")
            resource_type = entry.get("resource_type")
            resource_id = entry.get("resource_id")
            action = entry.get("action")
            ip_hash = entry.get("ip_hash")
            device_id = entry.get("device_id")
            trace_id = entry.get("trace_id")
            kms_request_id = entry.get("kms_request_id")
            raw_meta = entry.get("event_metadata") or entry.get("metadata") or {}

        # Extract session_id if present in metadata
        session_id = raw_meta.get("session_id") if isinstance(raw_meta, dict) else None

        return SecurityEventNormalized(
            event_id=event_id,
            event_type=event_type,
            timestamp=timestamp,
            source_subsystem="AUDIT",
            result=result_str.upper(),
            actor_id=str(actor_id) if actor_id else None,
            actor_role=str(actor_role) if actor_role else None,
            resource_type=str(resource_type) if resource_type else None,
            resource_id=str(resource_id) if resource_id else None,
            action=str(action) if action else None,
            session_id=str(session_id) if session_id else None,
            device_id=str(device_id) if device_id else None,
            ip_hash=str(ip_hash) if ip_hash else None,
            trace_id=str(trace_id) if trace_id else None,
            request_id=raw_meta.get("request_id") if isinstance(raw_meta, dict) else None,
            audit_log_id=event_id,
            kms_request_id=str(kms_request_id) if kms_request_id else None,
            policy_version="BSEA-DETECTION-v1",
            metadata=sanitize_metadata(raw_meta),
        )

    @staticmethod
    def normalize_auth_event(event_dict: Dict[str, Any]) -> SecurityEventNormalized:
        """
        Normalizes an authentication event (login failure, login success, lockout).
        """
        event_id = str(event_dict.get("event_id") or uuid.uuid4())
        event_type = str(event_dict.get("event_type", "LOGIN"))
        timestamp = ensure_utc(event_dict.get("timestamp"))
        success = event_dict.get("success", True)
        result = "SUCCESS" if success else "FAILURE"

        return SecurityEventNormalized(
            event_id=event_id,
            event_type=event_type,
            timestamp=timestamp,
            source_subsystem="AUTH",
            result=result,
            actor_id=event_dict.get("actor_id"),
            actor_role=event_dict.get("actor_role"),
            resource_type="auth",
            resource_id=event_dict.get("resource_id"),
            action=event_dict.get("action", "AUTHENTICATE"),
            session_id=event_dict.get("session_id"),
            device_id=event_dict.get("device_id"),
            ip_hash=event_dict.get("ip_hash"),
            trace_id=event_dict.get("trace_id"),
            request_id=event_dict.get("request_id"),
            audit_log_id=event_dict.get("audit_log_id"),
            policy_version="BSEA-DETECTION-v1",
            metadata=sanitize_metadata(event_dict.get("metadata", {})),
        )

    @staticmethod
    def normalize_cbt_event(event_dict: Dict[str, Any]) -> SecurityEventNormalized:
        """
        Normalizes a CBT proctoring security event (tab switch, fullscreen exit).
        """
        event_id = str(event_dict.get("event_id") or uuid.uuid4())
        cbt_type = event_dict.get("event_type", "SECURITY_VIOLATION")
        event_type = cbt_type if cbt_type.startswith("CBT_") else f"CBT_{cbt_type}"
        timestamp = ensure_utc(event_dict.get("timestamp"))

        return SecurityEventNormalized(
            event_id=event_id,
            event_type=event_type,
            timestamp=timestamp,
            source_subsystem="CBT",
            result="DENIED" if "VIOLATION" in event_type else "SUCCESS",
            actor_id=event_dict.get("candidate_id") or event_dict.get("actor_id"),
            actor_role="candidate",
            resource_type="exam_session",
            resource_id=event_dict.get("exam_id"),
            action=event_dict.get("action", "PROCTORING_EVENT"),
            session_id=event_dict.get("session_id"),
            device_id=event_dict.get("device_id") or event_dict.get("device_fingerprint"),
            ip_hash=event_dict.get("ip_hash"),
            trace_id=event_dict.get("trace_id"),
            request_id=event_dict.get("request_id"),
            audit_log_id=event_dict.get("audit_log_id"),
            policy_version="BSEA-DETECTION-v1",
            metadata=sanitize_metadata(event_dict.get("details", {})),
        )

    @staticmethod
    def normalize_kms_event(event_dict: Dict[str, Any]) -> SecurityEventNormalized:
        """
        Normalizes an application-side KMS security record (from _audit_kms_operation).
        """
        event_id = str(event_dict.get("event_id") or uuid.uuid4())
        op = str(event_dict.get("operation", "CRYPTO_OP")).upper()
        event_type = f"KMS_{op}" if not op.startswith("KMS_") else op
        timestamp = ensure_utc(event_dict.get("timestamp"))
        success = event_dict.get("success", True)
        result = "SUCCESS" if success else "FAILURE"

        return SecurityEventNormalized(
            event_id=event_id,
            event_type=event_type,
            timestamp=timestamp,
            source_subsystem="KMS",
            result=result,
            actor_id=event_dict.get("actor", "bsea-backend"),
            actor_role="service_role",
            resource_type="kms_key",
            resource_id=event_dict.get("kms_key_id"),
            action=op,
            trace_id=event_dict.get("trace_id"),
            request_id=event_dict.get("request_id"),
            audit_log_id=event_dict.get("audit_log_id"),
            kms_request_id=event_dict.get("kms_request_id") or event_dict.get("correlation_id"),
            policy_version="BSEA-DETECTION-v1",
            metadata=sanitize_metadata(event_dict),
        )

    @staticmethod
    def normalize_rate_limit_event(event_dict: Dict[str, Any]) -> SecurityEventNormalized:
        """
        Normalizes an HTTP 429 rate-limit rejection event.
        """
        event_id = str(event_dict.get("event_id") or uuid.uuid4())
        timestamp = ensure_utc(event_dict.get("timestamp"))

        return SecurityEventNormalized(
            event_id=event_id,
            event_type="RATE_LIMIT_EXCEEDED",
            timestamp=timestamp,
            source_subsystem="API",
            result="DENIED",
            actor_id=event_dict.get("actor_id"),
            actor_role=event_dict.get("actor_role"),
            resource_type="endpoint",
            resource_id=event_dict.get("endpoint_class"),
            action="HTTP_REQUEST",
            session_id=event_dict.get("session_id"),
            device_id=event_dict.get("device_id"),
            ip_hash=event_dict.get("ip_hash"),
            trace_id=event_dict.get("trace_id"),
            request_id=event_dict.get("request_id"),
            policy_version="BSEA-DETECTION-v1",
            metadata=sanitize_metadata(event_dict),
        )
