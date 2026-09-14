"""
B-SEA Production Observability Foundation — ASGI Telemetry Middleware
Phase 3C-5B Implementation conforming to BSEA_PHASE3C_5B_ARCHITECTURE_REVIEW_REV02.md
"""
from __future__ import annotations

import logging
import time
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.logging import (
    CURRENT_REQUEST_ID,
    CURRENT_TRACE_ID,
    categorize_user_agent,
    parse_or_generate_request_id,
    parse_or_generate_trace_id,
    sanitize_client_ip,
)
from app.core.metrics import categorize_route, metrics_registry

logger = logging.getLogger("bsea.http")


class BSEAHttpTelemetryMiddleware(BaseHTTPMiddleware):
    """
    ASGI Middleware managing request correlation, latency measurement,
    HTTP metrics recording, and structured log emission.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        # 1. Resolve W3C Trace Context and Request UUID
        raw_traceparent = request.headers.get("traceparent")
        trace_id = parse_or_generate_trace_id(raw_traceparent)

        raw_request_id = request.headers.get("x-request-id")
        request_id = parse_or_generate_request_id(raw_request_id)

        token_trace = CURRENT_TRACE_ID.set(trace_id)
        token_req = CURRENT_REQUEST_ID.set(request_id)

        # 2. Extract privacy-sanitized metadata
        raw_ip = request.headers.get("x-forwarded-for") or (request.client.host if request.client else None)
        masked_ip = sanitize_client_ip(raw_ip)
        ua_category = categorize_user_agent(request.headers.get("user-agent"))

        endpoint_class = categorize_route(request.url.path)
        method = request.method if request.method in ("GET", "POST", "PUT", "DELETE") else "GET"

        start_time = time.perf_counter()

        try:
            response = await call_next(request)
            duration_sec = time.perf_counter() - start_time
            latency_ms = round(duration_sec * 1000.0, 2)
            status_code = response.status_code

            # Classify status code
            if 200 <= status_code < 300:
                status_class = "2xx"
                result = "SUCCESS"
                log_level = logging.INFO
            elif 300 <= status_code < 400:
                status_class = "3xx"
                result = "SUCCESS"
                log_level = logging.INFO
            elif 400 <= status_code < 500:
                status_class = "4xx"
                result = "DENIED" if status_code in (401, 403) else "FAILED"
                log_level = logging.WARNING
            else:
                status_class = "5xx"
                result = "FAILED"
                log_level = logging.ERROR

            # Record bounded metrics safely (non-blocking)
            try:
                metrics_registry.inc_counter(
                    "bsea_http_requests_total",
                    {"endpoint_class": endpoint_class, "method": method, "status_class": status_class},
                )
                metrics_registry.observe_histogram(
                    "bsea_http_request_duration_seconds",
                    duration_sec,
                    {"endpoint_class": endpoint_class, "method": method},
                )
            except Exception as me:
                logger.warning(f"Metric recording fault: {me}")

            # Emit structured request completion log
            msg = f"{method} {endpoint_class} completed {status_code} ({latency_ms}ms)"
            extra = {
                "trace_id": trace_id,
                "request_id": request_id,
                "action": "HTTP_REQUEST",
                "result": result,
                "latency_ms": latency_ms,
                "client_ip_masked": masked_ip,
                "user_agent_category": ua_category,
            }
            if status_code >= 400:
                extra["error_code"] = f"HTTP_{status_code}"

            logger.log(log_level, msg, extra=extra)

            # Attach correlation headers to response
            response.headers["X-Trace-ID"] = trace_id
            response.headers["X-Request-ID"] = request_id
            return response

        except Exception as exc:
            duration_sec = time.perf_counter() - start_time
            latency_ms = round(duration_sec * 1000.0, 2)

            try:
                metrics_registry.inc_counter(
                    "bsea_http_requests_total",
                    {"endpoint_class": endpoint_class, "method": method, "status_class": "5xx"},
                )
                metrics_registry.observe_histogram(
                    "bsea_http_request_duration_seconds",
                    duration_sec,
                    {"endpoint_class": endpoint_class, "method": method},
                )
            except Exception:
                pass

            logger.error(
                f"{method} {endpoint_class} unhandled failure: {exc.__class__.__name__}",
                exc_info=True,
                extra={
                    "trace_id": trace_id,
                    "request_id": request_id,
                    "action": "HTTP_REQUEST",
                    "result": "FAILED",
                    "latency_ms": latency_ms,
                    "error_code": "INTERNAL_SERVER_ERROR",
                    "exception_type": exc.__class__.__name__,
                    "client_ip_masked": masked_ip,
                    "user_agent_category": ua_category,
                },
            )
            raise

        finally:
            CURRENT_TRACE_ID.reset(token_trace)
            CURRENT_REQUEST_ID.reset(token_req)
