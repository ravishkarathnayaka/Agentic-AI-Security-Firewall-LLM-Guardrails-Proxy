"""Structured JSON Audit Logging & Prometheus Telemetry for LLM Proxy."""

import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

# Prometheus Metrics Definitions
PROMETHEUS_REQUESTS_TOTAL = Counter(
    "llm_proxy_requests_total",
    "Total requests processed by LLM Security Proxy",
    ["endpoint", "status"]
)

PROMETHEUS_BLOCKED_ATTACKS = Counter(
    "llm_proxy_blocked_attacks_total",
    "Total security policy violations blocked by guardrails",
    ["guard", "violation_code"]
)

PROMETHEUS_PII_REDACTIONS = Counter(
    "llm_proxy_pii_redactions_total",
    "Total PII entities redacted by inbound sanitizer",
    ["entity_type"]
)

PROMETHEUS_LATENCY_HISTOGRAM = Histogram(
    "llm_proxy_latency_seconds",
    "Processing latency across security stages in seconds",
    ["stage"]
)


class AuditLogger:
    """Manages structured JSON security audit events and Prometheus metrics."""

    def __init__(self, log_file: str = "audit_logs.jsonl", log_level: str = "INFO"):
        self.log_file = log_file
        self.logger = logging.getLogger("llm_security_proxy")
        self.logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s"))
            self.logger.addHandler(handler)

    def log_event(
        self,
        request_id: str,
        client_ip: str,
        direction: str,
        status: str,
        latency_ms: float,
        guard: Optional[str] = None,
        violation_code: Optional[str] = None,
        details: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Record an audit log entry in structured JSON format and update metrics."""
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": request_id,
            "client_ip": client_ip,
            "direction": direction,
            "status": status,
            "latency_ms": round(latency_ms, 2),
            "guard": guard,
            "violation_code": violation_code,
            "details": details,
            "metadata": metadata or {},
        }

        # Format as compact JSON
        json_line = json.dumps(record)

        # Log via standard logger
        if status == "BLOCKED":
            self.logger.warning(f"SECURITY ALERT [BLOCKED]: {json_line}")
        elif status == "REDACTED":
            self.logger.info(f"SECURITY NOTICE [REDACTED]: {json_line}")
        else:
            self.logger.info(f"SECURITY AUDIT [ALLOWED]: {json_line}")

        # Append to audit file if specified
        if self.log_file:
            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(json_line + "\n")
            except Exception as e:
                self.logger.error(f"Failed to append to audit log file: {e}")

        # Update Prometheus metrics
        endpoint_label = metadata.get("endpoint", "/v1/chat/completions") if metadata else "/v1/chat/completions"
        PROMETHEUS_REQUESTS_TOTAL.labels(endpoint=endpoint_label, status=status).inc()

        if status == "BLOCKED" and guard:
            PROMETHEUS_BLOCKED_ATTACKS.labels(
                guard=guard,
                violation_code=violation_code or "unknown"
            ).inc()

        PROMETHEUS_LATENCY_HISTOGRAM.labels(stage=direction).observe(latency_ms / 1000.0)

        return record

    def record_pii_redaction(self, entity_type: str, count: int = 1):
        """Record PII redaction metrics."""
        PROMETHEUS_PII_REDACTIONS.labels(entity_type=entity_type).inc(count)

    def get_prometheus_metrics(self) -> bytes:
        """Export latest prometheus metrics."""
        return generate_latest()


# Global audit logger instance
audit_logger = AuditLogger()
