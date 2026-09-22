"""SIEM Telemetry Forwarder (CEF & RFC 5424 Syslog).

Converts internal LLM security audit logs into industry standard SIEM formats:
- Common Event Format (CEF) for ArcSight, Splunk, and Microsoft Sentinel
- RFC 5424 Syslog for enterprise syslog aggregators and Elastic Logstash.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import socket
from typing import Any, Dict, Optional


@dataclass
class SiemConfig:
    """Configuration for SIEM forwarding."""
    enabled: bool = False
    format_type: str = "CEF"  # 'CEF' or 'RFC5424'
    vendor: str = "Enterprise"
    product: str = "LLM-Security-Firewall"
    version: str = "1.2.0"
    device_host: str = "llm-proxy-01"


class SiemForwarder:
    """Formats and dispatches security event telemetry to SIEM endpoints."""

    def __init__(self, config: Optional[SiemConfig] = None):
        self.config = config or SiemConfig()

    def format_cef(self, event: Dict[str, Any]) -> str:
        """Format an audit event dictionary into Common Event Format (CEF).

        Specification:
        CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
        """
        status = event.get("status", "ALLOWED")
        guard = event.get("guard") or "generic_pipeline"
        violation_code = event.get("violation_code") or ("safe_completion" if status == "ALLOWED" else "policy_violation")
        details = str(event.get("details", "")).replace("|", "\\|")
        severity = 7 if status == "BLOCKED" else 1

        client_ip = event.get("client_ip", "0.0.0.0")
        request_id = event.get("request_id", "req-unknown")
        direction = event.get("direction", "inbound")
        latency_ms = event.get("latency_ms", 0.0)

        header = (
            f"CEF:0|{self.config.vendor}|{self.config.product}|{self.config.version}|"
            f"{violation_code}|{details}|{severity}|"
        )
        extensions = (
            f"src={client_ip} act={status} cs1={guard} cs1Label=GuardName "
            f"cs2={direction} cs2Label=Direction cs3={request_id} cs3Label=RequestID "
            f"cn1={latency_ms} cn1Label=LatencyMs"
        )
        return header + extensions

    def format_rfc5424(self, event: Dict[str, Any]) -> str:
        """Format an audit event into RFC 5424 Syslog format.

        Specification:
        <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG
        """
        status = event.get("status", "ALLOWED")
        facility = 16  # local0
        severity = 4 if status == "BLOCKED" else 6  # 4=Warning, 6=Informational
        priority = (facility * 8) + severity

        ts = event.get("timestamp") or datetime.now(timezone.utc).isoformat()
        hostname = self.config.device_host
        app_name = "llm-guardrails"
        procid = "1"
        msgid = event.get("violation_code") or ("ALLOWED" if status == "ALLOWED" else "BLOCKED")

        client_ip = event.get("client_ip", "0.0.0.0")
        request_id = event.get("request_id", "req-unknown")
        guard = event.get("guard") or "none"
        sd = f'[securityEvent@48577 reqId="{request_id}" clientIp="{client_ip}" guard="{guard}" status="{status}"]'

        msg = event.get("details", "")
        return f"<{priority}>1 {ts} {hostname} {app_name} {procid} {msgid} {sd} {msg}"

    def format_event(self, event: Dict[str, Any]) -> str:
        """Format event based on configured format."""
        if self.config.format_type.upper() == "RFC5424":
            return self.format_rfc5424(event)
        return self.format_cef(event)
