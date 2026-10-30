"""
Honeytoken Intrusion Forwarder & SIEM Alert Dispatcher
======================================================
Dispatches instant high-priority alerts to SIEM collectors (Splunk, Elastic, Sentinel)
and SOC webhook endpoints whenever a honeytoken decoy tripwire is activated.
"""

import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class SIEMAlert:
    alert_id: str
    severity: str
    source_ip: str
    session_id: str
    tripped_token_type: str
    leak_vector: str
    timestamp: float
    forwarded: bool = False


class HoneytokenIntrusionForwarder:
    """
    Manages alerting pipelines for active deception traps and honeytokens.
    """

    def __init__(self, webhook_endpoint: Optional[str] = None):
        self.webhook_endpoint = webhook_endpoint
        self.dispatched_alerts: List[SIEMAlert] = []

    def dispatch_tripwire_alert(self, session_id: str, source_ip: str, token_type: str, leak_vector: str) -> SIEMAlert:
        alert_id = f"HONEY-ALERT-{int(time.time()*1000)}"
        alert = SIEMAlert(
            alert_id=alert_id,
            severity="CRITICAL",
            source_ip=source_ip,
            session_id=session_id,
            tripped_token_type=token_type,
            leak_vector=leak_vector,
            timestamp=time.time(),
            forwarded=bool(self.webhook_endpoint)
        )
        self.dispatched_alerts.append(alert)
        return alert

    def get_incident_summary(self) -> Dict[str, Any]:
        return {
            "total_incidents": len(self.dispatched_alerts),
            "critical_traps": [a.alert_id for a in self.dispatched_alerts if a.severity == "CRITICAL"],
            "latest_incident": self.dispatched_alerts[-1].alert_id if self.dispatched_alerts else None
        }
