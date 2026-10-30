import pytest
from proxy.telemetry.honeytoken_intrusion_forwarder import HoneytokenIntrusionForwarder


def test_honeytoken_alert_dispatch():
    forwarder = HoneytokenIntrusionForwarder(webhook_endpoint="https://siem.internal/webhook")
    alert = forwarder.dispatch_tripwire_alert("sess_44", "192.168.1.10", "AWS_API_KEY", "OUTBOUND_LLM_GENERATION")
    assert alert.severity == "CRITICAL"
    assert alert.forwarded is True
    summary = forwarder.get_incident_summary()
    assert summary["total_incidents"] == 1
    assert alert.alert_id in summary["critical_traps"]
