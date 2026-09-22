"""Unit tests for SIEM Telemetry Forwarder (CEF & RFC 5424 Syslog)."""

import pytest
from proxy.telemetry.siem_forwarder import SiemForwarder, SiemConfig


@pytest.fixture
def blocked_event():
    return {
        "timestamp": "2026-09-22T17:30:00Z",
        "request_id": "req-987654",
        "client_ip": "198.51.100.22",
        "direction": "inbound",
        "status": "BLOCKED",
        "guard": "prompt_injection_guard",
        "violation_code": "prompt_injection_detected",
        "details": "DAN jailbreak attempt | override rules",
        "latency_ms": 1.45,
    }


@pytest.fixture
def allowed_event():
    return {
        "timestamp": "2026-09-22T17:30:05Z",
        "request_id": "req-112233",
        "client_ip": "198.51.100.44",
        "direction": "outbound",
        "status": "ALLOWED",
        "guard": None,
        "violation_code": None,
        "details": "Clean response passed inspection.",
        "latency_ms": 0.88,
    }


def test_cef_format_blocked_event(blocked_event):
    forwarder = SiemForwarder(SiemConfig(format_type="CEF"))
    cef_msg = forwarder.format_event(blocked_event)

    assert cef_msg.startswith("CEF:0|Enterprise|LLM-Security-Firewall|1.2.0|")
    assert "prompt_injection_detected" in cef_msg
    assert "|7|" in cef_msg  # Severity 7 for blocked attacks
    assert "src=198.51.100.22" in cef_msg
    assert "act=BLOCKED" in cef_msg
    assert "cs1=prompt_injection_guard" in cef_msg
    assert "cs3=req-987654" in cef_msg
    # Ensure pipes in details are escaped
    assert "DAN jailbreak attempt \\| override rules" in cef_msg


def test_cef_format_allowed_event(allowed_event):
    forwarder = SiemForwarder(SiemConfig(format_type="CEF"))
    cef_msg = forwarder.format_event(allowed_event)

    assert "|1|" in cef_msg  # Severity 1 for allowed traffic
    assert "act=ALLOWED" in cef_msg
    assert "safe_completion" in cef_msg


def test_rfc5424_syslog_format(blocked_event):
    forwarder = SiemForwarder(SiemConfig(format_type="RFC5424", device_host="gateway-ai-sec"))
    syslog_msg = forwarder.format_event(blocked_event)

    assert syslog_msg.startswith("<132>1")  # local0 (16*8) + warning (4) = 132
    assert "gateway-ai-sec" in syslog_msg
    assert "llm-guardrails" in syslog_msg
    assert '[securityEvent@48577 reqId="req-987654"' in syslog_msg
    assert 'clientIp="198.51.100.22"' in syslog_msg
    assert 'status="BLOCKED"' in syslog_msg
