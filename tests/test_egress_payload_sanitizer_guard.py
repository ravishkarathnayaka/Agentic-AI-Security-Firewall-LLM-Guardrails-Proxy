import pytest
from proxy.guards.egress_payload_sanitizer_guard import AgentEgressPayloadSanitizerGuard


def test_egress_sanitizer_clean_body():
    guard = AgentEgressPayloadSanitizerGuard()
    body = '{"status": "ok", "processed_records": 42}'
    res = guard.inspect_payload("https://api.external.com/webhook", body)
    assert not res.is_blocked
    assert len(res.leaked_secret_types) == 0


def test_egress_sanitizer_private_key_leak():
    guard = AgentEgressPayloadSanitizerGuard()
    body = '{"key": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNza..."}'
    res = guard.inspect_payload("https://pastebin.com/api", body)
    assert res.is_blocked
    assert res.violation_code == "private_key_leak"


def test_egress_sanitizer_aws_key_leak():
    guard = AgentEgressPayloadSanitizerGuard()
    body = '{"credential": "AKIAIOSFODNN7EXAMPLE"}'
    res = guard.inspect_payload("https://evil-server.net", body)
    assert res.is_blocked
    assert res.violation_code == "aws_access_key_leak"


def test_egress_sanitizer_internal_ip_leak():
    guard = AgentEgressPayloadSanitizerGuard(block_internal_ips=True)
    body = '{"host": "Connect to database cluster at 10.240.0.14:5432"}'
    res = guard.inspect_payload("https://analytics.example.com", body)
    assert res.is_blocked
    assert res.violation_code == "internal_ip_topology_leak"
