import time
import pytest
from proxy.guards.capability_lease_guard import CapabilityLeaseGuard, LeaseValidationResult


def test_capability_lease_happy_path():
    guard = CapabilityLeaseGuard()
    t0 = 1000.0
    lease = guard.issue_lease("subagent-alpha", ["read_file", "search_docs"], ttl_seconds=60.0, max_uses=2, current_time=t0)

    # First valid use
    res1 = guard.validate_and_consume(lease.lease_id, "subagent-alpha", "read_file", current_time=t0 + 5)
    assert res1.is_valid
    assert res1.remaining_uses == 1

    # Second valid use
    res2 = guard.validate_and_consume(lease.lease_id, "subagent-alpha", "search_docs", current_time=t0 + 10)
    assert res2.is_valid
    assert res2.remaining_uses == 0

    # Quota exhausted
    res3 = guard.validate_and_consume(lease.lease_id, "subagent-alpha", "read_file", current_time=t0 + 15)
    assert not res3.is_valid
    assert res3.violation_code == "lease_quota_exhausted"


def test_capability_lease_agent_mismatch():
    guard = CapabilityLeaseGuard()
    t0 = 1000.0
    lease = guard.issue_lease("subagent-alpha", ["read_file"], ttl_seconds=60.0, current_time=t0)

    res = guard.validate_and_consume(lease.lease_id, "rogue-agent", "read_file", current_time=t0 + 1)
    assert not res.is_valid
    assert res.violation_code == "lease_agent_mismatch"


def test_capability_lease_unauthorized_tool():
    guard = CapabilityLeaseGuard()
    t0 = 1000.0
    lease = guard.issue_lease("subagent-alpha", ["read_file"], ttl_seconds=60.0, current_time=t0)

    res = guard.validate_and_consume(lease.lease_id, "subagent-alpha", "delete_database", current_time=t0 + 1)
    assert not res.is_valid
    assert res.violation_code == "unauthorized_tool_in_lease"


def test_capability_lease_expired():
    guard = CapabilityLeaseGuard()
    t0 = 1000.0
    lease = guard.issue_lease("subagent-alpha", ["read_file"], ttl_seconds=30.0, current_time=t0)

    res = guard.validate_and_consume(lease.lease_id, "subagent-alpha", "read_file", current_time=t0 + 35.0)
    assert not res.is_valid
    assert res.violation_code == "lease_expired"


def test_capability_lease_tamper_detection():
    guard = CapabilityLeaseGuard()
    t0 = 1000.0
    lease = guard.issue_lease("subagent-alpha", ["read_file"], ttl_seconds=60.0, current_time=t0)

    # Tamper with allowed tools
    lease.allowed_tools.append("execute_bash")

    res = guard.validate_and_consume(lease.lease_id, "subagent-alpha", "execute_bash", current_time=t0 + 1)
    assert not res.is_valid
    assert res.violation_code == "lease_signature_tampered"
