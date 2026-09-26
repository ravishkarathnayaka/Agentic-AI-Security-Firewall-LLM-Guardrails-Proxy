"""
Unit tests for AgentVelocityGuard (proxy/guards/agent_velocity_guard.py).
"""

import pytest
from proxy.guards.agent_velocity_guard import AgentVelocityGuard, VelocityResult


@pytest.fixture
def velocity_guard():
    return AgentVelocityGuard(
        max_calls_per_minute=10,
        max_burst_per_10s=4,
        max_consecutive_failures=3,
        window_seconds=60
    )


def test_normal_velocity_passes(velocity_guard):
    t0 = 1000.0
    res1 = velocity_guard.record_and_check("agent_1", "calc", current_time=t0)
    assert res1.is_blocked is False
    assert res1.current_calls_in_window == 1

    res2 = velocity_guard.record_and_check("agent_1", "calc", current_time=t0 + 1.0)
    assert res2.is_blocked is False
    assert res2.current_calls_in_window == 2


def test_burst_anomaly_blocked(velocity_guard):
    t0 = 2000.0
    # max_burst_per_10s is 4
    for i in range(4):
        res = velocity_guard.record_and_check("agent_fast", "search", current_time=t0 + (i * 0.5))
        assert res.is_blocked is False

    # 5th call in 10s should be blocked
    res_blocked = velocity_guard.record_and_check("agent_fast", "search", current_time=t0 + 2.5)
    assert res_blocked.is_blocked is True
    assert res_blocked.violation_code == "anomalous_tool_burst_detected"


def test_window_velocity_limit_blocked(velocity_guard):
    t0 = 3000.0
    # Spread out over 50 seconds to avoid burst limit (1 call every 4s)
    # max_calls_per_minute is 10
    for i in range(10):
        res = velocity_guard.record_and_check("agent_marathon", "fetch", current_time=t0 + (i * 4.0))
        assert res.is_blocked is False

    # 11th call within the 60s window should exceed velocity
    res_exceeded = velocity_guard.record_and_check("agent_marathon", "fetch", current_time=t0 + 45.0)
    assert res_exceeded.is_blocked is True
    assert res_exceeded.violation_code == "agent_velocity_limit_exceeded"


def test_consecutive_failure_lockout(velocity_guard):
    # Record 3 failures (max_consecutive_failures is 3)
    velocity_guard.record_outcome("agent_fuzzer", success=False)
    velocity_guard.record_outcome("agent_fuzzer", success=False)
    velocity_guard.record_outcome("agent_fuzzer", success=False)

    res = velocity_guard.record_and_check("agent_fuzzer", "query", current_time=4000.0)
    assert res.is_blocked is True
    assert res.violation_code == "excessive_tool_failures_lockout"


def test_reset_agent_clears_state(velocity_guard):
    velocity_guard.record_outcome("agent_err", success=False)
    velocity_guard.record_outcome("agent_err", success=False)
    velocity_guard.record_outcome("agent_err", success=False)

    # Locked out
    assert velocity_guard.record_and_check("agent_err", "test").is_blocked is True

    # Reset
    velocity_guard.reset_agent("agent_err")
    assert velocity_guard.record_and_check("agent_err", "test").is_blocked is False
