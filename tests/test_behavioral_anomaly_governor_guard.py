import pytest
from proxy.guards.behavioral_anomaly_governor_guard import BehavioralAnomalyGovernorGuard


def test_normal_velocity():
    guard = BehavioralAnomalyGovernorGuard(max_tokens_per_min=10000, max_tool_calls_per_min=20)
    res = guard.record_and_evaluate("session_101", token_count=500, tool_call_count=1)
    assert not res.is_blocked
    assert res.current_velocity == 500.0


def test_token_velocity_breach():
    guard = BehavioralAnomalyGovernorGuard(max_tokens_per_min=2000)
    guard.record_and_evaluate("session_102", token_count=1500)
    res = guard.record_and_evaluate("session_102", token_count=800)
    assert res.is_blocked
    assert res.violation_code == "TOKEN_VELOCITY_LIMIT_EXCEEDED"


def test_runaway_tool_loop_breach():
    guard = BehavioralAnomalyGovernorGuard(max_tool_calls_per_min=5)
    for _ in range(5):
        guard.record_and_evaluate("session_103", token_count=10, tool_call_count=1)
    res = guard.record_and_evaluate("session_103", token_count=10, tool_call_count=1)
    assert res.is_blocked
    assert res.violation_code == "AUTONOMOUS_RUNAWAY_LOOP_DETECTED"
