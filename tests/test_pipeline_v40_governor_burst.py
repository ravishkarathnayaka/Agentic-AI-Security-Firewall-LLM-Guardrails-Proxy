import pytest
from proxy.guards.behavioral_anomaly_governor_guard import BehavioralAnomalyGovernorGuard


def test_high_throughput_governor_burst():
    governor = BehavioralAnomalyGovernorGuard(max_tokens_per_min=5000, max_tool_calls_per_min=10)

    # Simulate rapid 8 requests of 500 tokens (4000 tokens)
    for i in range(8):
        res = governor.record_and_evaluate("burst_sess", token_count=500, tool_call_count=1)
        assert not res.is_blocked

    # 9th request: 4500 tokens (still ok)
    res = governor.record_and_evaluate("burst_sess", token_count=500, tool_call_count=1)
    assert not res.is_blocked

    # 10th request: 5000 tokens (limit is 5000, so <= 5000 is still ok)
    res = governor.record_and_evaluate("burst_sess", token_count=500, tool_call_count=1)
    assert not res.is_blocked

    # 11th request: 5500 tokens (exceeds 5000, triggers block)
    res = governor.record_and_evaluate("burst_sess", token_count=500, tool_call_count=1)
    assert res.is_blocked
    assert res.violation_code in ("TOKEN_VELOCITY_LIMIT_EXCEEDED", "AUTONOMOUS_RUNAWAY_LOOP_DETECTED")
