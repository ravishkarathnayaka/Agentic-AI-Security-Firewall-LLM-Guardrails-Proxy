import pytest
from proxy.guards.adaptive_rate_burst_guard import AdaptiveRateBurstGuard


def test_adaptive_rate_nominal():
    guard = AdaptiveRateBurstGuard(base_rate_per_sec=10.0, max_bucket_capacity=20.0)
    res = guard.evaluate_request("sess_nom", token_cost=2.0, risk_score=0.0, current_time=100.0)
    assert not res.is_blocked
    assert res.remaining_tokens == 18.0
    assert res.current_risk_multiplier == 1.0


def test_adaptive_rate_high_risk_penalty():
    guard = AdaptiveRateBurstGuard(base_rate_per_sec=10.0, high_risk_penalty_factor=0.2)
    res = guard.evaluate_request("sess_risk", token_cost=1.0, risk_score=1.0, current_time=100.0)
    assert not res.is_blocked
    assert res.effective_rate_per_sec == pytest.approx(2.0)


def test_adaptive_rate_capacity_exhaustion():
    guard = AdaptiveRateBurstGuard(base_rate_per_sec=5.0, max_bucket_capacity=5.0)
    # Drain bucket
    res1 = guard.evaluate_request("sess_drain", token_cost=5.0, risk_score=0.5, current_time=100.0)
    assert not res1.is_blocked

    # Immediate second request should be blocked
    res2 = guard.evaluate_request("sess_drain", token_cost=1.0, risk_score=0.5, current_time=100.0)
    assert res2.is_blocked
    assert res2.violation_code == "ADAPTIVE_BURST_RATE_EXCEEDED"
