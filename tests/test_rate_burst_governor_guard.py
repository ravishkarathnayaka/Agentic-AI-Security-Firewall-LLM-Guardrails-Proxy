import pytest
from proxy.guards.rate_burst_governor_guard import AdaptiveRateBurstGovernorGuard


def test_rate_governor_normal_traffic():
    gov = AdaptiveRateBurstGovernorGuard(base_capacity=10.0, base_refill_rate=2.0)
    t0 = 1000.0

    # Consume 3 tokens
    res = gov.consume("client-1", cost=3.0, current_time=t0)
    assert res.is_allowed
    assert res.remaining_tokens == 7.0


def test_rate_governor_exhaustion_and_refill():
    gov = AdaptiveRateBurstGovernorGuard(base_capacity=5.0, base_refill_rate=1.0)
    t0 = 2000.0

    # Consume all tokens
    assert gov.consume("client-2", cost=5.0, current_time=t0).is_allowed

    # Immediate next request should fail
    res_fail = gov.consume("client-2", cost=1.0, current_time=t0)
    assert not res_fail.is_allowed
    assert res_fail.violation_code == "rate_burst_quota_exceeded"
    assert res_fail.retry_after_sec > 0

    # 3 seconds later, 3 tokens refilled
    res_ok = gov.consume("client-2", cost=2.0, current_time=t0 + 3.0)
    assert res_ok.is_allowed


def test_rate_governor_penalty_shrinks_capacity():
    gov = AdaptiveRateBurstGovernorGuard(base_capacity=20.0, base_refill_rate=2.0, min_capacity=4.0)
    t0 = 3000.0

    # Normal consume
    gov.consume("bad-actor", cost=1.0, current_time=t0)

    # Apply severe penalty
    gov.penalize_client("bad-actor", penalty_delta=5.0)

    # Next check should show diminished capacity
    res = gov.consume("bad-actor", cost=1.0, current_time=t0 + 0.1)
    assert res.current_capacity < 15.0
