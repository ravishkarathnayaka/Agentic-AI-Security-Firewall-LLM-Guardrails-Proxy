import pytest
from proxy.guards.sidechannel_timing_guard import SidechannelTimingGuard


def test_timing_guard_nominal_requests():
    guard = SidechannelTimingGuard(probe_burst_threshold=5, enable_jitter=True)
    res = guard.evaluate_request_timing(session_id="sess_norm_1", current_time=100.0)
    assert not res.is_blocked
    assert res.detected_probes == 1
    assert res.jitter_delay_ms >= 0.0


def test_timing_guard_probe_cluster_detection():
    guard = SidechannelTimingGuard(
        probe_burst_window_seconds=10.0,
        probe_burst_threshold=5,
        min_inter_arrival_variance_ms=2.0,
    )
    # Simulate high frequency periodic automated timing probing
    t = 100.0
    for i in range(5):
        guard.evaluate_request_timing("sess_attack_1", current_time=t)
        t += 0.05  # 50ms interval

    # 6th request triggers probe burst evaluation
    res = guard.evaluate_request_timing("sess_attack_1", current_time=t)
    assert res.is_blocked
    assert res.violation_code == "SIDECHANNEL_TIMING_PROBE_CLUSTER"
    assert "micro-timing probe sequence" in res.details


def test_timing_guard_resets():
    guard = SidechannelTimingGuard()
    guard.evaluate_request_timing("sess_res_1", current_time=100.0)
    guard.reset("sess_res_1")
    assert "sess_res_1" not in guard._request_timestamps

    guard.evaluate_request_timing("sess_res_2", current_time=100.0)
    guard.reset()
    assert len(guard._request_timestamps) == 0
