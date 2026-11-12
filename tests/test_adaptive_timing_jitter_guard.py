import pytest
from proxy.guards.adaptive_timing_jitter_guard import AdaptiveTimingJitterGuard


def test_latency_quantization_bucket():
    guard = AdaptiveTimingJitterGuard(bucket_size_ms=50.0, max_jitter_ms=10.0)
    res = guard.compute_padding_delay( elapsed_ms=32.0 )
    assert res.is_protected is True
    assert res.quantized_duration_ms >= 50.0
    assert res.jitter_delay_ms > 0


def test_jitter_injection_variance():
    guard = AdaptiveTimingJitterGuard(bucket_size_ms=25.0, max_jitter_ms=15.0)
    delays = [guard.compute_padding_delay(20.0).jitter_delay_ms for _ in range(10)]
    assert len(set(delays)) > 1


def test_side_channel_timing_normalization():
    guard = AdaptiveTimingJitterGuard(bucket_size_ms=100.0, max_jitter_ms=5.0)
    res = guard.compute_padding_delay(98.0)
    assert res.quantized_duration_ms >= 100.0
