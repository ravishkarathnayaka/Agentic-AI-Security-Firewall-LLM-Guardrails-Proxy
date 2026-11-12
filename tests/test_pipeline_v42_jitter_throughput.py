import pytest
from proxy.pipeline import SecurityPipeline


def test_jitter_pipeline_high_throughput():
    pipeline = SecurityPipeline()
    for i in range(10):
        res = pipeline.adaptive_timing_jitter_guard.compute_padding_delay(float(i * 10))
        assert res.is_protected is True
        assert res.quantized_duration_ms > 0
