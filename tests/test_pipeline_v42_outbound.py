import pytest
import time
from proxy.pipeline import SecurityPipeline, PipelineContext


def test_v42_pipeline_outbound_jitter_applied():
    pipeline = SecurityPipeline()
    ctx = PipelineContext(request_id="req_out_1", client_ip="127.0.0.1", start_time=time.time() - 0.05)
    resp = {"choices": [{"message": {"content": "Safe output."}}]}
    sanitized = pipeline.apply_v42_outbound_guards(ctx, resp)
    assert sanitized.get("headers", {}).get("X-Timing-Defense") == "AdaptiveJitterApplied"
