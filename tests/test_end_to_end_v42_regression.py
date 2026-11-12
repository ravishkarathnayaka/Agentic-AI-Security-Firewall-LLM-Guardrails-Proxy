import pytest
from proxy.pipeline import SecurityPipeline


def test_end_to_end_v42_regression():
    pipeline = SecurityPipeline()
    # Inbound clean query passes
    clean_payload = {"messages": [{"role": "user", "content": "Hello, summarize the enterprise security policies."}]}
    res = pipeline.process_inbound(clean_payload, "req_e2e_clean", "10.0.0.1")
    assert res.is_allowed is True
