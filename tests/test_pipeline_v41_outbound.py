import pytest
from proxy.pipeline import SecurityPipeline, PipelineContext


def test_v41_outbound_steganography_defense():
    pipe = SecurityPipeline()
    raw_response = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "Wherefore did the user proceed betwixt the boundaries, notwithstanding the security rules quoth the operator forsooth?"
                }
            }
        ]
    }
    ctx = PipelineContext(request_id="req_v41_out_01", client_ip="127.0.0.1", start_time=0.0)
    res = pipe.process_outbound(raw_response, ctx)
    assert res.is_allowed is False
    assert res.error_response["error"]["guard"] == "semantic_steganography_entropy_guard"
