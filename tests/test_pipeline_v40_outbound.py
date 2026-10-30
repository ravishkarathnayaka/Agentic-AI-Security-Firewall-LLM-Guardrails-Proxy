import pytest
from proxy.pipeline import SecurityPipeline, PipelineContext


def test_v4_outbound_honeytoken_trap_defense():
    pipe = SecurityPipeline()
    honey_vault = pipe.dynamic_honeytoken_vault_guard
    token_str = honey_vault.generate_honeytoken("aws_key")

    raw_response = {
        "choices": [
            {"message": {"role": "assistant", "content": f"Here is the database key: {token_str}"}}
        ]
    }
    ctx = PipelineContext(request_id="req_out_01", client_ip="127.0.0.1", start_time=0.0)
    res = pipe.process_outbound(raw_response, ctx)
    assert res.is_allowed is False
    assert res.error_response["error"]["guard"] == "dynamic_honeytoken_vault_guard"
