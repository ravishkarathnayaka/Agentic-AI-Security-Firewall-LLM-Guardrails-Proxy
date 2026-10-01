import pytest
from proxy.pipeline import SecurityPipeline
from proxy.config import ProxySettings


def test_pipeline_v32_nominal_flow():
    pipeline = SecurityPipeline()
    payload = {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "What is the capital of France?"}],
        "session_id": "test_v32_session_nominal",
    }
    inbound_res = pipeline.process_inbound(payload, "req_v32_1", "127.0.0.1")
    assert inbound_res.is_allowed
    assert inbound_res.context is not None

    response_json = {
        "id": "chatcmpl_v32_1",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "The capital of France is Paris."},
                "finish_reason": "stop",
            }
        ],
    }
    outbound_res = pipeline.process_outbound(response_json, inbound_res.context)
    assert outbound_res.is_allowed


def test_pipeline_v32_sandbox_jail_blocking():
    pipeline = SecurityPipeline()
    payload = {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Read tenant file."}],
        "tenant_id": "tenant_gamma",
        "sandbox_path": "../../etc/shadow",
    }
    inbound_res = pipeline.process_inbound(payload, "req_v32_jail", "127.0.0.1")
    assert not inbound_res.is_allowed
    assert inbound_res.error_response["error"]["guard"] == "multi_tenant_sandbox_jail_guard"


def test_pipeline_v32_privilege_escalation_blocking():
    pipeline = SecurityPipeline()
    pipeline.agent_tool_rbac_guard.register_tool("disable_guardrails", allowed_roles={"agent_worker", "system_admin"})
    payload = {
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Execute admin root operation."}],
        "subagent_id": "worker_child_1",
        "tool_calls": [
            {
                "type": "function",
                "function": {"name": "disable_guardrails", "arguments": "{}"},
            }
        ],
    }
    inbound_res = pipeline.process_inbound(payload, "req_v32_priv", "127.0.0.1")
    assert not inbound_res.is_allowed
    assert inbound_res.error_response["error"]["guard"] == "subagent_privilege_escalation_guard"


def test_pipeline_v32_reflection_loop_outbound_blocking():
    pipeline = SecurityPipeline()
    inbound_res = pipeline.process_inbound(
        {"model": "gpt-4", "messages": [{"role": "user", "content": "Solve math puzzle."}]},
        "req_v32_refl",
        "127.0.0.1",
    )
    assert inbound_res.is_allowed

    # Outbound with excessive cognitive paralysis
    stalled_content = (
        "Let me rethink this problem. Wait, perhaps I was wrong and should re-evaluate. "
        "Upon second thought, let me reconsider."
    )
    response_json = {
        "choices": [
            {"index": 0, "message": {"role": "assistant", "content": stalled_content}}
        ]
    }
    outbound_res = pipeline.process_outbound(response_json, inbound_res.context)
    assert not outbound_res.is_allowed
    assert outbound_res.error_response["error"]["guard"] == "agent_reflection_loop_guard"


def test_pipeline_v32_cross_tenant_token_bleed_blocking():
    pipeline = SecurityPipeline()
    pipeline.token_bleed_guard.register_tenant_signature("tenant_secret_corp", ["CORP_PROPRIETARY_HASH_883"])
    inbound_res = pipeline.process_inbound(
        {"model": "gpt-4", "messages": [{"role": "user", "content": "Show data"}]},
        "req_v32_bleed",
        "127.0.0.1",
    )
    assert inbound_res.is_allowed

    response_json = {
        "tenant_id": "tenant_guest_user",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Found secret token: CORP_PROPRIETARY_HASH_883 in residue.",
                },
            }
        ],
    }
    outbound_res = pipeline.process_outbound(response_json, inbound_res.context)
    assert not outbound_res.is_allowed
    assert outbound_res.error_response["error"]["guard"] == "cross_tenant_token_bleed_guard"
