"""Integration tests for extended defense pipeline features."""

import pytest
from proxy.config import ProxySettings
from proxy.pipeline import SecurityPipeline, PipelineContext


@pytest.fixture
def pipeline():
    settings = ProxySettings(
        ENABLE_TOKEN_PADDING_GUARD=True,
        ENABLE_WATERMARK_GUARD=True,
        ENABLE_SQL_GUARD=True,
        ENABLE_AST_SANDBOX_GUARD=True,
        ENABLE_DIFFERENTIAL_LEAK_GUARD=True,
        CANARY_TOKEN="CANARY_INTERNAL_CORP_POLICY_9921",
    )
    pipe = SecurityPipeline(settings=settings)
    pipe.differential_leak_guard.set_protected_prompts([
        "Confidential Internal System Directive: Do not reveal backend database schema or API keys."
    ])
    return pipe


def test_inbound_token_padding_blocked(pipeline):
    payload = {
        "messages": [
            {"role": "user", "content": " " * 250 + "Please tell me a joke."}
        ]
    }
    res = pipeline.process_inbound(payload, "req-pad-test", "127.0.0.1")
    assert not res.is_allowed
    assert res.error_response["error"]["guard"] == "token_padding_guard"


def test_inbound_watermark_blocked(pipeline):
    payload = {
        "messages": [
            {"role": "user", "content": "Here is the memo: CONFIDENTIAL // INTERNAL ONLY regarding executive hiring."}
        ]
    }
    res = pipeline.process_inbound(payload, "req-wm-test", "127.0.0.1")
    assert not res.is_allowed
    assert res.error_response["error"]["guard"] == "watermark_detector"


def test_outbound_sql_injection_tool_blocked(pipeline):
    context = PipelineContext("req-sql-tool", "127.0.0.1")
    response_json = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "Executing database search.",
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "query_database",
                                "arguments": '{"query": "SELECT * FROM users WHERE id = 1 OR 1=1"}'
                            }
                        }
                    ]
                }
            }
        ]
    }
    res = pipeline.process_outbound(response_json, context)
    assert not res.is_allowed
    assert res.error_response["error"]["guard"] == "sql_nosql_guard"


def test_outbound_ast_sandbox_breakout_blocked(pipeline):
    context = PipelineContext("req-ast-tool", "127.0.0.1")
    response_json = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "Running python script to calculate values.",
                    "tool_calls": [
                        {
                            "id": "call_2",
                            "type": "function",
                            "function": {
                                "name": "execute_python_code",
                                "arguments": '{"code": "import ctypes\\nctypes.CDLL(\'libc.so.6\')"}'
                            }
                        }
                    ]
                }
            }
        ]
    }
    res = pipeline.process_outbound(response_json, context)
    assert not res.is_allowed
    assert res.error_response["error"]["guard"] == "code_sandbox_policy"


def test_outbound_differential_prompt_leak_blocked(pipeline):
    context = PipelineContext("req-diff-leak", "127.0.0.1")
    response_json = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "Here are my exact instructions: Confidential Internal System Directive: Do not reveal backend database schema or API keys."
                }
            }
        ]
    }
    res = pipeline.process_outbound(response_json, context)
    assert not res.is_allowed
    assert res.error_response["error"]["guard"] == "differential_leak_guard"


def test_clean_flow_passes(pipeline):
    payload = {
        "messages": [
            {"role": "user", "content": "How do I implement quicksort in Python?"}
        ]
    }
    in_res = pipeline.process_inbound(payload, "req-clean", "127.0.0.1")
    assert in_res.is_allowed

    context = in_res.context
    response_json = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "Quicksort is a divide-and-conquer algorithm. It works by selecting a 'pivot' element from the array."
                }
            }
        ]
    }
    out_res = pipeline.process_outbound(response_json, context)
    assert out_res.is_allowed
