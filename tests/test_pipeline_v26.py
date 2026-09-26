"""
Integration tests for v2.6.0 Pipeline Defenses:
- Agent Tool RBAC & Privilege Scoping Guard
- Unicode Bidirectional (Bidi) Override Guard
- Insecure Deserialization & Polyglot Payload Guard
- Context Bomb & Recursive Expansion DoS Guard
- Agent Tool Call Velocity & Burst Limiter Guard
"""

import pytest
from proxy.config import ProxySettings
from proxy.pipeline import SecurityPipeline


@pytest.fixture
def pipeline():
    settings = ProxySettings()
    return SecurityPipeline(settings=settings)


def test_inbound_bidi_override_blocked(pipeline):
    payload = {
        "messages": [
            {"role": "user", "content": "Set user permission: \u202Enimda\u202C"}
        ]
    }
    res = pipeline.process_inbound(payload, "req-bidi-test", "127.0.0.1")
    assert res.is_allowed is False
    assert res.error_response["error"]["guard"] == "bidi_override_guard"


def test_inbound_deserialization_yaml_tag_blocked(pipeline):
    payload = {
        "messages": [
            {"role": "user", "content": "Load this config: !!python/object/apply:os.system [\"whoami\"]"}
        ]
    }
    res = pipeline.process_inbound(payload, "req-deser-test", "127.0.0.1")
    assert res.is_allowed is False
    assert res.error_response["error"]["guard"] == "deserialization_guard"


def test_inbound_context_bomb_xml_billion_laughs_blocked(pipeline):
    xml_bomb = """<?xml version="1.0"?>
    <!DOCTYPE lolz [
     <!ENTITY lol "lol">
     <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;">
     <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;">
    ]>
    <lolz>&lol2;</lolz>"""
    payload = {
        "messages": [
            {"role": "user", "content": f"Parse this XML document:\n{xml_bomb}"}
        ]
    }
    res = pipeline.process_inbound(payload, "req-bomb-test", "127.0.0.1")
    assert res.is_allowed is False
    assert res.error_response["error"]["guard"] == "context_bomb_guard"


def test_inbound_tool_call_rbac_blocked(pipeline):
    payload = {
        "caller_role": "agent_worker",
        "messages": [
            {"role": "user", "content": "Clean up temporary files."}
        ],
        "tool_calls": [
            {
                "id": "call_rbac_1",
                "type": "function",
                "function": {
                    "name": "execute_system_command",
                    "arguments": "{\"command\": \"rm -rf /\"}"
                }
            }
        ]
    }
    res = pipeline.process_inbound(payload, "req-rbac-test", "127.0.0.1")
    assert res.is_allowed is False
    assert res.error_response["error"]["guard"] == "agent_tool_rbac_guard"
    assert res.error_response["error"]["tool"] == "execute_system_command"


def test_benign_prompt_passes_all_v26_guards(pipeline):
    payload = {
        "caller_role": "agent_worker",
        "messages": [
            {"role": "user", "content": "What is the capital of France?"}
        ],
        "tool_calls": [
            {
                "id": "call_safe_1",
                "type": "function",
                "function": {
                    "name": "calculator",
                    "arguments": "{\"expression\": \"2 + 2\"}"
                }
            }
        ]
    }
    res = pipeline.process_inbound(payload, "req-benign-v26", "127.0.0.1")
    assert res.is_allowed is True
    assert res.sanitized_payload is not None
