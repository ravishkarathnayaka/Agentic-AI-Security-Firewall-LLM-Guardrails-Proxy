import pytest
from proxy.pipeline import SecurityPipeline


def test_pipeline_delegation_chain_escalation_blocked():
    pipeline = SecurityPipeline()
    payload = {
        "delegation_chain": [
            {"agent_id": "root", "allowed_actions": ["read_data"]},
            {"agent_id": "sub_agent", "allowed_actions": ["read_data", "admin_drop_db"]}
        ],
        "requested_action": "admin_drop_db"
    }
    res = pipeline.process_inbound(payload, "req_del_1", "127.0.0.1")
    assert res.is_allowed is False
    assert res.error_response["error"]["guard"] == "agent_delegation_chain_guard"
