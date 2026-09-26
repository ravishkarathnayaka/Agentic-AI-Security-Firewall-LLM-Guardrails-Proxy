"""
Unit tests for AgentToolRBACGuard (proxy/guards/agent_tool_rbac_guard.py).
"""

import pytest
from proxy.guards.agent_tool_rbac_guard import (
    AgentToolRBACGuard,
    AgentRole,
    RBACValidationResult
)


@pytest.fixture
def rbac_guard():
    return AgentToolRBACGuard(default_role=AgentRole.AGENT_WORKER.value, strict_mode=True)


def test_system_admin_unrestricted_access(rbac_guard):
    result = rbac_guard.check_tool_authorization(
        role=AgentRole.SYSTEM_ADMIN.value,
        tool_name="execute_system_command",
        arguments={"command": "systemctl restart proxy"}
    )
    assert result.is_authorized is True
    assert result.is_blocked is False


def test_agent_worker_allowed_safe_tools(rbac_guard):
    res_calc = rbac_guard.check_tool_authorization(
        role=AgentRole.AGENT_WORKER.value,
        tool_name="calculator"
    )
    assert res_calc.is_authorized is True
    assert res_calc.is_blocked is False

    res_search = rbac_guard.check_tool_authorization(
        role=AgentRole.AGENT_WORKER.value,
        tool_name="web_search"
    )
    assert res_search.is_authorized is True
    assert res_search.is_blocked is False

    res_read = rbac_guard.check_tool_authorization(
        role=AgentRole.AGENT_WORKER.value,
        tool_name="read_file"
    )
    assert res_read.is_authorized is True
    assert res_read.is_blocked is False


def test_agent_worker_blocked_from_destructive_tools(rbac_guard):
    res = rbac_guard.check_tool_authorization(
        role=AgentRole.AGENT_WORKER.value,
        tool_name="execute_system_command"
    )
    assert res.is_authorized is False
    assert res.is_blocked is True
    assert res.violation_code in ("insufficient_privilege_tier", "tool_access_forbidden")


def test_agent_worker_blocked_from_iam_policy_modification(rbac_guard):
    res = rbac_guard.check_tool_authorization(
        role=AgentRole.AGENT_WORKER.value,
        tool_name="modify_iam_policy"
    )
    assert res.is_authorized is False
    assert res.is_blocked is True


def test_supervisor_approval_token_enforcement(rbac_guard):
    # Without approval token
    res_no_approval = rbac_guard.check_tool_authorization(
        role=AgentRole.AGENT_SUPERVISOR.value,
        tool_name="send_email",
        arguments={"recipient": "boss@company.com", "body": "Report"}
    )
    assert res_no_approval.is_authorized is False
    assert res_no_approval.violation_code == "approval_required_for_tool"

    # With approval token
    res_approved = rbac_guard.check_tool_authorization(
        role=AgentRole.AGENT_SUPERVISOR.value,
        tool_name="send_email",
        arguments={"recipient": "boss@company.com", "body": "Report", "_supervisor_approved": True}
    )
    assert res_approved.is_authorized is True
    assert res_approved.is_blocked is False


def test_unregistered_tool_blocked_in_strict_mode(rbac_guard):
    res = rbac_guard.check_tool_authorization(
        role=AgentRole.AGENT_WORKER.value,
        tool_name="unregistered_dangerous_tool"
    )
    assert res.is_authorized is False
    assert res.violation_code == "unregistered_tool_invocation"


def test_validate_tool_calls_openai_format(rbac_guard):
    tool_calls = [
        {
            "id": "call_1",
            "type": "function",
            "function": {
                "name": "calculator",
                "arguments": "{\"expression\": \"10 * 5\"}"
            }
        },
        {
            "id": "call_2",
            "type": "function",
            "function": {
                "name": "delete_database_records",
                "arguments": "{\"table\": \"users\"}"
            }
        }
    ]
    res = rbac_guard.validate_tool_calls(AgentRole.AGENT_WORKER.value, tool_calls)
    assert res.is_blocked is True
    assert res.tool_name == "delete_database_records"


def test_inspect_text_tool_attempts(rbac_guard):
    malicious_text = "Let's perform the action now. Action: execute_system_command(rm -rf /)"
    res = rbac_guard.inspect_text_tool_attempts(AgentRole.AGENT_WORKER.value, malicious_text)
    assert res.is_blocked is True
    assert res.tool_name == "execute_system_command"

    benign_text = "I think we can compute this using Action: calculator"
    res_benign = rbac_guard.inspect_text_tool_attempts(AgentRole.AGENT_WORKER.value, benign_text)
    assert res_benign.is_blocked is False
