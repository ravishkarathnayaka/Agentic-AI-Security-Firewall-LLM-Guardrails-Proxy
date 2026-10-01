import pytest
from proxy.guards.subagent_privilege_escalation_guard import SubagentPrivilegeEscalationGuard


def test_subagent_privilege_nominal():
    guard = SubagentPrivilegeEscalationGuard()
    guard.register_subagent("worker_1", "orchestrator", ["read_doc", "search_index"])
    res = guard.evaluate_subagent_action("worker_1", "read_doc")
    assert not res.is_blocked
    assert res.requested_capability == "read_doc"


def test_subagent_privilege_admin_blocked():
    guard = SubagentPrivilegeEscalationGuard()
    res = guard.evaluate_subagent_action("worker_1", "disable_guardrails")
    assert res.is_blocked
    assert res.violation_code == "SUBAGENT_ADMIN_PRIVILEGE_ATTEMPT"


def test_subagent_privilege_scope_exceeded():
    guard = SubagentPrivilegeEscalationGuard()
    guard.register_subagent("worker_2", "orchestrator", ["read_doc"])
    res = guard.evaluate_subagent_action("worker_2", "write_filesystem")
    assert res.is_blocked
    assert res.violation_code == "SUBAGENT_DELEGATED_CAPABILITY_EXCEEDED"
