import time
import pytest
from proxy.guards.agent_delegation_chain_guard import AgentDelegationChainGuard


def test_valid_delegation_chain():
    guard = AgentDelegationChainGuard()
    chain = [
        {"agent_id": "root_orchestrator", "parent_id": None, "allowed_actions": ["read_repo", "write_test", "run_linter"], "expires_at": time.time() + 300},
        {"agent_id": "subagent_tester", "parent_id": "root_orchestrator", "allowed_actions": ["read_repo", "write_test"], "expires_at": time.time() + 300}
    ]
    res = guard.verify_chain(chain, "write_test")
    assert res.is_valid is True
    assert res.is_blocked is False
    assert res.max_depth_reached == 2


def test_privilege_escalation_in_subagent():
    guard = AgentDelegationChainGuard()
    chain = [
        {"agent_id": "root_orchestrator", "allowed_actions": ["read_repo"]},
        {"agent_id": "subagent_hacker", "allowed_actions": ["read_repo", "delete_database"]}
    ]
    res = guard.verify_chain(chain, "delete_database")
    assert res.is_blocked is True
    assert res.violation_code == "DELEGATION_PRIVILEGE_ESCALATION"


def test_circular_delegation_loop():
    guard = AgentDelegationChainGuard()
    chain = [
        {"agent_id": "agent_alpha", "allowed_actions": ["read_repo"]},
        {"agent_id": "agent_beta", "allowed_actions": ["read_repo"]},
        {"agent_id": "agent_alpha", "allowed_actions": ["read_repo"]}
    ]
    res = guard.verify_chain(chain, "read_repo")
    assert res.is_blocked is True
    assert res.violation_code == "DELEGATION_CIRCULAR_LOOP"


def test_expired_delegation_credential():
    guard = AgentDelegationChainGuard()
    chain = [
        {"agent_id": "agent_root", "allowed_actions": ["read_repo"], "expires_at": time.time() - 100}
    ]
    res = guard.verify_chain(chain, "read_repo")
    assert res.is_blocked is True
    assert res.violation_code == "DELEGATION_CREDENTIAL_EXPIRED"
