"""Unit Tests for Agent Recursive Subagent Delegation Depth and Cycle Guard."""

import pytest
from proxy.guards.delegation_depth_guard import DelegationDepthGuard, DelegationDepthResult


def test_valid_delegation_chain():
    guard = DelegationDepthGuard(max_delegation_depth=3)
    chain = ["lead_orchestrator", "task_planner"]
    res = guard.inspect_chain(chain)
    assert res.is_blocked is False
    assert res.current_depth == 2


def test_excessive_depth_blocked():
    guard = DelegationDepthGuard(max_delegation_depth=3)
    chain = ["agent_root", "agent_supervisor", "agent_worker", "agent_subworker"]
    res = guard.inspect_chain(chain)
    assert res.is_blocked is True
    assert res.violation_code == "delegation_depth_limit_exceeded"
    assert res.current_depth == 4


def test_cyclic_delegation_blocked():
    guard = DelegationDepthGuard(max_delegation_depth=5)
    chain = ["agent_alpha", "agent_beta", "agent_gamma", "agent_alpha"]
    res = guard.inspect_chain(chain)
    assert res.is_blocked is True
    assert res.violation_code == "cyclic_agent_delegation_detected"
    assert res.detected_cycle == "agent_alpha"


def test_header_string_parsing():
    guard = DelegationDepthGuard(max_delegation_depth=2)
    headers = {"X-Agent-Delegation-Chain": "agent_1 -> agent_2 -> agent_3"}
    res = guard.inspect_payload_or_headers(headers)
    assert res.is_blocked is True
    assert res.violation_code == "delegation_depth_limit_exceeded"
    assert res.current_depth == 3


def test_disabled_mode():
    guard = DelegationDepthGuard(max_delegation_depth=1, block_on_breach=False)
    chain = ["agent_1", "agent_2", "agent_3"]
    res = guard.inspect_chain(chain)
    assert res.is_blocked is False
    assert res.violation_code == "delegation_depth_limit_exceeded"
