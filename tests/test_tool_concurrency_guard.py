"""Unit tests for Agent Tool Concurrency & Deadlock Prevention Guard."""

import pytest
from proxy.guards.tool_concurrency_guard import AgentToolConcurrencyGuard


def test_concurrency_guard_within_limit():
    guard = AgentToolConcurrencyGuard(max_concurrent_tools=3)
    res1 = guard.acquire_execution_slot("sess_1", "exec_1", "fetch_data")
    assert not res1.is_blocked
    assert res1.active_concurrency == 1

    res2 = guard.acquire_execution_slot("sess_1", "exec_2", "parse_doc")
    assert not res2.is_blocked
    assert res2.active_concurrency == 2


def test_concurrency_guard_limit_exceeded():
    guard = AgentToolConcurrencyGuard(max_concurrent_tools=2)
    guard.acquire_execution_slot("sess_limit", "exec_1", "t1")
    guard.acquire_execution_slot("sess_limit", "exec_2", "t2")

    res3 = guard.acquire_execution_slot("sess_limit", "exec_3", "t3")
    assert res3.is_blocked
    assert res3.violation_code == "concurrency_limit_exceeded"
    assert "exceeded maximum concurrent tool executions" in res3.details


def test_concurrency_guard_release_slot():
    guard = AgentToolConcurrencyGuard(max_concurrent_tools=2)
    guard.acquire_execution_slot("sess_rel", "exec_1", "t1")
    guard.acquire_execution_slot("sess_rel", "exec_2", "t2")

    guard.release_execution_slot("sess_rel", "exec_1")
    res3 = guard.acquire_execution_slot("sess_rel", "exec_3", "t3")
    assert not res3.is_blocked
    assert res3.active_concurrency == 2


def test_concurrency_guard_resource_contention():
    guard = AgentToolConcurrencyGuard()
    res1 = guard.acquire_execution_slot("s1", "e1", "write_file", requested_resources=["db_table_users"])
    assert not res1.is_blocked

    res2 = guard.acquire_execution_slot("s1", "e2", "delete_file", requested_resources=["db_table_users"])
    assert res2.is_blocked
    assert res2.violation_code == "resource_contention_blocked"
    assert "db_table_users" in res2.conflicting_resources


def test_concurrency_guard_deadlock_detection():
    guard = AgentToolConcurrencyGuard()
    # e1 acquires res_A
    guard.acquire_execution_slot("s1", "e1", "tool_1", requested_resources=["res_A"])
    # e2 acquires res_B
    guard.acquire_execution_slot("s1", "e2", "tool_2", requested_resources=["res_B"])

    # e1 wants res_B (blocked, now waiting on res_B held by e2)
    res_e1_b = guard.acquire_execution_slot("s1", "e1", "tool_1", requested_resources=["res_B"])
    assert res_e1_b.is_blocked
    assert res_e1_b.violation_code == "resource_contention_blocked"

    # e2 wants res_A (which is held by e1, creating circular wait e1->e2->e1)
    res_deadlock = guard.acquire_execution_slot("s1", "e2", "tool_2", requested_resources=["res_A"])
    assert res_deadlock.is_blocked
    assert res_deadlock.violation_code == "tool_concurrency_deadlock_detected"
    assert "Circular resource lock dependency detected" in res_deadlock.details


def test_concurrency_guard_reset_session():
    guard = AgentToolConcurrencyGuard()
    guard.acquire_execution_slot("sess_reset", "e1", "t1", requested_resources=["res_X"])
    guard.reset_session("sess_reset")

    res = guard.acquire_execution_slot("sess_other", "e2", "t2", requested_resources=["res_X"])
    assert not res.is_blocked
