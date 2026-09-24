"""Unit tests for RecursionBudgetGuard."""

import pytest
from proxy.guards.recursion_budget_guard import RecursionBudgetGuard


def test_tool_budget_limit():
    guard = RecursionBudgetGuard(max_tool_calls_per_turn=3)
    call = [{"function": {"name": "fetch", "arguments": {"id": 1}}}]

    res1 = guard.check_tool_calls("req_budget", [{"function": {"name": "f1", "arguments": {}}}])
    assert res1.is_blocked is False

    res2 = guard.check_tool_calls("req_budget", [{"function": {"name": "f2", "arguments": {}}}])
    assert res2.is_blocked is False

    res3 = guard.check_tool_calls("req_budget", [{"function": {"name": "f3", "arguments": {}}}])
    assert res3.is_blocked is False

    # 4th call exceeds max limit of 3
    res4 = guard.check_tool_calls("req_budget", [{"function": {"name": "f4", "arguments": {}}}])
    assert res4.is_blocked is True
    assert res4.violation_code == "tool_call_budget_exceeded"


def test_identical_repeat_loop_detection():
    guard = RecursionBudgetGuard(max_identical_repeats=3)
    call = [{"function": {"name": "scrape_page", "arguments": {"url": "http://example.com"}}}]

    assert guard.check_tool_calls("req_loop", call).is_blocked is False
    assert guard.check_tool_calls("req_loop", call).is_blocked is False

    # 3rd identical invocation triggers loop blocker
    res3 = guard.check_tool_calls("req_loop", call)
    assert res3.is_blocked is True
    assert res3.violation_code == "agent_recursion_loop_detected"


def test_session_reset():
    guard = RecursionBudgetGuard(max_tool_calls_per_turn=2)
    guard.check_tool_calls("req_reset", [{"function": {"name": "f1", "arguments": {}}}])
    guard.check_tool_calls("req_reset", [{"function": {"name": "f2", "arguments": {}}}])

    # Reset clears history
    guard.reset_session("req_reset")
    res_after = guard.check_tool_calls("req_reset", [{"function": {"name": "f3", "arguments": {}}}])
    assert res_after.is_blocked is False
