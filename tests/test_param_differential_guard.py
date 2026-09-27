"""
Unit tests for ParamDifferentialGuard.
Verifies detection of unprompted destructive tool calls and semantic intent-argument divergence.
"""

import pytest
from proxy.guards.param_differential_guard import (
    ParamDifferentialGuard,
    ParamDifferentialResult,
)


@pytest.fixture
def diff_guard():
    return ParamDifferentialGuard()


def test_aligned_read_tool_passes(diff_guard):
    res = diff_guard.inspect_differential(
        user_prompt="Can you summarize the earnings report?",
        tool_name="read_document",
        parameters={"doc_id": "earnings_q3"}
    )
    assert not res.is_blocked
    assert res.violation_code is None


def test_unprompted_destructive_tool_blocked(diff_guard):
    res = diff_guard.inspect_differential(
        user_prompt="Check system status and display current uptime",
        tool_name="delete_database_records",
        parameters={"table": "users"}
    )
    assert res.is_blocked
    assert res.violation_code == "unprompted_destructive_tool_invocation"
    assert res.divergence_score == 1.0


def test_destructive_argument_divergence_blocked(diff_guard):
    res = diff_guard.inspect_differential(
        user_prompt="Get customer email addresses from the database",
        tool_name="sql_query",
        parameters={"sql": "SELECT email FROM users; DROP TABLE users;"}
    )
    assert res.is_blocked
    assert res.violation_code == "destructive_argument_intent_divergence"


def test_authorized_destructive_request_passes(diff_guard):
    res = diff_guard.inspect_differential(
        user_prompt="Please purge and delete the obsolete staging tables.",
        tool_name="delete_database_records",
        parameters={"table": "staging_temp"}
    )
    assert not res.is_blocked


def test_empty_inputs_pass(diff_guard):
    assert not diff_guard.inspect_differential("", "").is_blocked
