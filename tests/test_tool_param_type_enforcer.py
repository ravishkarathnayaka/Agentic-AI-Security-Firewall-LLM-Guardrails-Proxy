import json
import pytest
from proxy.guards.tool_param_type_enforcer import (
    ToolParamTypeEnforcer,
    ToolParamValidationResult,
    ParamConstraint,
)


@pytest.fixture
def enforcer():
    return ToolParamTypeEnforcer(strict_mode=False)


def test_valid_calculator_call(enforcer):
    args = json.dumps({"expression": "2 * (3 + 4) / 5"})
    res = enforcer.validate_tool_call("calculator", args)
    assert res.is_valid is True
    assert res.is_blocked is False


def test_calculator_regex_violation_with_shell_characters(enforcer):
    args = json.dumps({"expression": "2 + 2; rm -rf /"})
    res = enforcer.validate_tool_call("calculator", args)
    assert res.is_valid is False
    assert res.is_blocked is True
    assert res.violation_code == "parameter_pattern_violation"
    assert res.parameter_name == "expression"


def test_missing_required_parameter(enforcer):
    args = json.dumps({"limit": 50})
    res = enforcer.validate_tool_call("database_query", args)
    assert res.is_valid is False
    assert res.is_blocked is True
    assert res.violation_code == "missing_required_parameter"
    assert res.parameter_name == "query"


def test_parameter_type_mismatch_string_for_int(enforcer):
    args = json.dumps({"query": "SELECT * FROM users", "limit": "fifty"})
    res = enforcer.validate_tool_call("database_query", args)
    assert res.is_valid is False
    assert res.is_blocked is True
    assert res.violation_code == "parameter_type_mismatch"
    assert res.parameter_name == "limit"


def test_parameter_type_mismatch_bool_for_int(enforcer):
    args = json.dumps({"query": "SELECT * FROM users", "limit": True})
    res = enforcer.validate_tool_call("database_query", args)
    assert res.is_valid is False
    assert res.is_blocked is True
    assert res.violation_code == "parameter_type_mismatch"
    assert res.parameter_name == "limit"


def test_numerical_bounds_exceeded_maximum(enforcer):
    args = json.dumps({"query": "SELECT * FROM logs", "limit": 999999})
    res = enforcer.validate_tool_call("database_query", args)
    assert res.is_valid is False
    assert res.is_blocked is True
    assert res.violation_code == "parameter_bounds_exceeded"


def test_numerical_bounds_exceeded_minimum(enforcer):
    args = json.dumps({"query": "SELECT * FROM logs", "limit": 0})
    res = enforcer.validate_tool_call("database_query", args)
    assert res.is_valid is False
    assert res.is_blocked is True
    assert res.violation_code == "parameter_bounds_exceeded"


def test_parameter_enum_violation(enforcer):
    args = json.dumps({
        "recipient": "security@company.com",
        "subject": "System Incident",
        "body": "Detailed findings...",
        "priority": "catastrophic"
    })
    res = enforcer.validate_tool_call("send_email", args)
    assert res.is_valid is False
    assert res.is_blocked is True
    assert res.violation_code == "parameter_enum_violation"
    assert res.parameter_name == "priority"


def test_parameter_string_length_exceeded(enforcer):
    args = json.dumps({
        "recipient": "test@example.com",
        "subject": "A" * 200,
        "body": "Safe content"
    })
    res = enforcer.validate_tool_call("send_email", args)
    assert res.is_valid is False
    assert res.is_blocked is True
    assert res.violation_code == "parameter_length_exceeded"


def test_malformed_json_arguments(enforcer):
    args = '{"query": "SELECT 1", broken json}'
    res = enforcer.validate_tool_call("database_query", args)
    assert res.is_valid is False
    assert res.is_blocked is True
    assert res.violation_code == "malformed_tool_arguments"


def test_strict_mode_unregistered_tool():
    strict_enforcer = ToolParamTypeEnforcer(strict_mode=True)
    res = strict_enforcer.validate_tool_call("unknown_tool", "{}")
    assert res.is_valid is False
    assert res.is_blocked is True
    assert res.violation_code == "unregistered_tool_schema"


def test_non_strict_mode_allows_unregistered_tool(enforcer):
    res = enforcer.validate_tool_call("custom_unregistered_tool", json.dumps({"param": "val"}))
    assert res.is_valid is True
    assert res.is_blocked is False
