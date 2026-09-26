"""
Unit tests for ParamReDoSGuard.
Verifies static detection of catastrophic exponential backtracking and unbounded quantifier bounds.
"""

import pytest
from proxy.guards.param_redos_guard import (
    ParamReDoSGuard,
    ReDoSResult,
)


@pytest.fixture
def redos_guard():
    return ParamReDoSGuard(max_pattern_length=300, max_quantifier_value=1000)


def test_benign_regex_passes(redos_guard):
    res = redos_guard.inspect_pattern(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
    assert not res.is_blocked
    assert res.violation_code is None


def test_nested_quantifiers_blocked(redos_guard):
    res = redos_guard.inspect_pattern(r"^(a+)+$")
    assert res.is_blocked
    assert res.violation_code == "catastrophic_redos_signature"
    assert res.vulnerability_type == "nested_quantifiers_exponential_backtracking"


def test_overlapping_alternation_blocked(redos_guard):
    res = redos_guard.inspect_pattern(r"^(a|aa)+$")
    assert res.is_blocked
    assert res.violation_code == "catastrophic_redos_signature"
    assert res.vulnerability_type == "overlapping_alternation_repetition"


def test_nested_wildcard_blocked(redos_guard):
    res = redos_guard.inspect_pattern(r"^(.*)+$")
    assert res.is_blocked
    assert res.violation_code == "catastrophic_redos_signature"
    assert res.vulnerability_type in ("nested_wildcard_quantifier", "nested_quantifiers_exponential_backtracking")


def test_excessive_quantifier_bound_blocked(redos_guard):
    res = redos_guard.inspect_pattern(r"a{50000}")
    assert res.is_blocked
    assert res.violation_code == "excessive_quantifier_bound"


def test_excessive_pattern_length_blocked(redos_guard):
    long_pat = "a" * 350
    res = redos_guard.inspect_pattern(long_pat)
    assert res.is_blocked
    assert res.violation_code == "excessive_regex_length"


def test_invalid_syntax_blocked(redos_guard):
    res = redos_guard.inspect_pattern(r"(incomplete[group")
    assert res.is_blocked
    assert res.violation_code == "invalid_regex_syntax"


def test_tool_call_inspection_detects_redos(redos_guard):
    res = redos_guard.inspect_tool_call(
        tool_name="grep_code",
        parameters={"pattern": "([0-9]+)+", "path": "src/"}
    )
    assert res.is_blocked
    assert res.violation_code == "catastrophic_redos_signature"
