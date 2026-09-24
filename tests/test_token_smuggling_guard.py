"""Unit tests for TokenSmugglingGuard."""

import pytest
from proxy.guards.token_smuggling_guard import TokenSmugglingGuard


def test_zero_width_space_burst_blocked():
    guard = TokenSmugglingGuard(block_threshold=4)
    # 5 zero width spaces interleaved
    raw = "i\u200Bg\u200Bn\u200Bo\u200Br\u200Be"
    res = guard.inspect(raw)
    assert res.is_blocked is True
    assert res.violation_code == "zero_width_token_smuggling"
    assert res.sanitized_text == "ignore"
    assert res.zero_width_count == 5


def test_bidi_override_blocked():
    guard = TokenSmugglingGuard()
    raw = "Normal text \u202Ereversed instructions\u202C continuation"
    res = guard.inspect(raw)
    assert res.is_blocked is True
    assert res.violation_code == "bidi_override_smuggling"
    assert res.sanitized_text == "Normal text reversed instructions continuation"


def test_isolated_zero_width_stripped_not_blocked():
    guard = TokenSmugglingGuard(block_threshold=4)
    raw = "Hello\u200Bworld"
    res = guard.inspect(raw)
    assert res.is_blocked is False
    assert res.sanitized_text == "Helloworld"
    assert res.zero_width_count == 1


def test_clean_text_no_modification():
    guard = TokenSmugglingGuard()
    raw = "Simple clean prompt for machine learning."
    res = guard.inspect(raw)
    assert res.is_blocked is False
    assert res.sanitized_text == raw
    assert res.zero_width_count == 0


def test_empty_string():
    guard = TokenSmugglingGuard()
    res = guard.inspect("")
    assert res.is_blocked is False
    assert res.sanitized_text == ""
    assert res.zero_width_count == 0
