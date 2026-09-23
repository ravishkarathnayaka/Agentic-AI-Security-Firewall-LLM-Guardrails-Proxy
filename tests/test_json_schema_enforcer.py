"""Unit tests for StructuredOutputEnforcer."""

import pytest
from proxy.guards.json_schema_enforcer import StructuredOutputEnforcer


def test_valid_json_schema():
    enforcer = StructuredOutputEnforcer()
    raw = '{"action": "lookup_user", "user_id": 42, "is_admin": false}'
    ok, err, parsed = enforcer.validate_json_string(
        raw,
        required_keys=["action", "user_id"],
        expected_schema={"action": str, "user_id": int, "is_admin": bool}
    )
    assert ok is True
    assert err is None
    assert parsed["user_id"] == 42


def test_malformed_json_syntax():
    enforcer = StructuredOutputEnforcer()
    raw = '{"action": "broken_json", '
    ok, err, parsed = enforcer.validate_json_string(raw)
    assert ok is False
    assert "JSON syntax error" in err
    assert parsed is None


def test_missing_required_key():
    enforcer = StructuredOutputEnforcer()
    raw = '{"status": "ok"}'
    ok, err, _ = enforcer.validate_json_string(raw, required_keys=["status", "request_id"])
    assert ok is False
    assert "Missing required property: 'request_id'" in err


def test_type_mismatch():
    enforcer = StructuredOutputEnforcer()
    raw = '{"user_id": "not_an_int"}'
    ok, err, _ = enforcer.validate_json_string(raw, expected_schema={"user_id": int})
    assert ok is False
    assert "Property 'user_id' must be of type int, got str" in err


def test_prototype_pollution_rejection():
    enforcer = StructuredOutputEnforcer()
    raw = '{"action": "run", "__proto__": {"polluted": true}}'
    ok, err, _ = enforcer.validate_json_string(raw)
    assert ok is False
    assert "Prototype pollution key detected" in err


def test_json_depth_limit_enforcement():
    enforcer = StructuredOutputEnforcer(max_depth=3)
    # 4 levels deep
    deep_json = '{"a": {"b": {"c": {"d": 1}}}}'
    ok, err, _ = enforcer.validate_json_string(deep_json)
    assert ok is False
    assert "JSON nesting exceeds maximum depth limit" in err


def test_xss_script_injection_in_json():
    enforcer = StructuredOutputEnforcer()
    raw = '{"payload": "<script>alert(document.cookie)</script>"}'
    ok, err, _ = enforcer.validate_json_string(raw)
    assert ok is False
    assert "Unsafe script or payload pattern detected" in err
