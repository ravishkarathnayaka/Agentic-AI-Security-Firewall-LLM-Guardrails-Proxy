import pytest
from proxy.guards.schema_validator_guard import StructuredOutputSchemaValidatorGuard


def test_schema_validator_valid_payload():
    guard = StructuredOutputSchemaValidatorGuard()
    schema = {
        "type": "object",
        "required": ["decision", "confidence"],
        "properties": {
            "decision": {"type": "string"},
            "confidence": {"type": "number"}
        }
    }
    raw = '{"decision": "ALLOW", "confidence": 0.98}'
    res = guard.validate_json_response(raw, schema)
    assert res.is_valid
    assert res.parsed_data["decision"] == "ALLOW"


def test_schema_validator_missing_required_field():
    guard = StructuredOutputSchemaValidatorGuard()
    schema = {
        "type": "object",
        "required": ["user_id", "email"],
        "properties": {
            "user_id": {"type": "integer"},
            "email": {"type": "string"}
        }
    }
    raw = '{"user_id": 101}'
    res = guard.validate_json_response(raw, schema)
    assert not res.is_valid
    assert res.violation_code == "missing_required_field"


def test_schema_validator_type_mismatch():
    guard = StructuredOutputSchemaValidatorGuard()
    schema = {
        "type": "object",
        "properties": {
            "age": {"type": "integer"}
        }
    }
    raw = '{"age": "twenty five"}'
    res = guard.validate_json_response(raw, schema)
    assert not res.is_valid
    assert res.violation_code == "schema_type_mismatch"


def test_schema_validator_invalid_json():
    guard = StructuredOutputSchemaValidatorGuard()
    schema = {"type": "object"}
    raw = "Not JSON output at all"
    res = guard.validate_json_response(raw, schema)
    assert not res.is_valid
    assert res.violation_code == "invalid_json_syntax"
