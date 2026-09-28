"""Unit tests for Tool Argument JSON Schema Mutation and Prototype Hijack Guard."""

import pytest
from proxy.guards.schema_mutation_guard import SchemaMutationGuard


@pytest.fixture
def guard() -> SchemaMutationGuard:
    return SchemaMutationGuard(enabled=True, strict_schema_enforcement=True)


@pytest.fixture
def sample_schema() -> dict:
    return {
        "properties": {
            "query": {"type": "string"},
            "limit": {"type": "integer"},
            "dry_run": {"type": "boolean"},
        },
        "required": ["query"],
    }


def test_valid_tool_arguments_pass(guard: SchemaMutationGuard, sample_schema: dict):
    args = {"query": "SELECT count(*) FROM users", "limit": 10, "dry_run": False}
    ok, err = guard.validate_tool_arguments("db_query", args, sample_schema)
    assert ok is True
    assert err is None


def test_prototype_pollution_direct_key_blocked(guard: SchemaMutationGuard, sample_schema: dict):
    args = {"query": "fetch", "__proto__": {"isAdmin": True}}
    ok, err = guard.validate_tool_arguments("db_query", args, sample_schema)
    assert ok is False
    assert "Prototype pollution" in err or "Schema mutation" in err


def test_nested_constructor_pollution_blocked(guard: SchemaMutationGuard):
    args = {"filter": {"metadata": {"constructor": {"prototype": {"polluted": True}}}}}
    ok, err = guard.validate_tool_arguments("search", args)
    assert ok is False
    assert "Prototype pollution" in err


def test_json_string_prototype_injection_blocked(guard: SchemaMutationGuard):
    args = {"raw_payload": '{"__proto__": {"malicious": true}}'}
    ok, err = guard.validate_tool_arguments("webhook", args)
    assert ok is False
    assert "Prototype pollution" in err


def test_smuggled_undeclared_parameter_blocked(guard: SchemaMutationGuard, sample_schema: dict):
    args = {"query": "SELECT 1", "limit": 5, "unauthorized_flag": True}
    ok, err = guard.validate_tool_arguments("db_query", args, sample_schema)
    assert ok is False
    assert "Undeclared argument 'unauthorized_flag'" in err


def test_missing_required_argument_blocked(guard: SchemaMutationGuard, sample_schema: dict):
    args = {"limit": 5}
    ok, err = guard.validate_tool_arguments("db_query", args, sample_schema)
    assert ok is False
    assert "Missing required argument 'query'" in err


def test_type_confusion_mutation_blocked(guard: SchemaMutationGuard, sample_schema: dict):
    # Sending a dictionary where a string was declared
    args = {"query": {"$gt": ""}, "limit": 5}
    ok, err = guard.validate_tool_arguments("db_query", args, sample_schema)
    assert ok is False
    assert "Type confusion mutation" in err


def test_disabled_guard_allows_everything():
    disabled_guard = SchemaMutationGuard(enabled=False)
    args = {"__proto__": {"bypass": True}}
    ok, err = disabled_guard.validate_tool_arguments("test_tool", args)
    assert ok is True
    assert err is None
