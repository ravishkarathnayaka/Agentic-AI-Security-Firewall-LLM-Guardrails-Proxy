"""
Unit tests for CapabilityTokenGuard.
Verifies cryptographic signature validation, TTL expiration, nonce replay, tool binding, and scope enforcement.
"""

import pytest
import time
from proxy.guards.capability_token_guard import (
    CapabilityTokenGuard,
    CapabilityTokenResult,
)


@pytest.fixture
def guard():
    return CapabilityTokenGuard(secret_key="test-secret-salt-1234", default_ttl_seconds=60.0)


def test_valid_token_verification(guard):
    tok = guard.issue_token(agent_id="agent_alpha", tool_name="fetch_url", scopes=["read:web"])
    res = guard.verify_token(token_str=tok, expected_tool="fetch_url", required_scope="read:web")
    assert res.is_valid
    assert not res.is_blocked
    assert res.agent_id == "agent_alpha"
    assert "read:web" in res.granted_scopes


def test_expired_token_blocked(guard):
    now = 1000.0
    tok = guard.issue_token(agent_id="agent_alpha", tool_name="fetch_url", scopes=["read:web"], ttl_seconds=10.0)
    # Check at t=1050 (expired)
    res = guard.verify_token(token_str=tok, expected_tool="fetch_url", now=time.time() + 100.0)
    assert not res.is_valid
    assert res.is_blocked
    assert res.violation_code == "expired_capability_token"


def test_invalid_signature_blocked(guard):
    tok = guard.issue_token(agent_id="agent_alpha", tool_name="fetch_url", scopes=["read:web"])
    # Tamper with token bytes
    tampered = tok[:-4] + "AAAA"
    res = guard.verify_token(token_str=tampered, expected_tool="fetch_url")
    assert not res.is_valid
    assert res.is_blocked
    assert res.violation_code in ("invalid_capability_signature", "malformed_capability_token")


def test_replayed_nonce_blocked(guard):
    tok = guard.issue_token(agent_id="agent_alpha", tool_name="fetch_url", scopes=["read:web"])
    res1 = guard.verify_token(token_str=tok, expected_tool="fetch_url")
    assert res1.is_valid

    # Replay same token
    res2 = guard.verify_token(token_str=tok, expected_tool="fetch_url")
    assert not res2.is_valid
    assert res2.is_blocked
    assert res2.violation_code == "replayed_capability_nonce"


def test_unauthorized_tool_binding_blocked(guard):
    tok = guard.issue_token(agent_id="agent_alpha", tool_name="fetch_url", scopes=["read:web"])
    res = guard.verify_token(token_str=tok, expected_tool="execute_system_command")
    assert not res.is_valid
    assert res.is_blocked
    assert res.violation_code == "unauthorized_tool_binding"


def test_insufficient_scope_blocked(guard):
    tok = guard.issue_token(agent_id="agent_alpha", tool_name="query_db", scopes=["read:db:analytics"])
    res = guard.verify_token(token_str=tok, expected_tool="query_db", required_scope="write:db:salaries")
    assert not res.is_valid
    assert res.is_blocked
    assert res.violation_code == "insufficient_capability_scope"


def test_wildcard_scope_matching(guard):
    tok = guard.issue_token(agent_id="agent_alpha", tool_name="query_db", scopes=["read:*"])
    res = guard.verify_token(token_str=tok, expected_tool="query_db", required_scope="read:db:customers")
    assert res.is_valid
    assert not res.is_blocked


def test_inspect_tool_call_integration(guard):
    tok = guard.issue_token(agent_id="agent_worker", tool_name="read_file", scopes=["read:fs"])
    params = {"path": "/var/log/app.log", "capability_token": tok}
    res = guard.inspect_tool_call(tool_name="read_file", parameters=params, required_scope="read:fs")
    assert res.is_valid
    assert not res.is_blocked
