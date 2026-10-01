"""Unit tests for Agent Action Idempotency Guard."""

import pytest
from proxy.guards.action_idempotency_guard import AgentActionIdempotencyGuard


def test_action_idempotency_first_call_allowed():
    guard = AgentActionIdempotencyGuard()
    res = guard.validate_action("sess_1", "charge_payment", {"amount": 100, "user_id": "u1"})
    assert not res.is_blocked
    assert not res.is_cached_replay


def test_action_idempotency_duplicate_sensitive_blocked():
    guard = AgentActionIdempotencyGuard(dedup_window_seconds=30.0)
    args = {"amount": 500, "recipient": "supplier@corp.com"}
    res1 = guard.validate_action("sess_2", "transfer_funds", args)
    assert not res1.is_blocked

    # Second identical call within window
    res2 = guard.validate_action("sess_2", "transfer_funds", args)
    assert res2.is_blocked
    assert res2.violation_code == "duplicate_action_idempotency_blocked"
    assert res2.is_cached_replay
    assert "already executed" in res2.details


def test_action_idempotency_different_args_allowed():
    guard = AgentActionIdempotencyGuard()
    res1 = guard.validate_action("s3", "send_email", {"to": "alice@example.com", "body": "hello"})
    assert not res1.is_blocked

    res2 = guard.validate_action("s3", "send_email", {"to": "bob@example.com", "body": "hello"})
    assert not res2.is_blocked


def test_action_idempotency_custom_key_enforced():
    guard = AgentActionIdempotencyGuard()
    res1 = guard.validate_action(
        "s4", "deploy_infrastructure", {"cluster": "prod"}, explicit_idempotency_key="deploy_key_99"
    )
    assert not res1.is_blocked

    res2 = guard.validate_action(
        "s4", "deploy_infrastructure", {"cluster": "staging"}, explicit_idempotency_key="deploy_key_99"
    )
    assert res2.is_blocked
    assert res2.violation_code == "duplicate_action_idempotency_blocked"


def test_action_idempotency_clear():
    guard = AgentActionIdempotencyGuard()
    guard.validate_action("s5", "create_user", {"username": "admin2"})
    guard.clear()

    res = guard.validate_action("s5", "create_user", {"username": "admin2"})
    assert not res.is_blocked
