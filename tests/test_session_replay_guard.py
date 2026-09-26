"""
Unit tests for SessionAntiReplayGuard.
Verifies sliding-window nonce tracking, timestamp skew validation, and replay attack prevention.
"""

import pytest
from proxy.guards.session_replay_guard import (
    SessionAntiReplayGuard,
    AntiReplayResult,
)


@pytest.fixture
def replay_guard():
    return SessionAntiReplayGuard(window_seconds=10.0, max_tracked_nonces=100)


def test_first_nonce_passes(replay_guard):
    res = replay_guard.validate_request(session_id="sess_1", nonce="nonce_abc_123", now=1000.0)
    assert not res.is_blocked
    assert res.nonce == "nonce_abc_123"


def test_replayed_nonce_blocked(replay_guard):
    res1 = replay_guard.validate_request(session_id="sess_1", nonce="nonce_abc_123", now=1000.0)
    assert not res1.is_blocked

    # Second presentation of same nonce
    res2 = replay_guard.validate_request(session_id="sess_1", nonce="nonce_abc_123", now=1002.0)
    assert res2.is_blocked
    assert res2.violation_code == "replayed_authorization_detected"


def test_distinct_sessions_isolated(replay_guard):
    res1 = replay_guard.validate_request(session_id="sess_1", nonce="shared_nonce", now=1000.0)
    assert not res1.is_blocked

    # Same nonce in different session is allowed
    res2 = replay_guard.validate_request(session_id="sess_2", nonce="shared_nonce", now=1001.0)
    assert not res2.is_blocked


def test_acceptable_timestamp_skew_passes(replay_guard):
    res = replay_guard.validate_request(
        session_id="sess_1",
        nonce="nonce_skew_ok",
        timestamp=1003.0,
        now=1005.0
    )
    assert not res.is_blocked


def test_excessive_timestamp_skew_blocked(replay_guard):
    res = replay_guard.validate_request(
        session_id="sess_1",
        nonce="nonce_skew_bad",
        timestamp=900.0,  # 100s in past, window is 10s
        now=1000.0
    )
    assert res.is_blocked
    assert res.violation_code == "timestamp_skew_exceeded"
    assert res.skew_seconds == 100.0


def test_sliding_window_expiration(replay_guard):
    # Register nonce at t=1000
    replay_guard.validate_request(session_id="sess_1", nonce="nonce_exp", now=1000.0)

    # Replay after window expires (at t=1020, window is 10s)
    res = replay_guard.validate_request(session_id="sess_1", nonce="nonce_exp", now=1020.0)
    assert not res.is_blocked


def test_validate_tool_call_integration(replay_guard):
    params = {"idempotency_key": "tx_req_9999", "amount": 500}
    res1 = replay_guard.validate_tool_call(session_id="sess_1", tool_name="transfer", parameters=params, now=1000.0)
    assert not res1.is_blocked

    res2 = replay_guard.validate_tool_call(session_id="sess_1", tool_name="transfer", parameters=params, now=1001.0)
    assert res2.is_blocked
    assert res2.violation_code == "replayed_authorization_detected"
