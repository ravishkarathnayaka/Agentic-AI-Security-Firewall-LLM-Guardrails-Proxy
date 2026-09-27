"""
Unit tests for StateRollbackGuard.
Verifies LIFO compensation execution, session isolation, and commit mechanics.
"""

import pytest
from proxy.guards.state_rollback_guard import (
    StateRollbackGuard,
    RollbackResult,
)


@pytest.fixture
def rollback_guard():
    return StateRollbackGuard()


def test_record_and_rollback_lifo_order(rollback_guard):
    sess = "sess_checkout_123"
    # Action 1: Reserve Inventory
    act1 = rollback_guard.record_action(
        session_id=sess,
        forward_action="reserve_item",
        forward_params={"sku": "PROD_99", "qty": 2},
        compensation_action="release_item",
        compensation_params={"sku": "PROD_99", "qty": 2}
    )
    # Action 2: Authorize Hold
    act2 = rollback_guard.record_action(
        session_id=sess,
        forward_action="authorize_hold",
        forward_params={"amount": 100},
        compensation_action="void_hold",
        compensation_params={"amount": 100}
    )

    assert rollback_guard.get_pending_count(sess) == 2

    # Execute Rollback (e.g. downstream guard blocked final step)
    res = rollback_guard.rollback_session(sess)
    assert res.is_successful
    assert res.actions_rolled_back == 2
    # Verify LIFO: Action 2 (authorize_hold) rolled back first, then Action 1 (reserve_item)
    assert res.executed_compensations[0]["executed_compensation"] == "void_hold"
    assert res.executed_compensations[1]["executed_compensation"] == "release_item"
    assert rollback_guard.get_pending_count(sess) == 0


def test_commit_session_clears_ledger(rollback_guard):
    sess = "sess_success_456"
    rollback_guard.record_action(
        session_id=sess,
        forward_action="write_temp_file",
        forward_params={"path": "/tmp/a.txt"},
        compensation_action="delete_file",
        compensation_params={"path": "/tmp/a.txt"}
    )
    assert rollback_guard.get_pending_count(sess) == 1
    committed = rollback_guard.commit_session(sess)
    assert committed == 1
    assert rollback_guard.get_pending_count(sess) == 0


def test_empty_session_rollback(rollback_guard):
    res = rollback_guard.rollback_session("non_existent_session")
    assert res.is_successful
    assert res.actions_rolled_back == 0


def test_session_isolation(rollback_guard):
    rollback_guard.record_action("sess_A", "actA", {}, "compA", {})
    rollback_guard.record_action("sess_B", "actB", {}, "compB", {})

    assert rollback_guard.get_pending_count("sess_A") == 1
    assert rollback_guard.get_pending_count("sess_B") == 1

    resA = rollback_guard.rollback_session("sess_A")
    assert resA.actions_rolled_back == 1
    assert rollback_guard.get_pending_count("sess_A") == 0
    assert rollback_guard.get_pending_count("sess_B") == 1
