import pytest
from proxy.guards.agent_state_checkpoint_rollback_guard import AgentStateCheckpointRollbackGuard


def test_checkpoint_save_and_rollback():
    guard = AgentStateCheckpointRollbackGuard()
    initial_state = {"plan_step": 1, "memory": ["task_init"]}
    guard.save_checkpoint("sess_10", "chk_1", initial_state)

    # Rollback
    res = guard.rollback_to_latest("sess_10")
    assert res.success
    assert res.checkpoint_id == "chk_1"
    assert res.restored_state["plan_step"] == 1


def test_rollback_nonexistent_session():
    guard = AgentStateCheckpointRollbackGuard()
    res = guard.rollback_to_latest("nonexistent")
    assert not res.success
    assert "No checkpoints found" in res.details
