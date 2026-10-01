"""
Unit tests for Agent Sub-Task TTL & Orphan Killer Guard
"""

import time
import pytest
from proxy.guards.task_ttl_guard import AgentTaskTTLGuard


def test_register_and_valid_execution():
    guard = AgentTaskTTLGuard(default_task_ttl_seconds=30.0)
    res = guard.register_task("task-101", "session-1")
    assert not res.is_blocked
    assert res.status == "active"

    exec_res = guard.validate_task_execution("task-101")
    assert not exec_res.is_blocked
    assert exec_res.status == "active"


def test_task_ttl_expiration():
    guard = AgentTaskTTLGuard(default_task_ttl_seconds=0.05)
    guard.register_task("task-short", "session-1", ttl_seconds=0.05)
    time.sleep(0.08)

    res = guard.validate_task_execution("task-short")
    assert res.is_blocked
    assert res.status == "expired"
    assert res.violation_code == "task_ttl_expired"


def test_orphan_task_cascade_termination():
    guard = AgentTaskTTLGuard()
    guard.register_task("parent-1", "session-1")
    guard.register_task("child-1", "session-1", parent_task_id="parent-1")

    # Kill parent
    guard.kill_task("parent-1", cascade=True)

    # Child must be terminated
    res = guard.validate_task_execution("child-1")
    assert res.is_blocked
    assert res.status == "killed"


def test_unregistered_task_blocked():
    guard = AgentTaskTTLGuard()
    res = guard.validate_task_execution("non-existent-task")
    assert res.is_blocked
    assert res.violation_code == "unregistered_task_execution_blocked"


def test_max_subtasks_quota():
    guard = AgentTaskTTLGuard(max_active_tasks_per_session=2)
    guard.register_task("task-1", "session-quota")
    guard.register_task("task-2", "session-quota")
    res = guard.register_task("task-3", "session-quota")
    assert res.is_blocked
    assert res.violation_code == "max_subtask_budget_exceeded"
