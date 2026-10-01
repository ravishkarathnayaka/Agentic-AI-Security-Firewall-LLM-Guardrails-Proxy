"""
Agent Sub-Task TTL & Orphan Killer Guard
========================================
Tracks and limits time-to-live (TTL) for agent sub-tasks and background workers,
terminating orphaned worker processes, runaway infinite sub-loops, and zombie
delegations that outlive their parent execution context.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class TaskRecord:
    task_id: str
    parent_task_id: Optional[str]
    session_id: str
    created_at: float
    ttl_seconds: float
    last_heartbeat: float
    status: str = "active"  # "active", "completed", "expired", "killed"


@dataclass
class TaskValidationResult:
    is_blocked: bool
    status: str
    violation_code: Optional[str] = None
    details: Optional[str] = None
    remaining_ttl: float = 0.0


class AgentTaskTTLGuard:
    """
    Guards against runaway agent worker proliferation, zombie background loops,
    and orphaned sub-agents outliving their parent task scope.
    """

    def __init__(
        self,
        default_task_ttl_seconds: float = 120.0,
        heartbeat_timeout_seconds: float = 45.0,
        max_active_tasks_per_session: int = 15,
    ):
        self.default_task_ttl = default_task_ttl_seconds
        self.heartbeat_timeout = heartbeat_timeout_seconds
        self.max_active_tasks = max_active_tasks_per_session
        self._tasks: Dict[str, TaskRecord] = {}

    def register_task(
        self,
        task_id: str,
        session_id: str,
        parent_task_id: Optional[str] = None,
        ttl_seconds: Optional[float] = None,
    ) -> TaskValidationResult:
        """Registers a new sub-task execution context."""
        now = time.time()
        ttl = ttl_seconds if ttl_seconds is not None else self.default_task_ttl

        # Verify parent isn't already killed/expired
        if parent_task_id and parent_task_id in self._tasks:
            parent = self._tasks[parent_task_id]
            if parent.status in ("killed", "expired"):
                return TaskValidationResult(
                    is_blocked=True,
                    status="rejected_orphaned",
                    violation_code="orphan_subtask_spawn_blocked",
                    details=f"Cannot spawn child task '{task_id}': parent '{parent_task_id}' is {parent.status}.",
                )

        # Check session active task budget
        active_in_session = sum(
            1 for t in self._tasks.values()
            if t.session_id == session_id and t.status == "active"
        )
        if active_in_session >= self.max_active_tasks:
            return TaskValidationResult(
                is_blocked=True,
                status="rejected_quota_exceeded",
                violation_code="max_subtask_budget_exceeded",
                details=f"Session '{session_id}' reached active task limit of {self.max_active_tasks}.",
            )

        self._tasks[task_id] = TaskRecord(
            task_id=task_id,
            parent_task_id=parent_task_id,
            session_id=session_id,
            created_at=now,
            ttl_seconds=ttl,
            last_heartbeat=now,
            status="active",
        )

        return TaskValidationResult(
            is_blocked=False,
            status="active",
            remaining_ttl=ttl,
        )

    def validate_task_execution(self, task_id: str) -> TaskValidationResult:
        """Validates if a task is legally allowed to continue execution."""
        now = time.time()
        if task_id not in self._tasks:
            return TaskValidationResult(
                is_blocked=True,
                status="unknown_task",
                violation_code="unregistered_task_execution_blocked",
                details=f"Task '{task_id}' has not been registered in the security context.",
            )

        task = self._tasks[task_id]
        if task.status in ("completed", "killed", "expired"):
            return TaskValidationResult(
                is_blocked=True,
                status=task.status,
                violation_code=f"task_status_{task.status}_blocked",
                details=f"Task '{task_id}' execution forbidden because task is {task.status}.",
            )

        # Check TTL
        elapsed = now - task.created_at
        remaining = task.ttl_seconds - elapsed
        if remaining <= 0:
            task.status = "expired"
            return TaskValidationResult(
                is_blocked=True,
                status="expired",
                violation_code="task_ttl_expired",
                details=f"Task '{task_id}' exceeded TTL of {task.ttl_seconds}s (elapsed: {elapsed:.1f}s).",
            )

        # Check parent status if child
        if task.parent_task_id and task.parent_task_id in self._tasks:
            parent = self._tasks[task.parent_task_id]
            if parent.status in ("killed", "expired"):
                task.status = "killed"
                return TaskValidationResult(
                    is_blocked=True,
                    status="killed",
                    violation_code="orphan_task_killed",
                    details=f"Orphan task '{task_id}' terminated: parent task '{task.parent_task_id}' is {parent.status}.",
                )

        return TaskValidationResult(
            is_blocked=False,
            status="active",
            remaining_ttl=remaining,
        )

    def heartbeat(self, task_id: str) -> bool:
        """Updates last heartbeat timestamp for task."""
        if task_id in self._tasks and self._tasks[task_id].status == "active":
            self._tasks[task_id].last_heartbeat = time.time()
            return True
        return False

    def complete_task(self, task_id: str) -> bool:
        """Marks task as successfully completed."""
        if task_id in self._tasks:
            self._tasks[task_id].status = "completed"
            return True
        return False

    def kill_task(self, task_id: str, cascade: bool = True) -> int:
        """Explicitly terminates a task and optionally its children."""
        killed_count = 0
        if task_id in self._tasks:
            self._tasks[task_id].status = "killed"
            killed_count += 1

        if cascade:
            for t_id, record in self._tasks.items():
                if record.parent_task_id == task_id and record.status == "active":
                    record.status = "killed"
                    killed_count += 1
        return killed_count

    def clear(self) -> None:
        """Clears memory state."""
        self._tasks.clear()
