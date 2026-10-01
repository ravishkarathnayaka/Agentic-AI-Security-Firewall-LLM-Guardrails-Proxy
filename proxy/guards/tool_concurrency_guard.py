"""
Agent Tool Concurrency & Deadlock Prevention Guard
===================================================
Monitors concurrent tool executions across autonomous agents, detects resource
contention, prevents circular dependency deadlocks, and enforces maximum
concurrency thresholds per session and task thread.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class ConcurrencyResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    details: Optional[str] = None
    active_concurrency: int = 0
    conflicting_resources: List[str] = field(default_factory=list)


class AgentToolConcurrencyGuard:
    """
    Tracks in-flight tool executions, resource acquisition locks, and dependency graphs
    to avert deadlocks and race conditions in autonomous agent swarms.
    """

    def __init__(
        self,
        max_concurrent_tools: int = 5,
        lock_timeout_seconds: float = 30.0,
    ):
        self.max_concurrent_tools = max_concurrent_tools
        self.lock_timeout_seconds = lock_timeout_seconds
        # session_id -> list of active tool execution IDs
        self._active_executions: Dict[str, Set[str]] = {}
        # resource_name -> (holder_execution_id, acquisition_timestamp)
        self._resource_locks: Dict[str, Tuple[str, float]] = {}
        # execution_id -> set of acquired resources
        self._held_resources: Dict[str, Set[str]] = {}
        # execution_id -> set of requested resources (waiting)
        self._waiting_resources: Dict[str, Set[str]] = {}

    def _cleanup_expired_locks(self) -> None:
        """Evicts expired locks past timeout threshold."""
        now = time.time()
        expired = [
            res for res, (_, acquired_at) in self._resource_locks.items()
            if (now - acquired_at) > self.lock_timeout_seconds
        ]
        for res in expired:
            exec_id, _ = self._resource_locks.pop(res)
            if exec_id in self._held_resources:
                self._held_resources[exec_id].discard(res)

    def _has_circular_wait(self, start_exec: str, target_res: str) -> bool:
        """Detects if acquiring target_res leads to a circular dependency cycle."""
        if target_res not in self._resource_locks:
            return False

        current_holder = self._resource_locks[target_res][0]
        visited = set()
        queue = [current_holder]

        while queue:
            curr = queue.pop(0)
            if curr == start_exec:
                return True
            if curr in visited:
                continue
            visited.add(curr)
            # Find what curr is waiting on
            for waited_res in self._waiting_resources.get(curr, set()):
                if waited_res in self._resource_locks:
                    queue.append(self._resource_locks[waited_res][0])

        return False

    def acquire_execution_slot(
        self,
        session_id: str,
        execution_id: str,
        tool_name: str,
        requested_resources: Optional[List[str]] = None,
    ) -> ConcurrencyResult:
        """
        Validates whether an agent can start executing a tool with requested resources.
        """
        self._cleanup_expired_locks()

        active = self._active_executions.setdefault(session_id, set())
        if len(active) >= self.max_concurrent_tools and execution_id not in active:
            return ConcurrencyResult(
                is_blocked=True,
                violation_code="concurrency_limit_exceeded",
                details=(
                    f"Session '{session_id}' exceeded maximum concurrent tool executions "
                    f"({len(active)} >= {self.max_concurrent_tools}) when invoking '{tool_name}'"
                ),
                active_concurrency=len(active),
            )

        requested_resources = requested_resources or []
        conflicts: List[str] = []

        # Check circular dependency deadlock
        for res in requested_resources:
            if self._has_circular_wait(execution_id, res):
                return ConcurrencyResult(
                    is_blocked=True,
                    violation_code="tool_concurrency_deadlock_detected",
                    details=(
                        f"Circular resource lock dependency detected for execution '{execution_id}' "
                        f"waiting on resource '{res}' in tool '{tool_name}'"
                    ),
                    active_concurrency=len(active),
                    conflicting_resources=[res],
                )

        # Check existing lock conflicts
        now = time.time()
        for res in requested_resources:
            if res in self._resource_locks:
                holder, _ = self._resource_locks[res]
                if holder != execution_id:
                    conflicts.append(res)

        if conflicts:
            self._waiting_resources.setdefault(execution_id, set()).update(conflicts)
            return ConcurrencyResult(
                is_blocked=True,
                violation_code="resource_contention_blocked",
                details=(
                    f"Execution '{execution_id}' blocked due to active lock contention on: {conflicts}"
                ),
                active_concurrency=len(active),
                conflicting_resources=conflicts,
            )

        # Successfully acquired
        active.add(execution_id)
        for res in requested_resources:
            self._resource_locks[res] = (execution_id, now)
            self._held_resources.setdefault(execution_id, set()).add(res)
        self._waiting_resources.pop(execution_id, None)

        return ConcurrencyResult(
            is_blocked=False,
            active_concurrency=len(active),
        )

    def release_execution_slot(self, session_id: str, execution_id: str) -> None:
        """Releases all held resource locks and execution slot upon completion."""
        if session_id in self._active_executions:
            self._active_executions[session_id].discard(execution_id)

        held = self._held_resources.pop(execution_id, set())
        for res in held:
            self._resource_locks.pop(res, None)
        self._waiting_resources.pop(execution_id, None)

    def reset_session(self, session_id: str) -> None:
        """Cleans all resources for a terminated session."""
        active = self._active_executions.pop(session_id, set())
        for exec_id in active:
            held = self._held_resources.pop(exec_id, set())
            for res in held:
                self._resource_locks.pop(res, None)
            self._waiting_resources.pop(exec_id, None)
