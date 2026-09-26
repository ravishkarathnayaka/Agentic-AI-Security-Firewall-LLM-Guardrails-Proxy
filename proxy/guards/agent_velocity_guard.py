"""
Agent Tool Velocity and Anomaly Burst Limiter Guard.

Mitigates OWASP LLM08 (Excessive Agency) and OWASP Agentic AI ASI-02 (Rogue Agent Loops)
by tracking invocation velocity, burst frequency anomalies, and repeated tool failures
across autonomous agent identities and session workflows.
"""

import time
from collections import deque, defaultdict
from dataclasses import dataclass, field
from threading import Lock
from typing import Optional, Dict, Deque, Tuple


@dataclass
class VelocityResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    details: str = "Agent tool velocity within authorized parameters"
    agent_id: str = ""
    current_calls_in_window: int = 0
    burst_count: int = 0


class AgentVelocityGuard:
    """
    Tracks and limits tool invocation velocity and detects anomalous burst frequency.
    """

    def __init__(
        self,
        max_calls_per_minute: int = 30,
        max_burst_per_10s: int = 10,
        max_consecutive_failures: int = 5,
        window_seconds: int = 60
    ):
        self.max_calls_per_minute = max_calls_per_minute
        self.max_burst_per_10s = max_burst_per_10s
        self.max_consecutive_failures = max_consecutive_failures
        self.window_seconds = window_seconds

        self._lock = Lock()
        # agent_id -> deque of (timestamp, tool_name, success)
        self._history: Dict[str, Deque[Tuple[float, str, bool]]] = defaultdict(deque)
        self._consecutive_failures: Dict[str, int] = defaultdict(int)

    def record_and_check(
        self,
        agent_id: str,
        tool_name: str,
        current_time: Optional[float] = None
    ) -> VelocityResult:
        """
        Records a tool invocation attempt and evaluates velocity / burst limits.
        """
        now = current_time if current_time is not None else time.time()
        effective_agent = agent_id or "default_agent"

        with self._lock:
            q = self._history[effective_agent]

            # Prune events older than window_seconds
            cutoff_window = now - self.window_seconds
            while q and q[0][0] < cutoff_window:
                q.popleft()

            # Check consecutive failures limit
            if self._consecutive_failures[effective_agent] >= self.max_consecutive_failures:
                return VelocityResult(
                    is_blocked=True,
                    violation_code="excessive_tool_failures_lockout",
                    details=f"Agent '{effective_agent}' locked out due to {self._consecutive_failures[effective_agent]} consecutive tool execution failures.",
                    agent_id=effective_agent,
                    current_calls_in_window=len(q)
                )

            # Check 10-second burst limit
            burst_cutoff = now - 10.0
            burst_count = sum(1 for ts, _, _ in q if ts >= burst_cutoff)
            if burst_count >= self.max_burst_per_10s:
                return VelocityResult(
                    is_blocked=True,
                    violation_code="anomalous_tool_burst_detected",
                    details=f"Agent '{effective_agent}' exceeded burst threshold ({burst_count}/{self.max_burst_per_10s} calls in 10s).",
                    agent_id=effective_agent,
                    current_calls_in_window=len(q),
                    burst_count=burst_count
                )

            # Check window velocity limit
            if len(q) >= self.max_calls_per_minute:
                return VelocityResult(
                    is_blocked=True,
                    violation_code="agent_velocity_limit_exceeded",
                    details=f"Agent '{effective_agent}' exceeded velocity limit ({len(q)}/{self.max_calls_per_minute} calls/min).",
                    agent_id=effective_agent,
                    current_calls_in_window=len(q),
                    burst_count=burst_count
                )

            # Record this attempt
            q.append((now, tool_name, True))

            return VelocityResult(
                is_blocked=False,
                agent_id=effective_agent,
                current_calls_in_window=len(q),
                burst_count=burst_count + 1
            )

    def record_outcome(self, agent_id: str, success: bool):
        """
        Updates consecutive failure counter for the agent.
        """
        effective_agent = agent_id or "default_agent"
        with self._lock:
            if success:
                self._consecutive_failures[effective_agent] = 0
            else:
                self._consecutive_failures[effective_agent] += 1

    def reset_agent(self, agent_id: str):
        """
        Clears history and lockout for an agent.
        """
        with self._lock:
            self._history.pop(agent_id, None)
            self._consecutive_failures.pop(agent_id, None)
