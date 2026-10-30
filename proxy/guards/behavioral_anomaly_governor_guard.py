"""
Behavioral Anomaly Governor & Token Velocity Rate Guard
======================================================
Monitors session-level interaction dynamics, token velocity (bursts/min),
tool invocation frequency, and anomalous burst behavior to block runaway
autonomous agent loops and cost depletion attacks.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class AnomalyGovernorResult:
    is_blocked: bool
    risk_score: float = 0.0
    violation_code: Optional[str] = None
    details: Optional[str] = None
    current_velocity: float = 0.0


class BehavioralAnomalyGovernorGuard:
    """
    Enforces dynamic velocity limits and detects runaway autonomous execution cycles.
    """

    def __init__(self, max_tokens_per_min: int = 50000, max_tool_calls_per_min: int = 60):
        self.max_tokens_per_min = max_tokens_per_min
        self.max_tool_calls_per_min = max_tool_calls_per_min
        self.session_token_history: Dict[str, List[tuple]] = {}
        self.session_tool_history: Dict[str, List[tuple]] = {}

    def record_and_evaluate(self, session_id: str, token_count: int, tool_call_count: int = 0) -> AnomalyGovernorResult:
        now = time.time()
        cutoff = now - 60.0

        if session_id not in self.session_token_history:
            self.session_token_history[session_id] = []
        if session_id not in self.session_tool_history:
            self.session_tool_history[session_id] = []

        # Prune older than 60s
        self.session_token_history[session_id] = [
            (t, c) for t, c in self.session_token_history[session_id] if t >= cutoff
        ]
        self.session_tool_history[session_id] = [
            (t, c) for t, c in self.session_tool_history[session_id] if t >= cutoff
        ]

        self.session_token_history[session_id].append((now, token_count))
        self.session_tool_history[session_id].append((now, tool_call_count))

        total_tokens = sum(c for _, c in self.session_token_history[session_id])
        total_tools = sum(c for _, c in self.session_tool_history[session_id])

        if total_tokens > self.max_tokens_per_min:
            return AnomalyGovernorResult(
                is_blocked=True,
                risk_score=0.95,
                violation_code="TOKEN_VELOCITY_LIMIT_EXCEEDED",
                details=f"Session exceeded velocity budget: {total_tokens} tokens/min (Limit: {self.max_tokens_per_min})",
                current_velocity=float(total_tokens)
            )

        if total_tools > self.max_tool_calls_per_min:
            return AnomalyGovernorResult(
                is_blocked=True,
                risk_score=0.9,
                violation_code="AUTONOMOUS_RUNAWAY_LOOP_DETECTED",
                details=f"Tool call frequency anomaly: {total_tools} calls/min (Limit: {self.max_tool_calls_per_min})",
                current_velocity=float(total_tools)
            )

        return AnomalyGovernorResult(
            is_blocked=False,
            risk_score=0.0,
            current_velocity=float(total_tokens)
        )
