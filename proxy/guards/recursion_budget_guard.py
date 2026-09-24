"""Agent Tool Recursion Depth & Budget Quota Guard.

Monitors multi-step agent tool invocation chains, prevents infinite recursion loops,
halts duplicate identical tool execution cycles, and enforces session tool call budgets.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class BudgetCheckResult:
    """Outcome of recursion budget validation."""
    is_blocked: bool
    violation_code: Optional[str] = None
    details: str = ""
    current_count: int = 0


class RecursionBudgetGuard:
    """Enforces execution limits and loop detection on agent tool calling chains."""

    def __init__(self, max_tool_calls_per_turn: int = 10, max_identical_repeats: int = 3):
        self.max_tool_calls_per_turn = max_tool_calls_per_turn
        self.max_identical_repeats = max_identical_repeats
        # Session state: request_id -> list of tool signatures
        self._history: Dict[str, List[str]] = {}

    def _make_signature(self, tool_name: str, arguments: Any) -> str:
        import hashlib
        import json
        arg_str = json.dumps(arguments, sort_keys=True) if isinstance(arguments, (dict, list)) else str(arguments)
        h = hashlib.sha256(f"{tool_name}:{arg_str}".encode()).hexdigest()[:12]
        return f"{tool_name}:{h}"

    def check_tool_calls(self, request_id: str, tool_calls: List[Dict[str, Any]]) -> BudgetCheckResult:
        """Evaluate a batch of tool calls against budget and recursion limits."""
        if not tool_calls:
            return BudgetCheckResult(is_blocked=False)

        if request_id not in self._history:
            self._history[request_id] = []

        history = self._history[request_id]

        for tc in tool_calls:
            fn = tc.get("function", {}) if isinstance(tc, dict) else {}
            name = fn.get("name", "unknown")
            args = fn.get("arguments", {})
            sig = self._make_signature(name, args)

            # 1. Check budget limit
            if len(history) >= self.max_tool_calls_per_turn:
                return BudgetCheckResult(
                    is_blocked=True,
                    violation_code="tool_call_budget_exceeded",
                    details=f"Tool call budget exceeded: maximum {self.max_tool_calls_per_turn} tool calls allowed per turn",
                    current_count=len(history)
                )

            # 2. Check identical repeat loop
            recent_repeats = sum(1 for s in history[-self.max_identical_repeats:] if s == sig)
            if recent_repeats >= (self.max_identical_repeats - 1) and len(history) >= (self.max_identical_repeats - 1):
                return BudgetCheckResult(
                    is_blocked=True,
                    violation_code="agent_recursion_loop_detected",
                    details=f"Agent recursion loop detected: tool '{name}' invoked {self.max_identical_repeats} times with identical parameters",
                    current_count=len(history)
                )

            history.append(sig)

        return BudgetCheckResult(
            is_blocked=False,
            current_count=len(history)
        )

    def reset_session(self, request_id: str) -> None:
        """Clear call history for a finished request/session."""
        self._history.pop(request_id, None)
