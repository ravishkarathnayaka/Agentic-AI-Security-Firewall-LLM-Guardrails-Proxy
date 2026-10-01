"""
Agent Action Idempotency & Duplicate Execution Interceptor Guard
================================================================
Intercepts runaway duplicate tool invocations, accidental double-execution
of non-idempotent high-impact actions, and unprompted replay loops in agent tasks.
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class IdempotencyResult:
    is_blocked: bool
    idempotency_key: str
    violation_code: Optional[str] = None
    details: Optional[str] = None
    first_executed_timestamp: Optional[float] = None
    is_cached_replay: bool = False


class AgentActionIdempotencyGuard:
    """
    Enforces idempotency constraints and deduplication windows on critical agent tool calls.
    """

    # Tools that are inherently non-idempotent and must have idempotency checks
    NON_IDEMPOTENT_TOOLS = {
        "send_email", "charge_payment", "transfer_funds", "deploy_infrastructure",
        "create_user", "purchase_domain", "execute_wire", "order_service",
        "send_sms", "trigger_webhook", "write_ledger_entry"
    }

    def __init__(
        self,
        dedup_window_seconds: float = 60.0,
        max_tracked_entries: int = 5000,
    ):
        self.dedup_window_seconds = dedup_window_seconds
        self.max_tracked_entries = max_tracked_entries
        # idempotency_key -> timestamp
        self._action_cache: Dict[str, float] = {}

    def _generate_action_key(
        self,
        session_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        explicit_idempotency_key: Optional[str] = None
    ) -> str:
        """Computes deterministic digest for action."""
        if explicit_idempotency_key:
            return f"custom_{explicit_idempotency_key}"

        sorted_args = json.dumps(arguments, sort_keys=True, default=str)
        payload = f"{session_id}:{tool_name}:{sorted_args}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]

    def validate_action(
        self,
        session_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        explicit_idempotency_key: Optional[str] = None,
        force_check: bool = False
    ) -> IdempotencyResult:
        """
        Validates if tool execution is an unauthorized duplicate.
        """
        is_sensitive = tool_name.lower() in self.NON_IDEMPOTENT_TOOLS or force_check
        key = self._generate_action_key(session_id, tool_name, arguments, explicit_idempotency_key)
        now = time.time()

        # Clean old entries if capacity is reached
        if len(self._action_cache) >= self.max_tracked_entries:
            cutoff = now - self.dedup_window_seconds
            self._action_cache = {k: v for k, v in self._action_cache.items() if v > cutoff}

        if key in self._action_cache:
            prev_time = self._action_cache[key]
            elapsed = now - prev_time
            if elapsed < self.dedup_window_seconds:
                if is_sensitive:
                    return IdempotencyResult(
                        is_blocked=True,
                        idempotency_key=key,
                        violation_code="duplicate_action_idempotency_blocked",
                        details=(
                            f"Non-idempotent tool '{tool_name}' already executed {elapsed:.1f}s ago "
                            f"(idempotency window: {self.dedup_window_seconds}s). Duplicate call blocked."
                        ),
                        first_executed_timestamp=prev_time,
                        is_cached_replay=True,
                    )
                else:
                    return IdempotencyResult(
                        is_blocked=False,
                        idempotency_key=key,
                        first_executed_timestamp=prev_time,
                        is_cached_replay=True,
                    )

        # Record this execution
        self._action_cache[key] = now
        return IdempotencyResult(
            is_blocked=False,
            idempotency_key=key,
            first_executed_timestamp=now,
            is_cached_replay=False,
        )

    def clear(self) -> None:
        """Clears memory cache."""
        self._action_cache.clear()
