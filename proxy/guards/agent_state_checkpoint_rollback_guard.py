"""
Agent State Checkpoint & Micro-Rollback Guard
=============================================
Maintains immutable working-memory snapshots of autonomous agents during
multi-step plan execution. Automatically triggers micro-rollbacks to the last
known safe checkpoint if an intermediate step triggers a policy breach.
"""

import copy
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class RollbackResult:
    success: bool
    checkpoint_id: Optional[str] = None
    restored_state: Optional[Dict[str, Any]] = None
    details: Optional[str] = None


class AgentStateCheckpointRollbackGuard:
    """
    Saves and restores working state snapshots for transactional agent safety.
    """

    def __init__(self, max_checkpoints_per_session: int = 10):
        self.max_checkpoints_per_session = max_checkpoints_per_session
        # session_id -> list of (checkpoint_id, timestamp, state_dict)
        self._checkpoints: Dict[str, List[tuple[str, float, Dict[str, Any]]]] = {}

    def save_checkpoint(
        self, session_id: str, checkpoint_id: str, state_payload: Dict[str, Any]
    ) -> str:
        """Saves a deep copy of the current safe working state."""
        history = self._checkpoints.setdefault(session_id, [])
        deep_copy_state = copy.deepcopy(state_payload)
        history.append((checkpoint_id, time.time(), deep_copy_state))
        if len(history) > self.max_checkpoints_per_session:
            history.pop(0)
        return checkpoint_id

    def rollback_to_latest(self, session_id: str) -> RollbackResult:
        """Restores the most recent safe checkpoint, discarding unsafe intermediate state."""
        if session_id not in self._checkpoints or not self._checkpoints[session_id]:
            return RollbackResult(
                success=False,
                details=f"No checkpoints found for session '{session_id}'. Cannot rollback.",
            )

        checkpoint_id, ts, state_dict = self._checkpoints[session_id][-1]
        return RollbackResult(
            success=True,
            checkpoint_id=checkpoint_id,
            restored_state=copy.deepcopy(state_dict),
            details=f"Successfully rolled back session '{session_id}' to checkpoint '{checkpoint_id}'.",
        )

    def reset(self, session_id: Optional[str] = None) -> None:
        if session_id:
            self._checkpoints.pop(session_id, None)
        else:
            self._checkpoints.clear()
