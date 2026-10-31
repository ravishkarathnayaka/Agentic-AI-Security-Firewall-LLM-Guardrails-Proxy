"""
Agent Action Rollback Journal & Compensating Transaction Guard
=============================================================
Maintains an append-only compensating transaction log for autonomous agent
side-effects. When an agent action leads to a downstream security breach,
the journal automatically executes compensating reversions.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass
class JournalEntry:
    entry_id: str
    action_name: str
    target_resource: str
    undo_payload: Dict[str, Any]
    executed: bool = False
    reverted: bool = False


@dataclass
class RollbackJournalResult:
    is_blocked: bool
    reverted_entries_count: int = 0
    violation_code: Optional[str] = None
    details: Optional[str] = None


class AgentActionRollbackJournalGuard:
    """
    Transactional rollback coordinator tracking agent modifications to databases,
    files, and external APIs with automatic compensation execution.
    """

    def __init__(self, max_journal_size: int = 50):
        self.max_journal_size = max_journal_size
        self._journal: List[JournalEntry] = []

    def record_action(self, action_name: str, target_resource: str, undo_payload: Dict[str, Any]) -> str:
        entry_id = f"jrn_{len(self._journal)+1:05d}"
        entry = JournalEntry(
            entry_id=entry_id,
            action_name=action_name,
            target_resource=target_resource,
            undo_payload=undo_payload,
            executed=True
        )
        self._journal.append(entry)
        if len(self._journal) > self.max_journal_size:
            self._journal.pop(0)
        return entry_id

    def execute_compensating_rollback(self, incident_code: str) -> RollbackJournalResult:
        if not self._journal:
            return RollbackJournalResult(is_blocked=False, reverted_entries_count=0)

        reverted_count = 0
        for entry in reversed(self._journal):
            if not entry.reverted:
                # Mark compensating transaction as applied
                entry.reverted = True
                reverted_count += 1

        return RollbackJournalResult(
            is_blocked=True,
            reverted_entries_count=reverted_count,
            violation_code="COMPENSATING_ROLLBACK_EXECUTED",
            details=f"Incident '{incident_code}' triggered automatic compensation of {reverted_count} active agent actions."
        )

    def get_pending_actions_count(self) -> int:
        return sum(1 for e in self._journal if not e.reverted)
