import pytest
from proxy.guards.agent_action_rollback_journal_guard import AgentActionRollbackJournalGuard


def test_action_recording():
    guard = AgentActionRollbackJournalGuard()
    e1 = guard.record_action("create_file", "/tmp/report.csv", {"undo_action": "delete_file", "path": "/tmp/report.csv"})
    assert e1.startswith("jrn_")
    assert guard.get_pending_actions_count() == 1


def test_compensating_rollback_execution():
    guard = AgentActionRollbackJournalGuard()
    guard.record_action("db_update", "users_table", {"revert_sql": "UPDATE users SET role='user' WHERE id=42"})
    guard.record_action("file_write", "config.json", {"revert_file": "backup_config.json"})
    
    res = guard.execute_compensating_rollback("MALICIOUS_PROMPT_INJECTION")
    assert res.is_blocked is True
    assert res.reverted_entries_count == 2
    assert guard.get_pending_actions_count() == 0
