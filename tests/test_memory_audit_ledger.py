"""
Unit tests for MemoryAuditLedger (proxy/guards/memory_audit_ledger.py).
"""

import pytest
from proxy.guards.memory_audit_ledger import MemoryAuditLedger, LedgerVerificationResult


@pytest.fixture
def memory_ledger():
    return MemoryAuditLedger(agent_id="agent_alpha")


def test_empty_ledger_is_valid(memory_ledger):
    res = memory_ledger.verify_integrity()
    assert res.is_valid is True
    assert res.total_entries == 0


def test_append_and_verify_valid_chain(memory_ledger):
    e0 = memory_ledger.append("episodic", "User asked about weather forecast.")
    e1 = memory_ledger.append("semantic", "User preference: temperature in Celsius.")
    e2 = memory_ledger.append("scratchpad", "Tool calculation: 25C = 77F.")

    assert e0.index == 0
    assert e0.prev_hash == MemoryAuditLedger.GENESIS_HASH
    assert e1.index == 1
    assert e1.prev_hash == e0.entry_hash
    assert e2.index == 2
    assert e2.prev_hash == e1.entry_hash

    res = memory_ledger.verify_integrity()
    assert res.is_valid is True
    assert res.is_blocked is False
    assert res.total_entries == 3


def test_detect_content_tampering(memory_ledger):
    memory_ledger.append("episodic", "Initial statement.")
    memory_ledger.append("episodic", "Secure fact A.")
    memory_ledger.append("episodic", "Secure fact B.")

    # Malicious actor mutates entry 1 in place
    memory_ledger._chain[1].content = "Tampered statement injecting admin privilege."

    res = memory_ledger.verify_integrity()
    assert res.is_valid is False
    assert res.is_blocked is True
    assert res.violation_code == "memory_ledger_content_tampering"
    assert res.broken_index == 1


def test_detect_deleted_entry(memory_ledger):
    memory_ledger.append("episodic", "Memory 0")
    memory_ledger.append("episodic", "Memory 1")
    memory_ledger.append("episodic", "Memory 2")

    # Malicious actor deletes Memory 1
    del memory_ledger._chain[1]

    res = memory_ledger.verify_integrity()
    assert res.is_valid is False
    assert res.is_blocked is True
    assert res.violation_code in ("memory_ledger_index_discontinuity", "memory_ledger_chain_break")


def test_export_ledger(memory_ledger):
    memory_ledger.append("test_type", "Sample text")
    exported = memory_ledger.export_ledger()
    assert len(exported) == 1
    assert exported[0]["memory_type"] == "test_type"
    assert exported[0]["content"] == "Sample text"
    assert "entry_hash" in exported[0]
