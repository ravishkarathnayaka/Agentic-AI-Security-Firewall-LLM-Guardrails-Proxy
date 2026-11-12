import pytest
from proxy.telemetry.merkle_audit_ledger import MerkleAuditLedger


def test_merkle_tree_construction():
    ledger = MerkleAuditLedger()
    h1 = ledger.append_entry({"event": "BLOCKED_INJECTION", "ip": "1.2.3.4"})
    h2 = ledger.append_entry({"event": "SANITIZED_PII", "ip": "1.2.3.5"})
    assert ledger.get_root_hash() is not None
    assert len(ledger.leaves) == 2


def test_merkle_inclusion_proof_valid():
    ledger = MerkleAuditLedger()
    for i in range(4):
        ledger.append_entry({"tx_id": i, "status": "APPROVED"})

    proof = ledger.generate_proof(1)
    assert proof is not None
    assert proof.leaf_index == 1
    assert len(proof.audit_path) > 0
    assert proof.root_hash == ledger.get_root_hash()


def test_merkle_tamper_detection():
    ledger = MerkleAuditLedger()
    ledger.append_entry({"entry": "original"})
    root_before = ledger.get_root_hash()
    ledger.append_entry({"entry": "new_tamper"})
    root_after = ledger.get_root_hash()
    assert root_before != root_after
