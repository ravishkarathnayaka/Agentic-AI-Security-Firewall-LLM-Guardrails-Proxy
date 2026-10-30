import pytest
from proxy.telemetry.quantum_audit_signer import QuantumAuditSigner


def test_audit_signing_and_verification():
    signer = QuantumAuditSigner()
    r1 = signer.attest_event("sess_01", "INBOUND_SCAN", "PASSED", 0.05, [])
    r2 = signer.attest_event("sess_02", "OUTBOUND_SCAN", "BLOCKED", 0.95, ["HONEYTOKEN_LEAK"])
    assert r1.block_hash != ""
    assert r2.prev_block_hash == r1.block_hash
    assert signer.verify_chain_integrity() is True


def test_audit_chain_tamper_detection():
    signer = QuantumAuditSigner()
    signer.attest_event("sess_01", "INBOUND_SCAN", "PASSED", 0.0, [])
    r2 = signer.attest_event("sess_02", "INBOUND_SCAN", "BLOCKED", 0.9, ["SQL_INJECTION"])
    # Tamper with record
    r2.risk_score = 0.1
    assert signer.verify_chain_integrity() is False
