"""Unit tests for Cryptographic Proof-of-Execution (PoE) Receipt Guard."""

import time
import pytest
from proxy.guards.proof_of_execution_guard import ProofOfExecutionGuard


@pytest.fixture
def guard() -> ProofOfExecutionGuard:
    return ProofOfExecutionGuard(secret_key="test-secret-key-12345", max_age_seconds=60.0)


def test_valid_receipt_verification(guard: ProofOfExecutionGuard):
    args = {"action": "transfer", "amount": 1000, "currency": "USD"}
    output = {"status": "success", "tx_id": "tx_9981"}
    
    receipt = guard.generate_receipt(
        agent_id="agent-finance-01",
        session_id="session-xyz-100",
        tool_name="bank_wire",
        arguments=args,
        output=output,
    )
    
    ok, err = guard.verify_receipt(
        receipt=receipt,
        expected_tool_name="bank_wire",
        expected_arguments=args,
        expected_agent_id="agent-finance-01",
    )
    assert ok is True
    assert err is None


def test_tampered_argument_rejected(guard: ProofOfExecutionGuard):
    args = {"action": "transfer", "amount": 1000}
    receipt = guard.generate_receipt(
        agent_id="agent-finance-01",
        session_id="session-xyz-100",
        tool_name="bank_wire",
        arguments=args,
        output={"status": "ok"},
    )
    
    # Verifier supplies actual malicious argument attempted downstream
    tampered_args = {"action": "transfer", "amount": 999999}
    ok, err = guard.verify_receipt(
        receipt=receipt,
        expected_tool_name="bank_wire",
        expected_arguments=tampered_args,
    )
    assert ok is False
    assert "digest mismatch" in err


def test_replay_attack_rejected(guard: ProofOfExecutionGuard):
    args = {"query": "SELECT 1"}
    receipt = guard.generate_receipt(
        agent_id="agent-01",
        session_id="session-1",
        tool_name="db",
        arguments=args,
        output={"rows": 1},
    )
    
    # First verification succeeds
    ok1, err1 = guard.verify_receipt(receipt, expected_tool_name="db", expected_arguments=args)
    assert ok1 is True
    
    # Replay of the same receipt fails due to nonce reuse
    ok2, err2 = guard.verify_receipt(receipt, expected_tool_name="db", expected_arguments=args)
    assert ok2 is False
    assert "Replay attack detected" in err2


def test_tampered_signature_rejected(guard: ProofOfExecutionGuard):
    args = {"query": "SELECT 1"}
    receipt = guard.generate_receipt(
        agent_id="agent-01",
        session_id="session-1",
        tool_name="db",
        arguments=args,
        output={"rows": 1},
    )
    receipt["signature"] = "deadbeef" * 8
    ok, err = guard.verify_receipt(receipt, expected_tool_name="db", expected_arguments=args)
    assert ok is False
    assert "signature verification failed" in err


def test_expired_receipt_rejected(guard: ProofOfExecutionGuard):
    args = {"cmd": "status"}
    receipt = guard.generate_receipt(
        agent_id="agent-01",
        session_id="session-1",
        tool_name="exec",
        arguments=args,
        output={"code": 0},
    )
    # Simulate receipt created 120 seconds ago
    receipt["timestamp"] = time.time() - 120.0
    ok, err = guard.verify_receipt(receipt, expected_tool_name="exec", expected_arguments=args)
    assert ok is False
    assert "expired" in err


def test_mismatched_agent_rejected(guard: ProofOfExecutionGuard):
    args = {"cmd": "status"}
    receipt = guard.generate_receipt(
        agent_id="agent-unauthorized",
        session_id="session-1",
        tool_name="exec",
        arguments=args,
        output={"code": 0},
    )
    ok, err = guard.verify_receipt(
        receipt,
        expected_tool_name="exec",
        expected_arguments=args,
        expected_agent_id="agent-authorized",
    )
    assert ok is False
    assert "Agent ID mismatch" in err
