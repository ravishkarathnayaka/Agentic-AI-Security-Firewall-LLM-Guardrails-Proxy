import time
import pytest
from proxy.guards.zk_proof_verifier_guard import ZKProofVerifierGuard


def test_valid_zk_proof():
    guard = ZKProofVerifierGuard()
    proof_payload = {
        "circuit_id": "zk_rbac_tier_1",
        "proof": "a9f8b7c6d5e4f3a2b1c09876543210fedcba9876543210fedcba9876543210fe",
        "public_inputs": {"agent_role": "analyst", "max_tokens": 4000},
        "timestamp": time.time()
    }
    res = guard.verify_zk_proof(proof_payload)
    assert res.is_valid is True
    assert res.is_blocked is False
    assert res.proof_digest is not None


def test_expired_zk_proof_replay():
    guard = ZKProofVerifierGuard()
    proof_payload = {
        "circuit_id": "zk_rbac_tier_1",
        "proof": "a9f8b7c6d5e4f3a2b1c09876543210fedcba9876543210fedcba9876543210fe",
        "timestamp": time.time() - 600.0  # 10 minutes ago
    }
    res = guard.verify_zk_proof(proof_payload)
    assert res.is_blocked is True
    assert res.violation_code == "ZK_PROOF_REPLAY_EXPIRED"


def test_unregistered_circuit():
    guard = ZKProofVerifierGuard()
    proof_payload = {
        "circuit_id": "zk_unregistered_malicious_circuit",
        "proof": "valid_looking_proof_data_hex_string_32_bytes_long",
        "timestamp": time.time()
    }
    res = guard.verify_zk_proof(proof_payload)
    assert res.is_blocked is True
    assert res.violation_code == "ZK_UNKNOWN_CIRCUIT"
