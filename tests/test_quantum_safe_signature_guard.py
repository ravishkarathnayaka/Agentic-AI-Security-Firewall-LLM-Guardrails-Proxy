import pytest
from proxy.guards.quantum_safe_signature_guard import QuantumSafeSignatureGuard


def test_quantum_signature_nominal_verification():
    guard = QuantumSafeSignatureGuard()
    envelope = guard.generate_envelope("agent_alpha", "execute_analysis()", algorithm="pqc_dilithium3")
    res = guard.verify_envelope(envelope)
    assert res.is_valid
    assert not res.is_blocked
    assert res.verified_algorithm == "pqc_dilithium3"
    assert res.sender_agent_id == "agent_alpha"


def test_quantum_signature_algorithm_downgrade_blocked():
    guard = QuantumSafeSignatureGuard()
    envelope = guard.generate_envelope("agent_alpha", "data", algorithm="md5")
    res = guard.verify_envelope(envelope)
    assert not res.is_valid
    assert res.is_blocked
    assert res.violation_code == "CRYPTO_ALGORITHM_DOWNGRADE_ATTACK"


def test_quantum_signature_replay_attack_blocked():
    guard = QuantumSafeSignatureGuard()
    envelope = guard.generate_envelope("agent_beta", "transfer_funds", algorithm="pqc_kyber1024", nonce="fixed_nonce_1")
    res1 = guard.verify_envelope(envelope)
    assert res1.is_valid

    # Replay with same nonce
    res2 = guard.verify_envelope(envelope)
    assert not res2.is_valid
    assert res2.is_blocked
    assert res2.violation_code == "CRYPTO_REPLAY_ATTACK_DETECTED"


def test_quantum_signature_tampered_payload_blocked():
    guard = QuantumSafeSignatureGuard()
    envelope = guard.generate_envelope("agent_gamma", "original_payload", algorithm="hmac_blake3_pq")
    envelope["payload"] = "tampered_payload"
    res = guard.verify_envelope(envelope)
    assert not res.is_valid
    assert res.is_blocked
    assert res.violation_code == "PQC_SIGNATURE_VERIFICATION_FAILED"
