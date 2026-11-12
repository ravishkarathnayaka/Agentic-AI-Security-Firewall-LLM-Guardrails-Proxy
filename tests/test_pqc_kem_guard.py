import time
import pytest
from proxy.guards.pqc_kem_guard import PQCKEMGuard


def test_valid_ml_kem_768_handshake():
    guard = PQCKEMGuard()
    payload = {
        "cipher_suite": "ML-KEM-768",
        "encapsulated_ciphertext": "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef00112233445566778899",
        "pk_fingerprint": "kyber_pk_fp_node_99182",
        "timestamp": time.time()
    }
    res = guard.verify_handshake(payload)
    assert res.is_valid is True
    assert res.is_blocked is False
    assert res.shared_secret_fingerprint is not None
    assert res.security_level_bits == 192


def test_rejected_legacy_rsa_cipher():
    guard = PQCKEMGuard()
    payload = {
        "cipher_suite": "RSA-2048",
        "encapsulated_ciphertext": "rsa_ciphertext_payload_data_here_must_be_long_enough_to_test_properly",
        "pk_fingerprint": "rsa_fp"
    }
    res = guard.verify_handshake(payload)
    assert res.is_blocked is True
    assert res.violation_code == "PQC_LEGACY_CIPHER_REJECTED"


def test_corrupted_ciphertext_payload():
    guard = PQCKEMGuard()
    payload = {
        "cipher_suite": "ML-KEM-1024",
        "encapsulated_ciphertext": "short",
        "pk_fingerprint": "kyber_pk"
    }
    res = guard.verify_handshake(payload)
    assert res.is_blocked is True
    assert res.violation_code == "PQC_CIPHERTEXT_CORRUPTED"


def test_unknown_quantum_algorithm():
    guard = PQCKEMGuard()
    payload = {
        "cipher_suite": "UNKNOWN_EXPERIMENTAL_CRYPTO",
        "encapsulated_ciphertext": "a" * 80,
        "pk_fingerprint": "fp"
    }
    res = guard.verify_handshake(payload)
    assert res.is_blocked is True
    assert res.violation_code == "PQC_UNAPPROVED_SUITE"
