import pytest
from proxy.guards.hardware_enclave_attestation_guard import HardwareEnclaveAttestationGuard


def test_valid_nitro_enclave_quote():
    guard = HardwareEnclaveAttestationGuard()
    quote = {
        "enclave_type": "AWS_NITRO",
        "pcr0": "8f4e2b1a9c3d5e7f0123456789abcdef0123456789abcdef0123456789abcdef",
        "quote_signature": "a" * 64,
        "nonce": "test_nonce_123"
    }
    res = guard.verify_quote(quote)
    assert res.is_trusted is True
    assert res.is_blocked is False
    assert res.enclave_type == "AWS_NITRO"


def test_invalid_enclave_platform():
    guard = HardwareEnclaveAttestationGuard()
    quote = {
        "enclave_type": "UNKNOWN_EMULATOR_VBOX",
        "pcr0": "valid_pcr0_data_hex_32_bytes_long",
        "quote_signature": "a" * 64
    }
    res = guard.verify_quote(quote)
    assert res.is_blocked is True
    assert res.violation_code == "UNSUPPORTED_ENCLAVE_PLATFORM"


def test_missing_signature_tampered():
    guard = HardwareEnclaveAttestationGuard()
    quote = {
        "enclave_type": "INTEL_SGX",
        "pcr0": "valid_pcr0_data_hex_32_bytes_long",
        "quote_signature": "short"
    }
    res = guard.verify_quote(quote)
    assert res.is_blocked is True
    assert res.violation_code == "ENCLAVE_SIGNATURE_TAMPERED"
