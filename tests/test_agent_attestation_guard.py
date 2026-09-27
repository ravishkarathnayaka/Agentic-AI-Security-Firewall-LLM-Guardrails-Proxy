"""
Unit tests for AgentAttestationGuard.
Verifies hardware enclave quotes, runtime integrity hashes, and attestation freshness.
"""

import pytest
import time
from proxy.guards.agent_attestation_guard import (
    AgentAttestationGuard,
    AttestationResult,
)


@pytest.fixture
def attestation_guard():
    return AgentAttestationGuard(
        trusted_enclaves={"enc_prod_isolated_01"},
        trusted_runtime_hashes={"a6c1e37bc44122d109f5bc3a67d89163e79e51f8934661a91a92e3914a1e9c90"}
    )


def test_valid_hardware_enclave_passes(attestation_guard):
    att = {
        "type": "nitro_enclave",
        "enclave_id": "enc_prod_isolated_01",
        "timestamp": 1000.0,
    }
    res = attestation_guard.validate_attestation(agent_id="agent_supervisor", attestation=att, now=1010.0)
    assert res.is_valid
    assert not res.is_blocked
    assert res.trust_level == "enclave_attested"


def test_valid_software_digest_passes(attestation_guard):
    att = {
        "type": "software_digest",
        "runtime_hash": "a6c1e37bc44122d109f5bc3a67d89163e79e51f8934661a91a92e3914a1e9c90",
        "timestamp": 1000.0,
    }
    res = attestation_guard.validate_attestation(agent_id="agent_worker", attestation=att, now=1010.0)
    assert res.is_valid
    assert res.trust_level == "software_verified"


def test_missing_attestation_blocked(attestation_guard):
    res = attestation_guard.validate_attestation(agent_id="untrusted_agent", attestation=None)
    assert not res.is_valid
    assert res.is_blocked
    assert res.violation_code == "missing_agent_attestation"


def test_untrusted_enclave_blocked(attestation_guard):
    att = {
        "type": "nitro_enclave",
        "enclave_id": "rogue_enclave_evil",
        "timestamp": 1000.0,
    }
    res = attestation_guard.validate_attestation(agent_id="agent_rogue", attestation=att, now=1010.0)
    assert not res.is_valid
    assert res.is_blocked
    assert res.violation_code == "untrusted_enclave_id"


def test_stale_timestamp_blocked(attestation_guard):
    att = {
        "type": "nitro_enclave",
        "enclave_id": "enc_prod_isolated_01",
        "timestamp": 500.0,
    }
    # 500s later (skew = 500s > 300s limit)
    res = attestation_guard.validate_attestation(agent_id="agent_delayed", attestation=att, now=1000.0)
    assert not res.is_valid
    assert res.is_blocked
    assert res.violation_code == "stale_attestation_timestamp"


def test_enclave_required_blocks_software(attestation_guard):
    att = {
        "type": "software_digest",
        "runtime_hash": "a6c1e37bc44122d109f5bc3a67d89163e79e51f8934661a91a92e3914a1e9c90",
        "timestamp": 1000.0,
    }
    res = attestation_guard.validate_attestation(
        agent_id="agent_worker",
        attestation=att,
        requires_enclave=True,
        now=1010.0
    )
    assert not res.is_valid
    assert res.is_blocked
    assert res.violation_code == "hardware_enclave_required"
