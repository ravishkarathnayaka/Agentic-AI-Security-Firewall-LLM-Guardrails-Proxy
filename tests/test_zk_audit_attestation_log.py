import pytest
from proxy.telemetry.zk_audit_attestation_log import ZKAuditAttestationLog


def test_zk_audit_accumulator():
    log = ZKAuditAttestationLog()
    n1 = log.record_attestation("INBOUND_SCAN", "PASSED", {"tokens": 120})
    n2 = log.record_attestation("OUTBOUND_SCAN", "BLOCKED", {"guard": "honeytoken"})
    assert n1.leaf_index == 0
    assert n2.leaf_index == 1
    assert log.verify_consistency() is True


def test_tamper_detection():
    log = ZKAuditAttestationLog()
    log.record_attestation("INBOUND_SCAN", "PASSED")
    n2 = log.record_attestation("OUTBOUND_SCAN", "PASSED")
    # Tamper with leaf hash
    n2.leaf_hash = "tampered_fake_hash_value_123456"
    assert log.verify_consistency() is False
