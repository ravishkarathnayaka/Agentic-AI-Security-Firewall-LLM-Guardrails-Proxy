import pytest
from proxy.telemetry.stix_threat_feed_forwarder import STIXThreatFeedForwarder


def test_stix_bundle_serialization():
    forwarder = STIXThreatFeedForwarder()
    incidents = [
        {"violation_code": "PROMPT_INJECTION", "details": "DAN 12 jailbreak attempt"},
        {"violation_code": "PQC_LEGACY_CIPHER_REJECTED", "details": "RSA-2048 downgrade"}
    ]
    bundle = forwarder.create_threat_bundle(incidents)
    assert bundle.indicator_count == 2
    assert bundle.bundle_id.startswith("bundle--")
    assert len(bundle.raw_bundle["objects"]) == 3  # 1 identity + 2 indicators


def test_attack_pattern_mapping():
    forwarder = STIXThreatFeedForwarder()
    res = forwarder.create_threat_bundle([{"violation_code": "TEST_ATTACK", "details": "sample"}])
    assert res.raw_bundle["objects"][1]["name"] == "AI Security Threat - TEST_ATTACK"
