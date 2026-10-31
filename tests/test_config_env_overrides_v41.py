import pytest
from proxy.config import ProxySettings


def test_v41_all_config_flags():
    settings = ProxySettings()
    assert settings.ENABLE_EPISODIC_MEMORY_POISON_DECAY_GUARD is True
    assert settings.ENABLE_RECURSIVE_REFLECTION_GOVERNOR_GUARD is True
    assert settings.ENABLE_DIFFERENTIAL_PRIVACY_BUDGET_GUARD is True
    assert settings.ENABLE_AGENT_ACTION_ROLLBACK_JOURNAL_GUARD is True
    assert settings.ENABLE_EBPF_TELEMETRY_FORWARDER is True
    assert settings.ENABLE_ZK_AUDIT_ATTESTATION_LOG is True


def test_v41_env_override(monkeypatch):
    monkeypatch.setenv("ENABLE_ZK_PROOF_VERIFIER_GUARD", "false")
    settings = ProxySettings()
    assert settings.ENABLE_ZK_PROOF_VERIFIER_GUARD is False
