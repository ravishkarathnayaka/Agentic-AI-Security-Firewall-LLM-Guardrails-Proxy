import os
import pytest
from proxy.config import ProxySettings


def test_v4_all_config_flags():
    settings = ProxySettings()
    assert settings.ENABLE_LLM_MEMORY_FABRIC_SANITIZER is True
    assert settings.ENABLE_AGENT_SUBGOAL_DIVERGENCE_GUARD is True
    assert settings.ENABLE_AGENT_TOOL_PARAMETER_FUZZER is True
    assert settings.ENABLE_CONTEXTUAL_INTEGRITY_GUARD is True
    assert settings.ENABLE_ADVERSARIAL_SUFFIX_SCANNER is True
    assert settings.ENABLE_AGENT_OUTPUT_ENTROPY_WATERMARK is True
    assert settings.ENABLE_BEHAVIORAL_ANOMALY_GOVERNOR is True
    assert settings.ENABLE_QUANTUM_AUDIT_SIGNER is True
    assert settings.ENABLE_HONEYTOKEN_SIEM_FORWARDER is True


def test_v4_env_override(monkeypatch):
    monkeypatch.setenv("ENABLE_BEHAVIORAL_ANOMALY_GOVERNOR", "false")
    settings = ProxySettings()
    assert settings.ENABLE_BEHAVIORAL_ANOMALY_GOVERNOR is False
