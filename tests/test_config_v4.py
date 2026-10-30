import pytest
from proxy.config import ProxySettings


def test_v4_config_flags():
    settings = ProxySettings()
    assert settings.ENABLE_QUANTUM_SAFE_SIGNATURE_GUARD is True
    assert settings.ENABLE_DYNAMIC_HONEYTOKEN_VAULT_GUARD is True
    assert settings.ENABLE_AGENT_SYCOPHANCY_GUARD is True
    assert settings.ENABLE_SHADOW_PROMPT_INJECTION_GUARD is True
