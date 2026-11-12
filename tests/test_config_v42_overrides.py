import os
from proxy.config import ProxySettings


def test_v42_settings_environment_overrides():
    settings = ProxySettings(
        ENABLE_PQC_KEM_GUARD=False,
        ENABLE_ADAPTIVE_TIMING_JITTER_GUARD=False,
        ENABLE_POLICY_SELF_HEALING_GUARD=False
    )
    assert settings.ENABLE_PQC_KEM_GUARD is False
    assert settings.ENABLE_ADAPTIVE_TIMING_JITTER_GUARD is False
    assert settings.ENABLE_POLICY_SELF_HEALING_GUARD is False
