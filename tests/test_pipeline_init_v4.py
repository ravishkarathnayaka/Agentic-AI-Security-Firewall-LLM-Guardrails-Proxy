import pytest
from proxy.config import ProxySettings


def test_v4_batch2_config_flags():
    settings = ProxySettings()
    assert settings.ENABLE_AGENT_EPISTEMIC_DRIFT_TRACKER is True
    assert settings.ENABLE_CROSS_AGENT_COVERT_CHANNEL_GUARD is True
    assert settings.ENABLE_AGENT_STATE_CHECKPOINT_ROLLBACK_GUARD is True
    assert settings.ENABLE_PROMPT_INJECTION_ENSEMBLE_GUARD is True
