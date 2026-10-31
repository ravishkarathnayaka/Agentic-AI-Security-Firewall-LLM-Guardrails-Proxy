import pytest
from proxy.config import ProxySettings


def test_v41_batch1_config_flags():
    settings = ProxySettings()
    assert settings.ENABLE_NEURO_SYMBOLIC_SOLVER_GUARD is True
    assert settings.ENABLE_ZK_PROOF_VERIFIER_GUARD is True
    assert settings.ENABLE_AGENT_COLLUSION_SYBIL_GUARD is True
    assert settings.ENABLE_CONTEXT_FRAGMENTATION_SMUGGLING_GUARD is True
