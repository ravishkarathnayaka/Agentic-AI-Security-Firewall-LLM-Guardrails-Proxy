import pytest
from proxy.config import ProxySettings


def test_v41_batch2_config_flags():
    settings = ProxySettings()
    assert settings.ENABLE_SEMANTIC_STEGANOGRAPHY_GUARD is True
    assert settings.ENABLE_HARDWARE_ENCLAVE_ATTESTATION_GUARD is True
    assert settings.ENABLE_AGENT_PRIVILEGE_BOUNDARY_SANDBOX_GUARD is True
    assert settings.ENABLE_ADVERSARIAL_IMAGE_ASCII_ART_GUARD is True
