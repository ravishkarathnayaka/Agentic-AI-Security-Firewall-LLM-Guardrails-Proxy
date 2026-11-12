import pytest
from proxy.config import ProxySettings
from proxy.pipeline import SecurityPipeline


def test_v42_release_integrity():
    settings = ProxySettings()
    assert settings.ENABLE_PQC_KEM_GUARD is True
    assert settings.ENABLE_PROMPT_HONEYPOT_GUARD is True
    assert settings.ENABLE_RAG_MEMORY_INTEGRITY_GUARD is True
    assert settings.ENABLE_AGENT_DELEGATION_CHAIN_GUARD is True
    assert settings.ENABLE_ADAPTIVE_TIMING_JITTER_GUARD is True
    assert settings.ENABLE_MULTIMODAL_DEEPFAKE_GUARD is True

    pipeline = SecurityPipeline(settings)
    assert pipeline.pqc_kem_guard is not None
    assert pipeline.merkle_audit_ledger is not None
