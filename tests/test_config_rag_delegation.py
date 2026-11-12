from proxy.config import ProxySettings


def test_rag_and_delegation_settings_defaults():
    settings = ProxySettings()
    assert settings.ENABLE_RAG_MEMORY_INTEGRITY_GUARD is True
    assert settings.ENABLE_AGENT_DELEGATION_CHAIN_GUARD is True
