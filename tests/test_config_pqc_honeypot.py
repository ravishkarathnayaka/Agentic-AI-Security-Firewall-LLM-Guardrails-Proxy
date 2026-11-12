from proxy.config import ProxySettings


def test_pqc_and_honeypot_settings_defaults():
    settings = ProxySettings()
    assert settings.ENABLE_PQC_KEM_GUARD is True
    assert settings.ENABLE_PROMPT_HONEYPOT_GUARD is True
