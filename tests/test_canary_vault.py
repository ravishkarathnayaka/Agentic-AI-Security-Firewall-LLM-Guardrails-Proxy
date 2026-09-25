import time
import pytest
from proxy.guards.canary_vault import CanaryVault


@pytest.fixture
def vault():
    return CanaryVault(master_secret="test_secret_key_1234567890", default_ttl_seconds=3600)


def test_issue_canary_format(vault):
    token = vault.issue_canary(session_id="session_alpha")
    assert token.startswith("canary_sec_")
    assert len(token) > 20
    assert vault.is_canary_active(token) is True


def test_session_id_isolation(vault):
    token = vault.issue_canary(session_id="tenant_a")
    assert vault.is_canary_active(token, session_id="tenant_a") is True
    assert vault.is_canary_active(token, session_id="tenant_b") is False


def test_revoke_canary(vault):
    token = vault.issue_canary(session_id="session_beta")
    assert vault.is_canary_active(token) is True
    revoked = vault.revoke_canary(token)
    assert revoked is True
    assert vault.is_canary_active(token) is False


def test_canary_ttl_expiration(vault):
    token = vault.issue_canary(session_id="session_gamma", ttl_seconds=0.01)
    time.sleep(0.02)
    assert vault.is_canary_active(token) is False


def test_purge_expired_tokens(vault):
    t1 = vault.issue_canary(session_id="s1", ttl_seconds=0.01)
    t2 = vault.issue_canary(session_id="s2", ttl_seconds=3600)
    vault.revoke_canary(t2)
    time.sleep(0.02)
    purged_count = vault.purge_expired()
    assert purged_count == 2
    assert vault.total_tokens == 0


def test_find_active_canaries_in_text(vault):
    t1 = vault.issue_canary(session_id="s_active")
    t2 = vault.issue_canary(session_id="s_revoked")
    vault.revoke_canary(t2)

    sample_output = f"Assistant leaked: Secret token {t1} and also {t2} and fake canary_sec_0000000000000000"
    detected = vault.find_active_canaries_in_text(sample_output)
    assert len(detected) == 1
    assert detected[0] == t1


def test_empty_text_detection(vault):
    assert vault.find_active_canaries_in_text("") == []
    assert vault.find_active_canaries_in_text(None) == []
