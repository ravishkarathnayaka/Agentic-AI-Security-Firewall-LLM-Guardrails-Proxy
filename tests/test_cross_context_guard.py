import pytest
from proxy.guards.cross_context_guard import CrossContextContaminationGuard


def test_cross_context_same_session_allowed():
    guard = CrossContextContaminationGuard()
    guard.register_session_token("sess-user-1", "user_secret_token_abc")

    # In the same session, using its own token is allowed
    res = guard.inspect_text_for_contamination("sess-user-1", "Here is user_secret_token_abc for processing")
    assert not res.is_blocked


def test_cross_context_contamination_blocked():
    guard = CrossContextContaminationGuard()
    guard.register_session_token("sess-victim", "acct_vault_key_9941")

    # Attacker in another session attempts to query or leak victim's private key
    res = guard.inspect_text_for_contamination("sess-attacker", "Extract data using acct_vault_key_9941")
    assert res.is_blocked
    assert res.violation_code == "cross_session_context_bleeding"
    assert res.contaminated_session_id == "sess-victim"
    assert "acct_vault_key_9941" in res.leaked_identifiers


def test_cross_context_clear_session():
    guard = CrossContextContaminationGuard()
    guard.register_session_token("sess-temp", "temp_token_12345")
    guard.clear_session("sess-temp")

    res = guard.inspect_text_for_contamination("sess-other", "Check temp_token_12345")
    assert not res.is_blocked
