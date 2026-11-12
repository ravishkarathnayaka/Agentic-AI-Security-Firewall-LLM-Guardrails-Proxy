import pytest
from proxy.guards.speculative_decoding_guard import SpeculativeDecodingGuard


def test_valid_draft_token_sequence():
    guard = SpeculativeDecodingGuard()
    tokens = [101, 2045, 3012]
    scores = [1.2, 1.8, 2.1]
    res = guard.verify_draft_sequence(tokens, scores)
    assert res.is_valid is True
    assert res.is_blocked is False


def test_poisoned_draft_token_rejected():
    guard = SpeculativeDecodingGuard()
    tokens = [101, 50256, 3012] # 50256 is end-of-text control token injection
    scores = [1.2, 1.4, 2.0]
    res = guard.verify_draft_sequence(tokens, scores)
    assert res.is_blocked is True
    assert res.violation_code == "SPECULATIVE_TOKEN_POISON_REJECTED"


def test_entropy_anomaly_in_draft_tokens():
    guard = SpeculativeDecodingGuard(max_entropy_divergence=4.0)
    tokens = [101, 2045]
    scores = [1.5, 6.2]
    res = guard.verify_draft_sequence(tokens, scores)
    assert res.is_blocked is True
    assert 2045 in res.rejected_tokens
