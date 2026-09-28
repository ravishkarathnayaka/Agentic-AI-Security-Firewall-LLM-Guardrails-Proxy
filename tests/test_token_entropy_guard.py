import pytest
from proxy.guards.token_entropy_guard import TokenEntropyGuard, TokenEntropyResult


def test_token_entropy_normal_text():
    guard = TokenEntropyGuard(min_token_threshold=25)
    text = (
        "The quick brown fox jumps over the lazy dog in the sunny forest. In computer science and "
        "information security, Shannon entropy measures the degree of unpredictability or randomness "
        "found within an arbitrary message sequence or stream of agent communication tokens."
    )
    res = guard.inspect_text(text)
    assert not res.is_blocked
    assert res.entropy > 3.0


def test_token_entropy_short_prompt_allowed():
    guard = TokenEntropyGuard(min_token_threshold=20)
    res = guard.inspect_text("hello world test")
    assert not res.is_blocked


def test_token_entropy_excessive_single_token_repetition():
    guard = TokenEntropyGuard(min_token_threshold=20, max_single_token_fraction=0.30)
    text = "spam " * 25 + "normal words mixed in here to create long prompt with text and parameters"
    res = guard.inspect_text(text)
    assert res.is_blocked
    assert res.violation_code == "excessive_token_repetition"


def test_token_entropy_low_shannon_entropy():
    guard = TokenEntropyGuard(min_token_threshold=30, min_shannon_entropy=2.0)
    text = "alpha beta alpha beta " * 20
    res = guard.inspect_text(text)
    assert res.is_blocked
    assert res.violation_code in ["low_entropy_token_stuffing", "excessive_ngram_repetition", "excessive_token_repetition"]


def test_token_entropy_bigram_repetition():
    guard = TokenEntropyGuard(min_token_threshold=20, max_repetition_ratio=0.50)
    text = "bypass filter " * 15 + "and additional filler tokens for testing evaluation purpose"
    res = guard.inspect_text(text)
    assert res.is_blocked
