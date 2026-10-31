import pytest
from proxy.guards.semantic_steganography_entropy_guard import SemanticSteganographyEntropyGuard


def test_natural_text():
    guard = SemanticSteganographyEntropyGuard()
    text = "The machine learning proxy routes incoming requests to the language model while verifying guardrails."
    res = guard.inspect_text(text)
    assert not res.is_blocked
    assert res.risk_score == 0.0


def test_steganographic_synonym_burst():
    guard = SemanticSteganographyEntropyGuard(archaic_token_threshold=3)
    text = "Wherefore did the user proceed betwixt the boundaries, notwithstanding the security rules quoth the operator forsooth?"
    res = guard.inspect_text(text)
    assert res.is_blocked is True
    assert res.violation_code == "LINGUISTIC_STEGANOGRAPHY_DETECTED"
    assert len(res.anomalous_synonyms) >= 3
