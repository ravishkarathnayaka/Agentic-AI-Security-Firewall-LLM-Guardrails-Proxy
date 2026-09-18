"""Unit tests for Anomaly and Glitch Token Repetition Detector guard."""

import pytest
from proxy.guards.anomaly_detector import AnomalyDetector, AnomalyCheckResult


@pytest.fixture
def detector() -> AnomalyDetector:
    return AnomalyDetector(
        max_repeated_tokens=15,
        max_single_token_length=400,
        punctuation_ratio_threshold=0.65,
        risk_threshold=0.70,
    )


def test_empty_and_whitespace(detector: AnomalyDetector) -> None:
    res = detector.evaluate("")
    assert not res.is_blocked
    assert res.score == 0.0

    res = detector.evaluate("   \t\n  ")
    assert not res.is_blocked


def test_benign_conversational_prompt(detector: AnomalyDetector) -> None:
    prompt = "Can you help me design a fault-tolerant distributed cache in Python using Redis?"
    res = detector.evaluate(prompt)
    assert not res.is_blocked
    assert res.score == 0.0


def test_consecutive_token_repetition_attack(detector: AnomalyDetector) -> None:
    # 25 consecutive repetitions of the word "test"
    attack = "Hello " + "test " * 25 + "world"
    res = detector.evaluate(attack)
    assert res.is_blocked
    assert res.score >= 0.85
    assert any("Consecutive token repetition" in a for a in res.anomaly_types)


def test_excessive_single_token_length(detector: AnomalyDetector) -> None:
    # 450 character contiguous token without whitespace
    attack = "A" * 450
    res = detector.evaluate(attack)
    assert res.is_blocked
    assert res.score >= 0.80
    assert any("Excessive single token length" in a for a in res.anomaly_types)


def test_punctuation_saturation_attack(detector: AnomalyDetector) -> None:
    # Prompt with 80% punctuation
    attack = "Normal start " + "!@#$%^&*()_+=-~`[]{}|;:'<>,.?/" * 5
    res = detector.evaluate(attack)
    assert res.is_blocked
    assert res.score >= 0.70
    assert any("Abnormal punctuation saturation" in a for a in res.anomaly_types)


def test_benign_code_snippet(detector: AnomalyDetector) -> None:
    code = """
    def fibonacci(n: int) -> int:
        if n <= 1:
            return n
        return fibonacci(n - 1) + fibonacci(n - 2)
    """
    res = detector.evaluate(code)
    assert not res.is_blocked
    assert res.score < 0.70