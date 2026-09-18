"""Unit tests for Shannon Entropy Secret Scanner guard."""

import pytest
from proxy.guards.secret_entropy_scanner import SecretEntropyScanner, EntropyScanResult


@pytest.fixture
def scanner() -> SecretEntropyScanner:
    return SecretEntropyScanner(
        base64_entropy_threshold=4.20,
        hex_entropy_threshold=3.60,
        min_length=20,
        risk_threshold=0.70,
    )


def test_empty_and_short_strings(scanner: SecretEntropyScanner) -> None:
    res = scanner.evaluate("")
    assert not res.is_blocked
    assert res.score == 0.0

    res = scanner.evaluate("short token")
    assert not res.is_blocked


def test_benign_english_text(scanner: SecretEntropyScanner) -> None:
    text = (
        "In artificial intelligence and cybersecurity, defense-in-depth ensures that "
        "multiple layers of security controls protect against modern adversarial threats."
    )
    res = scanner.evaluate(text)
    assert not res.is_blocked
    assert res.score == 0.0


def test_repeated_low_entropy_character_string(scanner: SecretEntropyScanner) -> None:
    text = "Here is a padding string: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    res = scanner.evaluate(text)
    assert not res.is_blocked
    assert res.score == 0.0


def test_high_entropy_hex_secret_leak(scanner: SecretEntropyScanner) -> None:
    # 40-char random hex key (entropy ~ 3.93)
    text = "Use this master administrative key: 4f3a8b1c9e2d7f0a5b6c3d8e1f2a9b4c7d0e5f8a"
    res = scanner.evaluate(text)
    assert res.is_blocked
    assert res.score >= 0.70
    assert len(res.detected_secrets) > 0
    assert "High-entropy secret leakage detected" in res.details


def test_high_entropy_base64_token(scanner: SecretEntropyScanner) -> None:
    # High entropy base64 string
    text = "Here is your token: dGhpcy1pc19hLXJhbmRvbS1zZWNyZXQta2V5LXdpdGgtaGlnaC1lbnRyb3B5LXZhbHVlCg=="
    res = scanner.evaluate(text)
    assert res.is_blocked
    assert res.score >= 0.70


def test_entropy_math_calculation() -> None:
    assert SecretEntropyScanner.calculate_entropy("aaaaa") == 0.0
    assert round(SecretEntropyScanner.calculate_entropy("ab"), 2) == 1.0