"""Unit tests for format-preserving synthetic PII generator."""

import pytest
from proxy.guards.pii_synthetic_generator import SyntheticPIIGenerator


def test_synthetic_email_replacement():
    gen = SyntheticPIIGenerator()
    text = "Please reach out to alice.smith@secure-bank.org for verification."
    sanitized, mapping = gen.sanitize(text)

    assert "alice.smith@secure-bank.org" not in sanitized
    assert "synthetic_" in sanitized
    assert "@example-corp.internal" in sanitized
    assert "alice.smith@secure-bank.org" in mapping


def test_synthetic_determinism():
    gen = SyntheticPIIGenerator(salt="fixed-salt-xyz")
    real = "customer.service@fintech.co"

    res1, _ = gen.sanitize(f"Contact {real}")
    res2, _ = gen.sanitize(f"Ping {real} once more")

    # The synthetic email replacement should be identical for identical inputs
    assert res1.split()[-1] == res2.split()[-3]


def test_synthetic_credit_card_replacement():
    gen = SyntheticPIIGenerator()
    text = "Charged card 4111 2222 3333 4444 for subscription."
    sanitized, mapping = gen.sanitize(text)

    assert "4111 2222 3333 4444" not in sanitized
    assert "4000-" in sanitized
    assert len(mapping) == 1


def test_synthetic_ssn_replacement():
    gen = SyntheticPIIGenerator()
    text = "Tax ID: 123-45-6789"
    sanitized, mapping = gen.sanitize(text)

    assert "123-45-6789" not in sanitized
    assert "000-" in sanitized
    assert "123-45-6789" in mapping


def test_synthetic_api_key_replacement():
    gen = SyntheticPIIGenerator()
    key = "sk-1234567890abcdef1234567890abcdef"
    text = f"Authorization: Bearer {key}"
    sanitized, mapping = gen.sanitize(text)

    assert key not in sanitized
    assert "sk-synthetic-" in sanitized
    assert key in mapping


def test_empty_and_benign_text():
    gen = SyntheticPIIGenerator()
    sanitized, mapping = gen.sanitize("")
    assert sanitized == ""
    assert mapping == {}

    benign = "Hello world, what is the capital of France?"
    sanitized, mapping = gen.sanitize(benign)
    assert sanitized == benign
    assert len(mapping) == 0
