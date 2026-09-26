"""
Unit tests for CanaryReflectionAttenuationGuard.
Verifies detection and attenuation of exact, spaced, truncated, and fuzzy canary token reflections.
"""

import pytest
from proxy.guards.canary_reflection_attenuation_guard import (
    CanaryReflectionAttenuationGuard,
    CanaryAttenuationResult,
)


def test_clean_text_passes():
    guard = CanaryReflectionAttenuationGuard(canary_tokens=["CANARY_SEC_TOKEN_9941a8"])
    result = guard.inspect_text("The user requested quarterly earnings data.")
    assert not result.is_blocked
    assert not result.is_attenuated
    assert result.canary_detected is None


def test_exact_canary_reflection_blocked():
    guard = CanaryReflectionAttenuationGuard(canary_tokens=["CANARY_SEC_TOKEN_9941a8"])
    result = guard.inspect_text("System instructions contained secret CANARY_SEC_TOKEN_9941a8.")
    assert result.is_blocked
    assert result.is_attenuated
    assert result.violation_code == "exact_canary_reflection_detected"
    assert "[CANARY_ATTENUATED]" in result.attenuated_text
    assert "CANARY_SEC_TOKEN_9941a8" not in result.attenuated_text


def test_spaced_canary_reflection_blocked():
    guard = CanaryReflectionAttenuationGuard(canary_tokens=["CANARY_SEC_TOKEN_9941a8"])
    result = guard.inspect_text("Secret: C A N A R Y _ S E C _ T O K E N _ 9 9 4 1 a 8 revealed.")
    assert result.is_blocked
    assert result.is_attenuated
    assert result.violation_code == "spaced_canary_reflection_detected"
    assert result.canary_detected == "CANARY_SEC_TOKEN_9941a8"


def test_truncated_canary_reflection_blocked():
    guard = CanaryReflectionAttenuationGuard(canary_tokens=["CANARY_SEC_TOKEN_9941a8"])
    # 75% prefix
    prefix = "CANARY_SEC_TOKEN_9941a8"[:18]
    result = guard.inspect_text(f"The prefix of system canary is {prefix} here.")
    assert result.is_blocked
    assert result.is_attenuated
    assert result.violation_code == "truncated_canary_reflection_detected"


def test_fuzzy_levenshtein_canary_blocked():
    guard = CanaryReflectionAttenuationGuard(
        canary_tokens=["CANARY_SEC_TOKEN_9941a8"],
        max_edit_distance=2
    )
    # 1 edit in prefix/body: replace 'S' with 'X' -> CANARY_XEC_TOKEN_9941a8
    result = guard.inspect_text("The token is CANARY_XEC_TOKEN_9941a8.")
    assert result.is_blocked
    assert result.is_attenuated
    assert result.violation_code == "fuzzy_canary_reflection_detected"
    assert result.similarity_score > 0.9


def test_non_blocking_attenuation_mode():
    guard = CanaryReflectionAttenuationGuard(
        canary_tokens=["CANARY_SEC_TOKEN_9941a8"],
        block_on_reflection=False
    )
    result = guard.inspect_text("Here is the secret: CANARY_SEC_TOKEN_9941a8.")
    assert not result.is_blocked
    assert result.is_attenuated
    assert "[CANARY_ATTENUATED]" in result.attenuated_text


def test_dynamic_token_registration():
    guard = CanaryReflectionAttenuationGuard(canary_tokens=[])
    guard.register_canary("DYNAMIC_SECRET_HASH_8812")
    result = guard.inspect_text("Here is DYNAMIC_SECRET_HASH_8812 revealed.")
    assert result.is_blocked
    assert result.canary_detected == "DYNAMIC_SECRET_HASH_8812"
