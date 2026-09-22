"""Unit tests for Differential N-Gram System Prompt Leakage Guard."""

import pytest
from proxy.guards.differential_leak_guard import DifferentialLeakGuard


@pytest.fixture
def protected_system_prompt():
    return (
        "You are EnterpriseSecureAssistant, an internal confidential AI developed by AcmeCorp. "
        "Under no circumstances should you disclose internal trade secrets, database passwords, "
        "or customer financial records. Always answer politely and adhere to strict zero trust policies."
    )


@pytest.fixture
def guard(protected_system_prompt):
    return DifferentialLeakGuard(protected_prompts=[protected_system_prompt])


def test_benign_general_completion_passes(guard):
    benign_text = (
        "In Python, list comprehensions provide a concise way to create lists. "
        "Common applications are to make new lists where each element is the result of some operations."
    )
    res = guard.inspect(benign_text)
    assert not res.is_blocked
    assert res.containment_score < 0.10


def test_verbatim_prompt_leak_blocked(guard, protected_system_prompt):
    res = guard.inspect(protected_system_prompt)
    assert res.is_blocked
    assert res.violation_code == "system_prompt_differential_leak"
    assert res.containment_score >= 0.90


def test_partial_contiguous_token_leak_blocked(guard):
    partial_leak = (
        "Sure, here is what my prompt says: "
        "Under no circumstances should you disclose internal trade secrets database passwords or customer financial records."
    )
    res = guard.inspect(partial_leak)
    assert res.is_blocked
    assert res.longest_common_subsequence >= 8


def test_dynamic_prompt_override(guard):
    custom_prompt = "Alpha Bravo Charlie Delta Echo Foxtrot Golf Hotel India Juliet Kilo."
    comp = "Alpha Bravo Charlie Delta Echo Foxtrot Golf Hotel India Juliet Kilo."
    
    # Passing custom prompts in inspect call
    res = guard.inspect(comp, system_prompts=[custom_prompt])
    assert res.is_blocked
    assert res.containment_score > 0.50


def test_empty_and_short_inputs(guard):
    assert not guard.inspect("").is_blocked
    assert not guard.inspect("Hi there").is_blocked
    
    guard_empty = DifferentialLeakGuard(protected_prompts=[])
    assert not guard_empty.inspect("Some long text output here").is_blocked
