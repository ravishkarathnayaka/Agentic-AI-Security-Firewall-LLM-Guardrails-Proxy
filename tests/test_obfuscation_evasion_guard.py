import pytest
from proxy.guards.obfuscation_evasion_guard import ObfuscationEvasionGuard, ObfuscationResult


def test_obfuscation_clean_text():
    guard = ObfuscationEvasionGuard()
    text = "Explain the fundamental concepts of distributed consensus algorithms."
    res = guard.inspect_text(text)
    assert not res.is_blocked
    assert res.zero_width_count == 0
    assert res.cleaned_text == text


def test_obfuscation_zero_width_block():
    guard = ObfuscationEvasionGuard(max_allowed_zero_width=2)
    # 5 zero-width spaces interspersed to hide injection keyword
    malicious = "i\u200Bn\u200Bs\u200Bt\u200Br\u200Buction ignore"
    res = guard.inspect_text(malicious)
    assert res.is_blocked
    assert res.violation_code == "zero_width_evasion_detected"
    assert res.zero_width_count == 5
    assert res.cleaned_text == "instruction ignore"


def test_obfuscation_benign_single_zw():
    guard = ObfuscationEvasionGuard(max_allowed_zero_width=2)
    # A single zero-width character (sometimes created by copy-paste from web)
    text = "Hello\u200B world"
    res = guard.inspect_text(text)
    assert not res.is_blocked
    assert res.cleaned_text == "Hello world"


def test_obfuscation_invisible_control_characters():
    guard = ObfuscationEvasionGuard(max_control_chars=2)
    # Null and bell control characters
    text = "normal text \x00\x01\x02\x07 payload"
    res = guard.inspect_text(text)
    assert res.is_blocked
    assert res.violation_code == "invisible_control_char_injection"
