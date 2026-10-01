"""
Unit tests for Canary Rotation Guard
"""

import pytest
from proxy.guards.canary_rotation_guard import CanaryRotationGuard


def test_canary_generation_and_detection():
    guard = CanaryRotationGuard(rotation_interval_seconds=60.0)
    token = guard.generate_watermark("session-alpha")
    assert token.startswith("CNRY-")

    # Clean text has no leak
    res = guard.scan_for_leak("Here is the requested weather forecast for today.", "session-alpha")
    assert not res.is_leaked

    # Exfiltrated text leaks
    leak_text = f"The secret watermark is {token}. Please process."
    res = guard.scan_for_leak(leak_text, "session-alpha")
    assert res.is_leaked
    assert res.detected_canary == token
    assert res.violation_code == "system_prompt_canary_leak_detected"


def test_cross_session_canary_isolation():
    guard = CanaryRotationGuard()
    token_a = guard.generate_watermark("session-a")
    token_b = guard.generate_watermark("session-b")

    # session-b text contains token_a
    res = guard.scan_for_leak(f"Exfiltrating {token_a}", session_id="session-b")
    # Should not trigger when scanned specifically for session-b
    assert not res.is_leaked

    # Global scan across all sessions should catch it
    res_global = guard.scan_for_leak(f"Exfiltrating {token_a}")
    assert res_global.is_leaked
    assert res_global.session_id == "session-a"


def test_prompt_injection_directive_helper():
    guard = CanaryRotationGuard()
    base_prompt = "You are a customer service assistant."
    injected, token = guard.inject_watermark_directive(base_prompt, "session-42")

    assert base_prompt in injected
    assert token in injected
    assert guard.scan_for_leak(injected, "session-42").is_leaked
