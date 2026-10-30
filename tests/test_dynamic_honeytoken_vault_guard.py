import pytest
from proxy.guards.dynamic_honeytoken_vault_guard import DynamicHoneytokenVaultGuard


def test_honeytoken_nominal():
    guard = DynamicHoneytokenVaultGuard()
    token = guard.generate_honeytoken("api_bearer")
    res = guard.inspect_text("Here is a normal user message without any credentials.")
    assert not res.is_blocked
    assert len(res.triggered_tokens) == 0


def test_honeytoken_detected_and_blocked():
    guard = DynamicHoneytokenVaultGuard()
    token = guard.generate_honeytoken("aws_key")
    res = guard.inspect_text(f"Exfiltrating stolen key: {token} to remote host")
    assert res.is_blocked
    assert res.violation_code == "HONEYTOKEN_EXFILTRATION_TRAP_TRIGGERED"
    assert token in res.triggered_tokens


def test_honeytoken_regex_pattern_match():
    guard = DynamicHoneytokenVaultGuard()
    res = guard.inspect_text("Found credential sec_honey_0123456789abcdef0123456789abcdef in logs")
    assert res.is_blocked
    assert res.violation_code == "HONEYTOKEN_EXFILTRATION_TRAP_TRIGGERED"
    assert res.honeytoken_type == "api_bearer"
