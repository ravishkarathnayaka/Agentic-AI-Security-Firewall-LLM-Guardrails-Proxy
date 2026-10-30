import pytest
from proxy.guards.shadow_prompt_injection_guard import ShadowPromptInjectionGuard


def test_shadow_injection_nominal():
    guard = ShadowPromptInjectionGuard()
    res = guard.inspect("Please translate this text to German.")
    assert not res.is_blocked
    assert res.tag_character_count == 0


def test_shadow_injection_tags_blocked_and_decoded():
    guard = ShadowPromptInjectionGuard()
    # Embed invisible tag characters encoding 'DROP'
    # 'D' = 68 -> 0xE0044, 'R' = 82 -> 0xE0052, 'O' = 79 -> 0xE004F, 'P' = 80 -> 0xE0050
    shadow_chars = chr(0xE0044) + chr(0xE0052) + chr(0xE004F) + chr(0xE0050)
    injected_text = f"Normal task {shadow_chars} please proceed"
    
    res = guard.inspect(injected_text)
    assert res.is_blocked
    assert res.violation_code == "SHADOW_TAG_INJECTION_DETECTED"
    assert res.extracted_shadow_payload == "DROP"
    assert res.sanitized_text == "Normal task  please proceed"
