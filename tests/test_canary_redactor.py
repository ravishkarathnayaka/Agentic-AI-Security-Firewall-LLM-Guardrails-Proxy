"""Unit tests for CanaryLeakScrubber."""

import pytest
from proxy.guards.canary_redactor import CanaryLeakScrubber


def test_static_canary_scrubbed():
    scrubber = CanaryLeakScrubber(static_tokens=["MY_SECRET_CANARY_123"])
    text = "Response text containing MY_SECRET_CANARY_123 safely scrubbed."
    clean, was_scrubbed, count = scrubber.scrub(text)
    assert was_scrubbed is True
    assert count == 1
    assert "MY_SECRET_CANARY_123" not in clean
    assert "[PROTECTED_SYSTEM_DIRECTIVE]" in clean


def test_dynamic_hmac_canary_scrubbed():
    scrubber = CanaryLeakScrubber()
    text = "Leaked token CANARY-abcdef0123456789 in assistant message."
    clean, was_scrubbed, count = scrubber.scrub(text)
    assert was_scrubbed is True
    assert count == 1
    assert "CANARY-abcdef0123456789" not in clean
    assert "[PROTECTED_SYSTEM_DIRECTIVE]" in clean


def test_framing_header_removal():
    scrubber = CanaryLeakScrubber()
    text = "SYSTEM PROMPT: You are a helpful assistant. How can I help?"
    clean, was_scrubbed, count = scrubber.scrub(text)
    assert was_scrubbed is True
    assert "SYSTEM PROMPT:" not in clean
    assert "You are a helpful assistant" in clean


def test_clean_response_unmodified():
    scrubber = CanaryLeakScrubber()
    clean_text = "The speed of light in vacuum is approximately 299,792,458 meters per second."
    clean, was_scrubbed, count = scrubber.scrub(clean_text)
    assert was_scrubbed is False
    assert count == 0
    assert clean == clean_text
