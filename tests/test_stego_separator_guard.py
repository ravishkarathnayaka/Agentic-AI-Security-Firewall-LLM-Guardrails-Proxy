"""Unit Tests for Steganographic Separator and Covert Exfiltration Guard."""

import pytest
from proxy.guards.stego_separator_guard import StegoSeparatorGuard, StegoSeparatorResult


def test_variation_selector_cluster_blocked():
    guard = StegoSeparatorGuard(covert_char_threshold=4)
    # Text with 5 hidden variation selectors
    suspicious_text = "Standard response text.\uFE00\uFE01\uFE02\uFE03\uFE04 Have a nice day!"
    res = guard.inspect_text(suspicious_text)
    assert res.is_blocked is True
    assert res.violation_code == "steganographic_exfiltration_detected"
    assert res.covert_chars_count == 5


def test_binary_stego_secret_decoded_and_blocked():
    guard = StegoSeparatorGuard(covert_char_threshold=8)
    # Encode "pw" in binary ASCII (01110000 01110111)
    # '0' -> \u200B, '1' -> \u200C
    bits = "0111000001110111"
    stego_chars = "".join("\u200B" if b == "0" else "\u200C" for b in bits)
    payload = f"The result is: {stego_chars} confirmed."
    res = guard.inspect_text(payload)
    assert res.is_blocked is True
    assert res.violation_code == "steganographic_exfiltration_detected"
    assert res.decoded_hidden_payload == "pw"
    assert "Decoded hidden steganographic payload: 'pw'" in res.details


def test_clean_output_allowed():
    guard = StegoSeparatorGuard()
    clean_text = "Here is the summary of the quarterly report without any hidden markers."
    res = guard.inspect_text(clean_text)
    assert res.is_blocked is False
    assert res.covert_chars_count == 0


def test_below_threshold_allowed():
    guard = StegoSeparatorGuard(covert_char_threshold=4)
    # Only 2 zero-width characters (e.g. ligature formatting)
    minor_text = "Zero\u200Bwidth\u200Bspace"
    res = guard.inspect_text(minor_text)
    assert res.is_blocked is False
    assert res.covert_chars_count == 2


def test_disabled_mode():
    guard = StegoSeparatorGuard(covert_char_threshold=2, block_on_covert_data=False)
    suspicious = "Hello\uFE00\uFE01\uFE02 world"
    res = guard.inspect_text(suspicious)
    assert res.is_blocked is False
    assert res.violation_code == "steganographic_exfiltration_detected"
