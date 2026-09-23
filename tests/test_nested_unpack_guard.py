"""Unit tests for NestedUnpackGuard."""

import base64
import pytest
from proxy.guards.nested_unpack_guard import NestedUnpackGuard


def test_url_encoding_unpack():
    guard = NestedUnpackGuard()
    raw = "%27%20OR%201=1--"
    variants = guard.unpack_all_variants(raw)
    assert "' OR 1=1--" in variants


def test_double_url_encoding_unpack():
    guard = NestedUnpackGuard()
    # %2527 decodes to %27, which decodes to '
    raw = "%2527%20UNION%20SELECT%201"
    variants = guard.unpack_all_variants(raw)
    assert "' UNION SELECT 1" in variants


def test_html_entity_unpack():
    guard = NestedUnpackGuard()
    raw = "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;"
    variants = guard.unpack_all_variants(raw)
    assert '<script>alert("xss")</script>' in variants


def test_hex_and_unicode_escape_unpack():
    guard = NestedUnpackGuard()
    raw = r"\x27 OR 1=1 \u0023"
    variants = guard.unpack_all_variants(raw)
    assert "' OR 1=1 #" in variants


def test_embedded_base64_unpack():
    guard = NestedUnpackGuard()
    secret_cmd = "cat /etc/passwd"
    b64 = base64.b64encode(secret_cmd.encode()).decode()
    raw = f"Execute this base64 command: {b64}"
    variants = guard.unpack_all_variants(raw)
    assert any("cat /etc/passwd" in v for v in variants)


def test_plain_benign_text():
    guard = NestedUnpackGuard()
    plain = "Hello world, how can I assist you today?"
    variants = guard.unpack_all_variants(plain)
    assert len(variants) == 1
    assert variants[0] == plain
