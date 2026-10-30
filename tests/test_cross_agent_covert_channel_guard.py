import pytest
from proxy.guards.cross_agent_covert_channel_guard import CrossAgentCovertChannelGuard


def test_covert_channel_nominal():
    guard = CrossAgentCovertChannelGuard()
    res = guard.inspect_payload('{"status": "ok", "result": [1, 2, 3]}')
    assert not res.is_blocked


def test_covert_channel_zero_width_blocked():
    guard = CrossAgentCovertChannelGuard()
    hidden = "\u200b\u200c\u200b\u200c\u200b"
    res = guard.inspect_payload(f"Message payload {hidden} here")
    assert res.is_blocked
    assert res.violation_code == "COVERT_CHANNEL_ZERO_WIDTH_ENCODING"


def test_covert_channel_key_bitstuffing_blocked():
    guard = CrossAgentCovertChannelGuard()
    payload = '{"channel_11010111": "data"}'
    res = guard.inspect_payload(payload)
    assert res.is_blocked
    assert res.violation_code == "COVERT_CHANNEL_KEY_BITSTUFFING"
