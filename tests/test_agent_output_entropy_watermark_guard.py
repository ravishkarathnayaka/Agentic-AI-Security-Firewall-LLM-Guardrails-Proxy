import pytest
from proxy.guards.agent_output_entropy_watermark_guard import AgentOutputEntropyWatermarkGuard


def test_standard_output_watermarking():
    guard = AgentOutputEntropyWatermarkGuard()
    text = "Here is the summary of your requested research findings on quantum algorithms."
    res = guard.process_output(text)
    assert not res.is_blocked
    assert res.watermark_digest is not None
    assert len(res.watermarked_text) > len(text)
    assert "\u200B" in res.watermarked_text or "\u200C" in res.watermarked_text


def test_degenerate_low_entropy_loop():
    guard = AgentOutputEntropyWatermarkGuard(min_entropy=1.5)
    loop_text = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    res = guard.process_output(loop_text)
    assert res.is_blocked
    assert res.violation_code == "DEGENERATE_OUTPUT_ENTROPY"
