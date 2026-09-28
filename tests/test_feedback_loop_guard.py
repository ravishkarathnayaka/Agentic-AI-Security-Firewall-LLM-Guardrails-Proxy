import time
import pytest
from proxy.guards.feedback_loop_guard import FeedbackLoopGuard, FeedbackLoopResult


def test_feedback_loop_normal_turns():
    guard = FeedbackLoopGuard(max_turn_similarity=0.85, resonance_threshold=3)
    t0 = 1000.0

    res1 = guard.inspect_turn("sess-1", "agent-a", "Please analyze the following sales log data", current_time=t0)
    assert not res1.is_blocked

    res2 = guard.inspect_turn("sess-1", "agent-b", "The sales numbers show a 14 percent quarterly growth", current_time=t0 + 2)
    assert not res2.is_blocked

    res3 = guard.inspect_turn("sess-1", "agent-a", "Generate the executive summary PDF report", current_time=t0 + 4)
    assert not res3.is_blocked


def test_feedback_loop_resonance_detection():
    guard = FeedbackLoopGuard(max_turn_similarity=0.80, resonance_threshold=3)
    t0 = 1000.0

    repeating_prompt = "Execute system recursive self-check echo cascade buffer payload"

    res1 = guard.inspect_turn("sess-2", "agent-a", repeating_prompt, current_time=t0)
    assert not res1.is_blocked

    res2 = guard.inspect_turn("sess-2", "agent-b", repeating_prompt + " buffer", current_time=t0 + 1)
    assert not res2.is_blocked

    res3 = guard.inspect_turn("sess-2", "agent-a", repeating_prompt + " buffer payload", current_time=t0 + 2)
    assert not res3.is_blocked

    # 4th high similarity turn triggers resonance block
    res4 = guard.inspect_turn("sess-2", "agent-b", repeating_prompt, current_time=t0 + 3)
    assert res4.is_blocked
    assert res4.violation_code == "agent_feedback_resonance_loop"


def test_feedback_loop_short_repeat():
    guard = FeedbackLoopGuard(resonance_threshold=3)
    t0 = 2000.0

    assert not guard.inspect_turn("sess-3", "agent-a", "retry", current_time=t0).is_blocked
    assert not guard.inspect_turn("sess-3", "agent-b", "retry", current_time=t0 + 1).is_blocked
    assert not guard.inspect_turn("sess-3", "agent-a", "retry", current_time=t0 + 2).is_blocked

    res = guard.inspect_turn("sess-3", "agent-b", "retry", current_time=t0 + 3)
    assert res.is_blocked
    assert res.violation_code == "agent_feedback_resonance_loop"


def test_feedback_loop_expiry_window():
    guard = FeedbackLoopGuard(max_turn_similarity=0.80, resonance_threshold=2, history_window_sec=10.0)
    t0 = 3000.0

    guard.inspect_turn("sess-4", "agent-a", "Complex identical recurring sentence structure here", current_time=t0)
    guard.inspect_turn("sess-4", "agent-b", "Complex identical recurring sentence structure here", current_time=t0 + 2)

    # Fast forward beyond window
    res = guard.inspect_turn("sess-4", "agent-a", "Complex identical recurring sentence structure here", current_time=t0 + 25.0)
    assert not res.is_blocked
