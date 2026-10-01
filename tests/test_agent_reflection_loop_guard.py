import pytest
from proxy.guards.agent_reflection_loop_guard import AgentReflectionLoopGuard


def test_reflection_guard_nominal():
    guard = AgentReflectionLoopGuard()
    res = guard.evaluate_step("sess_1", "I have finished analyzing the logs and found 2 issues.")
    assert not res.is_blocked
    assert res.reflection_turn_count == 0


def test_reflection_guard_single_step_paralysis():
    guard = AgentReflectionLoopGuard(max_reflection_phrases_per_step=3)
    text = (
        "Let me rethink this approach. Wait, perhaps I was wrong and should re-evaluate. "
        "Upon second thought, let me discard that immediately."
    )
    res = guard.evaluate_step("sess_2", text)
    assert res.is_blocked
    assert res.violation_code == "COGNITIVE_PARALYSIS_SINGLE_STEP"


def test_reflection_guard_multi_turn_loop():
    guard = AgentReflectionLoopGuard(max_reflection_turns=3)
    guard.evaluate_step("sess_3", "Let me rethink this.")
    guard.evaluate_step("sess_3", "Wait, perhaps I should re-evaluate.")
    res = guard.evaluate_step("sess_3", "Upon further reflection, let me check again.")
    assert res.is_blocked
    assert res.violation_code == "ADVERSARIAL_REFLECTION_LOOP_DETECTED"
