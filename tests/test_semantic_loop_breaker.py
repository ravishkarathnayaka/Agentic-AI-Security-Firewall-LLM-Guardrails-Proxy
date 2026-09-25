import pytest
from proxy.guards.semantic_loop_breaker import SemanticLoopBreaker, SemanticLoopResult


@pytest.fixture
def breaker():
    return SemanticLoopBreaker(similarity_threshold=0.80, max_consecutive_repetitions=3, window_size=5)


def test_varied_conversation_no_loop(breaker):
    s_id = "session_normal"
    t1 = "Let's inspect the application codebase for security vulnerabilities."
    t2 = "Found three potential SQL injection entry points in the database layer."
    t3 = "Applying parameterized query fixes and verifying unit test passes."

    assert breaker.check_turn(s_id, t1).is_loop_detected is False
    assert breaker.check_turn(s_id, t2).is_loop_detected is False
    assert breaker.check_turn(s_id, t3).is_loop_detected is False


def test_repetitive_loop_deadlock_detected(breaker):
    s_id = "session_looping"
    loop_text = "I apologize, but I encountered an unexpected error while executing the database query tool. Please retry."
    slight_variant = "I apologize, but I encountered an unexpected error while executing the database query tool! Please retry."

    # Turn 1: initial
    r1 = breaker.check_turn(s_id, loop_text)
    assert r1.is_loop_detected is False

    # Turn 2: repeat 1
    r2 = breaker.check_turn(s_id, slight_variant)
    assert r2.is_loop_detected is False

    # Turn 3: repeat 2
    r3 = breaker.check_turn(s_id, loop_text)
    assert r3.is_loop_detected is False

    # Turn 4: repeat 3 (hits max_consecutive=3)
    r4 = breaker.check_turn(s_id, slight_variant)
    assert r4.is_loop_detected is True
    assert r4.is_blocked is True
    assert r4.violation_code == "agent_semantic_loop_deadlock"
    assert r4.consecutive_repetitions >= 3


def test_short_responses_ignored(breaker):
    s_id = "session_short"
    for _ in range(5):
        res = breaker.check_turn(s_id, "OK, done")
        assert res.is_loop_detected is False


def test_session_isolation(breaker):
    s1 = "session_1"
    s2 = "session_2"
    text = "Executing tool call fetch_weather with parameters city=London."

    breaker.check_turn(s1, text)
    breaker.check_turn(s1, text)

    # Different session should not inherit s1's repetitions
    res = breaker.check_turn(s2, text)
    assert res.consecutive_repetitions == 0
    assert res.is_loop_detected is False


def test_reset_session(breaker):
    s_id = "session_reset"
    text = "Executing diagnostic ping on service endpoint host."
    breaker.check_turn(s_id, text)
    breaker.check_turn(s_id, text)
    breaker.reset_session(s_id)

    res = breaker.check_turn(s_id, text)
    assert res.consecutive_repetitions == 0
    assert res.is_loop_detected is False
