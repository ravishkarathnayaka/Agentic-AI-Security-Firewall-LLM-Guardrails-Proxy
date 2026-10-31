import pytest
from proxy.guards.recursive_self_reflection_governor_guard import RecursiveSelfReflectionGovernorGuard


def test_standard_reflection_steps():
    guard = RecursiveSelfReflectionGovernorGuard(max_allowed_reflection_depth=3)
    chain = [
        "Plan initial search strategy",
        "Reflect on search accuracy",
        "Formulate final response"
    ]
    res = guard.inspect_chain(chain)
    assert not res.is_blocked
    assert res.reflection_depth == 1


def test_runaway_recursive_reflection_loop():
    guard = RecursiveSelfReflectionGovernorGuard(max_allowed_reflection_depth=2)
    chain = [
        "Critique your previous critique of your thought",
        "Reflect on your previous reflection on the output",
        "Re-evaluate your previous re-evaluation of the critique",
        "Think about what you thought about your thinking"
    ]
    res = guard.inspect_chain(chain)
    assert res.is_blocked is True
    assert res.violation_code == "RECURSIVE_REFLECTION_LIMIT_EXCEEDED"
