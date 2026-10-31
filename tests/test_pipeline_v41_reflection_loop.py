import pytest
from proxy.guards.recursive_self_reflection_governor_guard import RecursiveSelfReflectionGovernorGuard


def test_reflection_chain_depth_limit():
    gov = RecursiveSelfReflectionGovernorGuard(max_allowed_reflection_depth=3)

    benign_chain = ["Step 1: plan", "Step 2: reflect on output", "Step 3: finalize"]
    assert gov.inspect_chain(benign_chain).is_blocked is False

    malicious_chain = [
        "Critique your previous critique of your thought",
        "Reflect on your previous reflection on the output",
        "Re-evaluate your previous re-evaluation of the critique",
        "Think about what you thought about your thinking"
    ]
    res = gov.inspect_chain(malicious_chain)
    assert res.is_blocked is True
    assert res.violation_code == "RECURSIVE_REFLECTION_LIMIT_EXCEEDED"
