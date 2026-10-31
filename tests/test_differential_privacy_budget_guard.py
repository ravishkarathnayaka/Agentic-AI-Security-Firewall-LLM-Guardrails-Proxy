import pytest
from proxy.guards.differential_privacy_budget_guard import DifferentialPrivacyBudgetGuard


def test_normal_dp_budget_consumption():
    guard = DifferentialPrivacyBudgetGuard(max_session_epsilon=5.0, base_query_epsilon=1.0)
    res = guard.consume_budget("session_alpha", query_sensitivity=1.0)
    assert not res.is_blocked
    assert res.consumed_epsilon == 1.0
    assert res.remaining_epsilon == 4.0


def test_dp_budget_depletion_blocked():
    guard = DifferentialPrivacyBudgetGuard(max_session_epsilon=3.0, base_query_epsilon=1.0)
    guard.consume_budget("session_beta", query_sensitivity=1.5)  # 1.5
    guard.consume_budget("session_beta", query_sensitivity=1.0)  # 2.5
    res = guard.consume_budget("session_beta", query_sensitivity=1.0)  # would be 3.5 > 3.0
    assert res.is_blocked is True
    assert res.violation_code == "DIFFERENTIAL_PRIVACY_BUDGET_DEPLETED"
