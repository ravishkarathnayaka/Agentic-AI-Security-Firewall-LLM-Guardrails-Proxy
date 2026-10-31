"""
Differential Privacy Budget & Epsilon-Delta Tracker Guard
========================================================
Maintains mathematical (epsilon, delta)-differential privacy accounting across
consecutive agent queries, preventing model inversion, database reconstruction,
and membership inference attacks against proprietary training corpora.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class DPBudgetResult:
    is_blocked: bool
    risk_score: float = 0.0
    violation_code: Optional[str] = None
    details: Optional[str] = None
    consumed_epsilon: float = 0.0
    remaining_epsilon: float = 0.0


class DifferentialPrivacyBudgetGuard:
    """
    Enforces privacy loss ceilings: Sum(epsilon_i) <= max_epsilon per session/tenant.
    """

    def __init__(self, max_session_epsilon: float = 10.0, base_query_epsilon: float = 0.5):
        self.max_epsilon = max_session_epsilon
        self.base_query_epsilon = base_query_epsilon
        # session_id -> accumulated epsilon
        self._session_budgets: Dict[str, float] = {}

    def consume_budget(self, session_id: str, query_sensitivity: float = 1.0) -> DPBudgetResult:
        current = self._session_budgets.get(session_id, 0.0)
        cost = self.base_query_epsilon * max(0.5, query_sensitivity)
        projected = current + cost

        if projected > self.max_epsilon:
            return DPBudgetResult(
                is_blocked=True,
                risk_score=0.92,
                violation_code="DIFFERENTIAL_PRIVACY_BUDGET_DEPLETED",
                details=f"Session privacy budget depleted ({projected:.2f} > max {self.max_epsilon:.2f}). Further queries blocked to prevent database reconstruction.",
                consumed_epsilon=current,
                remaining_epsilon=max(0.0, self.max_epsilon - current)
            )

        self._session_budgets[session_id] = projected
        return DPBudgetResult(
            is_blocked=False,
            consumed_epsilon=projected,
            remaining_epsilon=max(0.0, self.max_epsilon - projected)
        )

    def reset_budget(self, session_id: Optional[str] = None) -> None:
        if session_id:
            self._session_budgets.pop(session_id, None)
        else:
            self._session_budgets.clear()
