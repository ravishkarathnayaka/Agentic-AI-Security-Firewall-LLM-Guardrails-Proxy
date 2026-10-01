"""
Adaptive Risk-Weighted Rate & Burst Throttling Guard
===================================================
Dynamically modulates token-bucket rates and burst tolerances according to real-time
agent threat risk levels. As cumulative anomaly scores increase, allowed request rates
and compute allocations shrink dynamically.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class AdaptiveBurstResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    details: Optional[str] = None
    remaining_tokens: float = 0.0
    effective_rate_per_sec: float = 10.0
    current_risk_multiplier: float = 1.0


class AdaptiveRateBurstGuard:
    """
    Applies an adaptive leaky-bucket algorithm that dampens token consumption
    allowances inversely proportional to the session's cumulative threat score.
    """

    def __init__(
        self,
        base_rate_per_sec: float = 10.0,
        max_bucket_capacity: float = 20.0,
        high_risk_penalty_factor: float = 0.2,  # drops rate to 20% on high risk
    ):
        self.base_rate_per_sec = base_rate_per_sec
        self.max_bucket_capacity = max_bucket_capacity
        self.high_risk_penalty_factor = high_risk_penalty_factor

        # session_id -> (current_tokens, last_refill_timestamp)
        self._buckets: Dict[str, tuple[float, float]] = {}

    def evaluate_request(
        self,
        session_id: str,
        token_cost: float = 1.0,
        risk_score: float = 0.0,  # 0.0 to 1.0
        current_time: Optional[float] = None,
    ) -> AdaptiveBurstResult:
        """
        Evaluates token availability adjusted for threat risk level.
        """
        now = current_time if current_time is not None else time.time()

        # Risk multiplier reduces effective refill rate
        clamped_risk = max(0.0, min(1.0, risk_score))
        risk_multiplier = 1.0 - clamped_risk * (1.0 - self.high_risk_penalty_factor)
        effective_rate = self.base_rate_per_sec * risk_multiplier

        if session_id not in self._buckets:
            tokens = self.max_bucket_capacity
            last_time = now
        else:
            tokens, last_time = self._buckets[session_id]
            delta = max(0.0, now - last_time)
            tokens = min(self.max_bucket_capacity, tokens + delta * effective_rate)

        if tokens < token_cost:
            # Capacity exceeded
            self._buckets[session_id] = (tokens, now)
            return AdaptiveBurstResult(
                is_blocked=True,
                violation_code="ADAPTIVE_BURST_RATE_EXCEEDED",
                details=(
                    f"Session rate limit exceeded under risk profile "
                    f"(risk={clamped_risk:.2f}, effective_rate={effective_rate:.2f}/s, "
                    f"tokens={tokens:.2f}/{token_cost})"
                ),
                remaining_tokens=tokens,
                effective_rate_per_sec=effective_rate,
                current_risk_multiplier=risk_multiplier,
            )

        # Deduct cost
        tokens -= token_cost
        self._buckets[session_id] = (tokens, now)

        return AdaptiveBurstResult(
            is_blocked=False,
            remaining_tokens=tokens,
            effective_rate_per_sec=effective_rate,
            current_risk_multiplier=risk_multiplier,
        )

    def reset(self, session_id: Optional[str] = None) -> None:
        if session_id:
            self._buckets.pop(session_id, None)
        else:
            self._buckets.clear()
