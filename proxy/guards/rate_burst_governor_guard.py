"""
Adaptive Rate Burst Governor Guard
==================================
Adaptive token-bucket rate limiter and burst governor.
Dynamically scales maximum burst capacity and refill rate according to
client security risk score, anomaly velocity, and recent violation counts.
Prevents low-and-slow brute forcing, API denial-of-wallet, and automated
jailbreak fuzzing sweeps.
"""

import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple


@dataclass
class RateGovernorResult:
    is_allowed: bool
    remaining_tokens: float = 0.0
    retry_after_sec: float = 0.0
    current_capacity: float = 0.0
    violation_code: Optional[str] = None
    details: Optional[str] = None


@dataclass
class ClientBucket:
    tokens: float
    capacity: float
    refill_rate: float
    last_update: float
    penalty_score: float = 0.0


class AdaptiveRateBurstGovernorGuard:
    """
    Manages per-client adaptive token buckets with risk-weighted throttling.
    """

    def __init__(
        self,
        base_capacity: float = 20.0,
        base_refill_rate: float = 2.0,  # tokens per second
        min_capacity: float = 2.0,
    ):
        self.base_capacity = base_capacity
        self.base_refill_rate = base_refill_rate
        self.min_capacity = min_capacity
        # client_id -> ClientBucket
        self._buckets: Dict[str, ClientBucket] = {}

    def penalize_client(self, client_id: str, penalty_delta: float = 1.0) -> None:
        """Increase penalty score on client for security violations."""
        if client_id in self._buckets:
            self._buckets[client_id].penalty_score = min(
                10.0,
                self._buckets[client_id].penalty_score + penalty_delta
            )

    def consume(
        self,
        client_id: str,
        cost: float = 1.0,
        current_time: Optional[float] = None
    ) -> RateGovernorResult:
        """
        Attempt to consume token(s) from client bucket.
        """
        now = current_time if current_time is not None else time.time()

        if client_id not in self._buckets:
            self._buckets[client_id] = ClientBucket(
                tokens=self.base_capacity,
                capacity=self.base_capacity,
                refill_rate=self.base_refill_rate,
                last_update=now,
                penalty_score=0.0
            )

        bucket = self._buckets[client_id]

        # Calculate effective capacity based on penalty
        # Higher penalty shrinks bucket capacity and slows refill rate
        penalty_factor = max(0.1, 1.0 - (bucket.penalty_score * 0.1))
        effective_capacity = max(self.min_capacity, self.base_capacity * penalty_factor)
        effective_refill = max(0.2, self.base_refill_rate * penalty_factor)

        # Refill tokens since last update
        elapsed = now - bucket.last_update
        bucket.tokens = min(effective_capacity, bucket.tokens + (elapsed * effective_refill))
        bucket.last_update = now

        # Decay penalty score slowly over time
        if elapsed > 10.0 and bucket.penalty_score > 0:
            bucket.penalty_score = max(0.0, bucket.penalty_score - (elapsed * 0.05))

        if bucket.tokens >= cost:
            bucket.tokens -= cost
            return RateGovernorResult(
                is_allowed=True,
                remaining_tokens=bucket.tokens,
                current_capacity=effective_capacity,
            )

        # Bucket empty - calculate wait time
        needed = cost - bucket.tokens
        wait_sec = needed / effective_refill
        return RateGovernorResult(
            is_allowed=False,
            remaining_tokens=bucket.tokens,
            retry_after_sec=round(wait_sec, 2),
            current_capacity=effective_capacity,
            violation_code="rate_burst_quota_exceeded",
            details=f"Rate limit burst quota exceeded. Please retry after {wait_sec:.2f} seconds."
        )
