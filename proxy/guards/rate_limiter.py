"""Sliding-Window Token-Bucket Rate Limiter Guard (OWASP LLM04 - Model Denial of Service).

Prevents denial-of-service resource exhaustion and high-frequency automated jailbreak probing
by enforcing IP-based and client-based request rate limits.
"""

import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class RateLimitResult:
    """Outcome of rate limit check."""
    is_allowed: bool
    current_count: int
    limit: int
    retry_after_seconds: float = 0.0
    details: str = ""


class RateLimiter:
    """Sliding-window request rate limiter per client IP or API key."""

    def __init__(self, requests_per_minute: int = 60, burst_limit: int = 15):
        self.requests_per_minute = requests_per_minute
        self.burst_limit = burst_limit
        # Tracks timestamps of recent requests per identifier
        self._history: Dict[str, List[float]] = defaultdict(list)

    def check(self, client_id: str) -> RateLimitResult:
        """Check if client request is within rate limits.

        Args:
            client_id: Client IP address or API key identifier.

        Returns:
            RateLimitResult with decision and remaining allowances.
        """
        now = time.time()
        window_start = now - 60.0

        # Clean old entries older than 60 seconds
        history = self._history[client_id]
        while history and history[0] < window_start:
            history.pop(0)

        # Check minute rate limit
        current_count = len(history)
        if current_count >= self.requests_per_minute:
            oldest_in_window = history[0]
            retry_after = round(oldest_in_window + 60.0 - now, 1)
            return RateLimitResult(
                is_allowed=False,
                current_count=current_count,
                limit=self.requests_per_minute,
                retry_after_seconds=max(0.1, retry_after),
                details=f"Rate limit exceeded: {current_count}/{self.requests_per_minute} req/min for '{client_id}'."
            )

        # Check 1-second burst limit
        burst_start = now - 1.0
        burst_count = sum(1 for t in history if t >= burst_start)
        if burst_count >= self.burst_limit:
            return RateLimitResult(
                is_allowed=False,
                current_count=burst_count,
                limit=self.burst_limit,
                retry_after_seconds=1.0,
                details=f"Burst limit exceeded: {burst_count}/{self.burst_limit} req/sec for '{client_id}'."
            )

        # Record this request
        history.append(now)

        return RateLimitResult(
            is_allowed=True,
            current_count=current_count + 1,
            limit=self.requests_per_minute,
            details="Request permitted within rate boundaries."
        )

    def reset(self, client_id: Optional[str] = None):
        """Reset history for a client or all clients."""
        if client_id:
            self._history.pop(client_id, None)
        else:
            self._history.clear()
