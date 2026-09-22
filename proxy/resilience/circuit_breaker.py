"""Upstream LLM Circuit Breaker and Fallback Router (OWASP LLM04).

Prevents proxy hanging and cascading failures when upstream model endpoints
fail, timeout, or return HTTP 429/500 errors.
"""

from enum import Enum
import time
from typing import Callable, Optional


class CircuitState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class CircuitBreakerOpenException(Exception):
    """Raised when request is rejected because the circuit breaker is open."""
    pass


class CircuitBreaker:
    """Three-state circuit breaker for resilient upstream model routing."""

    def __init__(
        self,
        failure_threshold: int = 3,
        recovery_timeout_seconds: float = 15.0,
        half_open_success_threshold: int = 2,
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout_seconds = recovery_timeout_seconds
        self.half_open_success_threshold = half_open_success_threshold

        self.state: CircuitState = CircuitState.CLOSED
        self.consecutive_failures: int = 0
        self.consecutive_successes: int = 0
        self.last_state_change: float = time.time()

    def allow_request(self) -> bool:
        """Check if a new request is allowed to pass to upstream."""
        now = time.time()

        if self.state == CircuitState.CLOSED:
            return True

        if self.state == CircuitState.OPEN:
            # Check if recovery timeout has elapsed
            if now - self.last_state_change >= self.recovery_timeout_seconds:
                self.state = CircuitState.HALF_OPEN
                self.last_state_change = now
                self.consecutive_successes = 0
                return True
            return False

        if self.state == CircuitState.HALF_OPEN:
            return True

        return False

    def record_success(self):
        """Record a successful response from upstream."""
        if self.state == CircuitState.HALF_OPEN:
            self.consecutive_successes += 1
            if self.consecutive_successes >= self.half_open_success_threshold:
                self.state = CircuitState.CLOSED
                self.consecutive_failures = 0
                self.consecutive_successes = 0
                self.last_state_change = time.time()
        elif self.state == CircuitState.CLOSED:
            self.consecutive_failures = 0

    def record_failure(self):
        """Record an upstream failure (timeout, network error, 5xx)."""
        now = time.time()
        self.consecutive_failures += 1

        if self.state == CircuitState.HALF_OPEN:
            # Immediate trip back to OPEN
            self.state = CircuitState.OPEN
            self.last_state_change = now
        elif self.state == CircuitState.CLOSED:
            if self.consecutive_failures >= self.failure_threshold:
                self.state = CircuitState.OPEN
                self.last_state_change = now

    def reset(self):
        """Force manual reset to CLOSED state."""
        self.state = CircuitState.CLOSED
        self.consecutive_failures = 0
        self.consecutive_successes = 0
        self.last_state_change = time.time()
