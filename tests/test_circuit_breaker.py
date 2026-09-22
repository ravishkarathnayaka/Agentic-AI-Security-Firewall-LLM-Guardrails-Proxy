"""Unit tests for Upstream LLM Circuit Breaker."""

import time
import pytest
from proxy.resilience.circuit_breaker import CircuitBreaker, CircuitState


@pytest.fixture
def breaker():
    return CircuitBreaker(
        failure_threshold=3,
        recovery_timeout_seconds=0.2,  # fast timeout for test execution
        half_open_success_threshold=2,
    )


def test_initial_state_is_closed(breaker):
    assert breaker.state == CircuitState.CLOSED
    assert breaker.allow_request() is True


def test_trips_to_open_after_failure_threshold(breaker):
    assert breaker.allow_request() is True
    breaker.record_failure()
    assert breaker.state == CircuitState.CLOSED
    breaker.record_failure()
    assert breaker.state == CircuitState.CLOSED
    breaker.record_failure()
    # 3 failures reached
    assert breaker.state == CircuitState.OPEN
    assert breaker.allow_request() is False


def test_recovers_through_half_open_to_closed(breaker):
    # Force trip to OPEN
    for _ in range(3):
        breaker.record_failure()
    assert breaker.state == CircuitState.OPEN
    assert breaker.allow_request() is False

    # Wait for recovery timeout
    time.sleep(0.25)

    # First request after timeout should transition to HALF_OPEN
    assert breaker.allow_request() is True
    assert breaker.state == CircuitState.HALF_OPEN

    # Two consecutive successes needed to close
    breaker.record_success()
    assert breaker.state == CircuitState.HALF_OPEN
    breaker.record_success()
    assert breaker.state == CircuitState.CLOSED
    assert breaker.allow_request() is True


def test_fails_in_half_open_trips_immediately_to_open(breaker):
    for _ in range(3):
        breaker.record_failure()
    time.sleep(0.25)
    breaker.allow_request()
    assert breaker.state == CircuitState.HALF_OPEN

    # Failure during probe trips back to OPEN
    breaker.record_failure()
    assert breaker.state == CircuitState.OPEN
    assert breaker.allow_request() is False


def test_manual_reset(breaker):
    for _ in range(3):
        breaker.record_failure()
    assert breaker.state == CircuitState.OPEN

    breaker.reset()
    assert breaker.state == CircuitState.CLOSED
    assert breaker.allow_request() is True
