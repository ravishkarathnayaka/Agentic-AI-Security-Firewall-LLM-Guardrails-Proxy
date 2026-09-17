"""Unit tests for token-bucket rate limiter guard (OWASP LLM04)."""

import time
import pytest
from proxy.guards.rate_limiter import RateLimiter


@pytest.fixture
def limiter():
    return RateLimiter(requests_per_minute=10, burst_limit=5)


def test_requests_within_limits_allowed(limiter):
    """Test that requests within rate allowances pass."""
    for _ in range(4):
        res = limiter.check("client_127.0.0.1")
        assert res.is_allowed is True


def test_burst_limit_exceeded(limiter):
    """Test that exceeding per-second burst limit blocks subsequent requests."""
    for _ in range(5):
        res = limiter.check("burst_client")
        assert res.is_allowed is True

    # 6th request within 1 second triggers burst block
    blocked_res = limiter.check("burst_client")
    assert blocked_res.is_allowed is False
    assert "Burst limit exceeded" in blocked_res.details
    assert blocked_res.retry_after_seconds > 0


def test_client_ip_isolation(limiter):
    """Verify that hitting the rate limit on one client does not affect another."""
    # Exhaust client A
    for _ in range(6):
        limiter.check("client_a")

    # Client B should still be completely unconstrained
    res_b = limiter.check("client_b")
    assert res_b.is_allowed is True
    assert res_b.current_count == 1


def test_rate_limiter_reset(limiter):
    """Verify that reset clears history and restores access."""
    for _ in range(6):
        limiter.check("temp_client")

    assert limiter.check("temp_client").is_allowed is False
    limiter.reset("temp_client")
    assert limiter.check("temp_client").is_allowed is True
