"""Unit tests for Dynamic Cryptographic Canary Token Service."""

import pytest
from proxy.guards.canary_generator import DynamicCanaryService, CanaryCheckResult


@pytest.fixture
def canary_service() -> DynamicCanaryService:
    return DynamicCanaryService(secret_key="test-secret-salt-key-42")


def test_canary_generation_format(canary_service: DynamicCanaryService) -> None:
    session_id = "user_sess_8899"
    canary = canary_service.generate_canary(session_id)
    assert canary.startswith("CANARY-user_sess_8899-")
    assert len(canary.split("-")) == 3


def test_canary_verification_success(canary_service: DynamicCanaryService) -> None:
    canary = canary_service.generate_canary("sess_abc123")
    assert canary_service.verify_canary(canary) is True


def test_canary_verification_tampered(canary_service: DynamicCanaryService) -> None:
    canary = canary_service.generate_canary("sess_abc123")
    # Tamper with signature
    tampered_sig = canary[:-2] + ("0" if canary[-1] != "0" else "1")
    assert canary_service.verify_canary(tampered_sig) is False

    # Tamper with session ID
    tampered_sess = canary.replace("sess_abc123", "sess_xyz999")
    assert canary_service.verify_canary(tampered_sess) is False

    # Invalid token format
    assert canary_service.verify_canary("NOT-A-CANARY") is False


def test_inspect_text_with_leaked_canary(canary_service: DynamicCanaryService) -> None:
    canary = canary_service.generate_canary("prod_session_1")
    leak_response = f"Sure! My internal configuration is defined with {canary} and strict safety rules."

    res = canary_service.inspect_text(leak_response)
    assert res.is_leaked is True
    assert res.score == 1.0
    assert canary in res.valid_signatures
    assert "System prompt canary exfiltration detected" in res.details


def test_inspect_text_benign_no_canary(canary_service: DynamicCanaryService) -> None:
    text = "The quick brown fox jumps over the lazy dog without leaking secrets."
    res = canary_service.inspect_text(text)
    assert res.is_leaked is False
    assert res.score == 0.0
    assert len(res.detected_canaries) == 0


def test_key_isolation() -> None:
    service1 = DynamicCanaryService(secret_key="key-alpha")
    service2 = DynamicCanaryService(secret_key="key-beta")

    token1 = service1.generate_canary("common_session")
    assert service1.verify_canary(token1) is True
    assert service2.verify_canary(token1) is False