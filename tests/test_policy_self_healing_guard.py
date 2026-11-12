import pytest
from proxy.guards.policy_self_healing_guard import PolicySelfHealingGuard


def test_self_healing_threshold_tightening():
    guard = PolicySelfHealingGuard(baseline_threshold=0.60)
    status1 = guard.record_violation("agent_attacker")
    assert status1.adjusted_threshold < 0.60
    assert status1.is_quarantined is False


def test_agent_temporary_quarantine():
    guard = PolicySelfHealingGuard(quarantine_limit=3)
    guard.record_violation("ip_malicious")
    guard.record_violation("ip_malicious")
    status = guard.record_violation("ip_malicious")
    assert status.is_quarantined is True
    assert guard.is_quarantined("ip_malicious") is True


def test_cooldown_and_decay():
    guard = PolicySelfHealingGuard()
    assert guard.is_quarantined("clean_client") is False
