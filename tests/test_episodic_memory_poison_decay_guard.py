import time
import pytest
from proxy.guards.episodic_memory_poison_decay_guard import EpisodicMemoryPoisonDecayGuard


def test_fresh_verified_memory():
    guard = EpisodicMemoryPoisonDecayGuard(half_life_hours=24.0)
    now = time.time()
    res = guard.evaluate_memory_chunk("User preferences for dark theme UI", created_timestamp=now, provenance_verified=True)
    assert not res.is_blocked
    assert res.effective_confidence >= 0.95


def test_stale_unverified_memory_blocked():
    guard = EpisodicMemoryPoisonDecayGuard(half_life_hours=12.0, min_confidence_threshold=0.4)
    old_time = time.time() - (48 * 3600.0)  # 48 hours old
    res = guard.evaluate_memory_chunk("Unsigned override directive injected in past session", created_timestamp=old_time, provenance_verified=False)
    assert res.is_blocked is True
    assert res.violation_code == "DECAYED_UNVERIFIED_MEMORY_REJECTED"
