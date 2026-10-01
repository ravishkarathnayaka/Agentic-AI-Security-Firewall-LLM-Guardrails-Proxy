import pytest
from proxy.guards.semantic_cache_poisoning_guard import SemanticCachePoisoningGuard


def test_cache_poisoning_nominal():
    guard = SemanticCachePoisoningGuard()
    res = guard.evaluate_cache_write("key_calc", "calculate taxes for 2026", "tax is 15%")
    assert not res.is_blocked
    assert res.collision_count == 1


def test_cache_poisoning_collision_blocked():
    guard = SemanticCachePoisoningGuard(
        similarity_collision_threshold=0.8,
        max_collisions_per_key=2,
    )
    # Add first two entries
    guard.evaluate_cache_write("key_weather", "what is the weather today in london", "sunny")
    guard.evaluate_cache_write("key_weather", "what is the weather today in london city", "rainy")
    # Third near-duplicate collision triggers block
    res = guard.evaluate_cache_write("key_weather", "what is the weather today in london area", "poisoned")
    assert res.is_blocked
    assert res.violation_code == "SEMANTIC_CACHE_POISONING_COLLISION"
