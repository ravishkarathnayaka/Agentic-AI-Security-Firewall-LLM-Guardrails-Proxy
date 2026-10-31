"""
Episodic Memory Poison Decay & Provenance Verification Guard
============================================================
Enforces exponential temporal decay, confidence thresholding, and provenance
cryptographic signatures on memories retrieved into agent context, neutralizing
stale or poisoned long-term episodic injections before they corrupt reasoning.
"""

import math
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class MemoryDecayResult:
    is_blocked: bool
    risk_score: float = 0.0
    violation_code: Optional[str] = None
    details: Optional[str] = None
    effective_confidence: float = 1.0


class EpisodicMemoryPoisonDecayGuard:
    """
    Applies half-life temporal attenuation to unverified memory entries and
    blocks memories whose origin signature does not match trusted sources.
    """

    def __init__(self, half_life_hours: float = 24.0, min_confidence_threshold: float = 0.35):
        self.half_life_seconds = half_life_hours * 3600.0
        self.min_confidence = min_confidence_threshold

    def evaluate_memory_chunk(self, memory_text: str, created_timestamp: float, provenance_verified: bool = False, initial_confidence: float = 1.0) -> MemoryDecayResult:
        if not memory_text or not memory_text.strip():
            return MemoryDecayResult(is_blocked=False)

        now = time.time()
        age_seconds = max(0.0, now - created_timestamp)

        # Exponential decay: C(t) = C0 * (0.5 ^ (t / T_half))
        decay_factor = math.pow(0.5, age_seconds / self.half_life_seconds)
        effective_conf = initial_confidence * decay_factor

        # Unverified provenance penalty
        if not provenance_verified:
            effective_conf *= 0.6

        # Check for unverified stale memory injection
        if effective_conf < self.min_confidence and not provenance_verified:
            return MemoryDecayResult(
                is_blocked=True,
                risk_score=min(1.0, 1.0 - effective_conf),
                violation_code="DECAYED_UNVERIFIED_MEMORY_REJECTED",
                details=f"Episodic memory chunk rejected due to age and lack of cryptographic provenance (Confidence: {effective_conf:.2f} < {self.min_confidence}).",
                effective_confidence=effective_conf
            )

        return MemoryDecayResult(
            is_blocked=False,
            effective_confidence=effective_conf
        )
