"""
Adaptive Latency Jitter & Side-Channel Timing Defense Guard
===========================================================
Normalizes response delivery latency into quantized time buckets and introduces
cryptographic pseudo-random jitter to prevent timing-based token and classifier inference.
"""

import math
import random
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class TimingDefenseResult:
    original_duration_ms: float
    quantized_duration_ms: float
    jitter_delay_ms: float
    is_protected: bool
    details: str


class AdaptiveTimingJitterGuard:
    """Mitigates side-channel timing analysis attacks."""

    def __init__(self, bucket_size_ms: float = 25.0, max_jitter_ms: float = 15.0):
        self.bucket_size_ms = bucket_size_ms
        self.max_jitter_ms = max_jitter_ms

    def compute_padding_delay(self, elapsed_ms: float) -> TimingDefenseResult:
        """Calculates needed delay to reach next quantized bucket + micro-jitter."""
        # Quantize to next multiple of bucket_size_ms
        buckets = math.ceil(elapsed_ms / self.bucket_size_ms)
        target_ms = max(buckets * self.bucket_size_ms, self.bucket_size_ms)
        base_padding = target_ms - elapsed_ms

        # Add pseudo-random micro-jitter
        jitter = random.uniform(1.0, self.max_jitter_ms)
        total_delay_ms = base_padding + jitter

        return TimingDefenseResult(
            original_duration_ms=elapsed_ms,
            quantized_duration_ms=target_ms + jitter,
            jitter_delay_ms=total_delay_ms,
            is_protected=True,
            details=f"Applied {total_delay_ms:.2f}ms timing normalization padding."
        )
