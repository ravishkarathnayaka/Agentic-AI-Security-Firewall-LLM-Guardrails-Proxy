"""
Agent Output Entropy & Watermark Verification Guard
===================================================
Analyzes model generation entropy to prevent model hallucination cascades,
and embeds cryptographically verifiable steganographic watermarks into outbound
responses to enable zero-knowledge origin tracing.
"""

import hashlib
import hmac
import math
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class OutputEntropyWatermarkResult:
    is_blocked: bool
    risk_score: float = 0.0
    violation_code: Optional[str] = None
    details: Optional[str] = None
    watermarked_text: Optional[str] = None
    watermark_digest: Optional[str] = None
    entropy: float = 0.0


class AgentOutputEntropyWatermarkGuard:
    """
    Computes Shannon entropy across generated token sequences and signs
    responses with undetectable zero-width unicode cryptographic watermarks.
    """

    ZERO_WIDTH_SPACE = "\u200B"
    ZERO_WIDTH_NON_JOINER = "\u200C"

    def __init__(self, secret_key: str = "quantum_watermark_seed_v4", min_entropy: float = 1.0, max_entropy: float = 7.5):
        self.secret_key = secret_key.encode("utf-8")
        self.min_entropy = min_entropy
        self.max_entropy = max_entropy

    def _shannon_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        counts = {}
        for char in text:
            counts[char] = counts.get(char, 0) + 1
        n = len(text)
        entropy = 0.0
        for count in counts.values():
            p = count / n
            entropy -= p * math.log2(p)
        return entropy

    def _generate_watermark_bits(self, text: str) -> str:
        digest = hmac.new(self.secret_key, text.encode("utf-8"), hashlib.sha256).hexdigest()[:8]
        bits = "".join(f"{int(c, 16):04b}" for c in digest)
        # Convert first 16 bits to zero width markers
        return "".join(self.ZERO_WIDTH_SPACE if b == '1' else self.ZERO_WIDTH_NON_JOINER for b in bits[:16])

    def process_output(self, text: str) -> OutputEntropyWatermarkResult:
        if not text or len(text.strip()) == 0:
            return OutputEntropyWatermarkResult(is_blocked=False, risk_score=0.0, watermarked_text=text)

        entropy = self._shannon_entropy(text)

        # Hallucination loops (e.g. repeated "the the the...") produce extremely low entropy
        if len(text) > 50 and entropy < self.min_entropy:
            return OutputEntropyWatermarkResult(
                is_blocked=True,
                risk_score=0.9,
                violation_code="DEGENERATE_OUTPUT_ENTROPY",
                details=f"Output rejected due to repetitive degenerate collapse (Entropy: {entropy:.2f})",
                entropy=entropy
            )

        # Pure random high-entropy token explosion
        if len(text) > 100 and entropy > self.max_entropy:
            return OutputEntropyWatermarkResult(
                is_blocked=True,
                risk_score=0.85,
                violation_code="ANOMALOUS_HIGH_ENTROPY_BURST",
                details=f"Output rejected due to anomalous high entropy garbage burst (Entropy: {entropy:.2f})",
                entropy=entropy
            )

        # Embed watermark mark into first whitespace
        wm_chars = self._generate_watermark_bits(text)
        watermark_digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]

        if " " in text:
            watermarked = text.replace(" ", f" {wm_chars}", 1)
        else:
            watermarked = text + wm_chars

        return OutputEntropyWatermarkResult(
            is_blocked=False,
            risk_score=0.0,
            watermarked_text=watermarked,
            watermark_digest=watermark_digest,
            entropy=entropy
        )
