"""
Speculative Decoding & Draft Token Poisoning Guard
==================================================
Inspects speculative decoding draft proposals (small speculative draft model tokens)
to stop draft poisoning attacks designed to bypass acceptance sampling logic.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class SpeculativeInspectionResult:
    is_valid: bool
    is_blocked: bool
    rejected_tokens: List[int] = field(default_factory=list)
    violation_code: Optional[str] = None
    details: Optional[str] = None


class SpeculativeDecodingGuard:
    """Guards draft token acceptance sequences in speculative decoding."""

    def __init__(self, max_entropy_divergence: float = 4.5):
        self.max_entropy_divergence = max_entropy_divergence

    def verify_draft_sequence(self, draft_tokens: List[int], entropy_scores: List[float]) -> SpeculativeInspectionResult:
        if not draft_tokens:
            return SpeculativeInspectionResult(is_valid=True, is_blocked=False, details="No draft tokens.")

        poisoned = []
        for tok, score in zip(draft_tokens, entropy_scores):
            # Check for illegal control tokens or extreme entropy divergence
            if tok in (50256, 50257, 128001, 128009) or score > self.max_entropy_divergence:
                poisoned.append(tok)

        if poisoned:
            return SpeculativeInspectionResult(
                is_valid=False,
                is_blocked=True,
                rejected_tokens=poisoned,
                violation_code="SPECULATIVE_TOKEN_POISON_REJECTED",
                details=f"Draft model proposed anomalous or control tokens: {poisoned}."
            )

        return SpeculativeInspectionResult(
            is_valid=True,
            is_blocked=False,
            details="Speculative draft token sequence verified."
        )
