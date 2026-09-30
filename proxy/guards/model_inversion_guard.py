"""
Model Inversion & Training Data Extraction Defense Guard
========================================================
Mitigates model inversion, membership inference, verbatim training data
extraction, and raw logit probability probing attacks.
Detects targeted extraction prompts designed to trigger unaligned memorization
spills or statistical parameter reconstruction.
"""

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class ModelInversionResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    details: Optional[str] = None
    confidence_score: float = 0.0


class ModelInversionDefenseGuard:
    """
    Scans prompts and model generations for training data extraction signatures
    and model inversion probes.
    """

    INVERSION_PATTERNS = [
        (
            re.compile(r"repeat\s+the\s+(?:word|token|phrase)\s+['\"`]?\w+['\"`]?\s+(?:forever|indefinitely|10000|\d{4,})", re.IGNORECASE),
            "divergence_memorization_extraction",
            0.95
        ),
        (
            re.compile(r"(?:reconstruct|extract|reveal|dump)\s+.*?(?:training\s+(?:data|set|corpus)|model\s+weights)", re.IGNORECASE),
            "training_corpus_extraction_probe",
            0.92
        ),
        (
            re.compile(r"(?:output|print|show|extract|dump)\s+.*?(?:logprobs?|logits?|probability\s+vectors?)", re.IGNORECASE),
            "logit_distribution_probing",
            0.90
        ),
        (
            re.compile(r"(?:membership\s+inference|was\s+(?:present\s+in|in)\s+(?:your\s+)?(?:pre[-_ ]?)?training|(?:record|individual|ssn|patient).*?in\s+(?:your\s+)?(?:pre[-_ ]?)?training)", re.IGNORECASE),
            "membership_inference_probe",
            0.90
        ),
        (
            re.compile(r"(?:recite|dump)\s+(?:the\s+)?(?:first|entire)\s+\d{3,}\s+tokens\s+of\s+(?:your\s+training|common\s+crawl)", re.IGNORECASE),
            "verbatim_corpus_spill_probe",
            0.93
        ),
        (
            re.compile(r"(?:attention\s+head\s+weights|projection\s+matrices|feed[-_ ]forward\s+bias\s+tensors|layer\s+\d+\s+weights)", re.IGNORECASE),
            "weight_reconstruction_probe",
            0.92
        ),
        (
            re.compile(r"(?:differential\s+loss\s+gradients?|loss\s+gradients?.*?input\s+embedding|reconstruct\s+upstream\s+proprietary)", re.IGNORECASE),
            "gradient_leakage_probe",
            0.92
        ),
        (
            re.compile(r"(?:hidden\s+state\s+activation|activation\s+vectors?.*?invert|latent\s+space\s+representation)", re.IGNORECASE),
            "latent_representation_inversion",
            0.92
        ),
        (
            re.compile(r"(?:differential\s+privacy\s+epsilon|high[-_ ]frequency\s+perturbation.*?reconstruct|boundary\s+inversion)", re.IGNORECASE),
            "differential_privacy_boundary_probe",
            0.92
        ),
    ]

    def __init__(self, block_threshold: float = 0.85):
        self.block_threshold = block_threshold

    def inspect_prompt(self, text: str) -> ModelInversionResult:
        """Inspect prompt for model inversion and training extraction queries."""
        if not text:
            return ModelInversionResult(is_blocked=False)

        for pattern, code, score in self.INVERSION_PATTERNS:
            if pattern.search(text):
                if score >= self.block_threshold:
                    return ModelInversionResult(
                        is_blocked=True,
                        violation_code=code,
                        details=f"Model inversion / training extraction attempt detected ({code})",
                        confidence_score=score,
                    )

        return ModelInversionResult(is_blocked=False)
