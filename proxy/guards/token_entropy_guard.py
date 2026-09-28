"""
Token Frequency Entropy & Repetition Suppression Guard
======================================================
Mitigates adversarial token degeneration attacks, repetitive token flooding,
and low-entropy context stuffing used by attackers to exhaust context windows,
degrade LLM generation quality, or bypass attention layers.

Computes Shannon entropy across unigram and bigram distributions and measures
n-gram repetition ratios against adaptive statistical baselines.
"""

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class TokenEntropyResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    details: Optional[str] = None
    entropy: float = 0.0
    repetition_ratio: float = 0.0
    token_count: int = 0


class TokenEntropyGuard:
    """
    Analyzes prompt text to ensure sufficient informational entropy and
    suppress malicious token degeneration loops or low-entropy stuffing.
    """

    def __init__(
        self,
        min_token_threshold: int = 35,
        min_shannon_entropy: float = 2.2,
        max_repetition_ratio: float = 0.65,
        max_single_token_fraction: float = 0.35,
    ):
        self.min_token_threshold = min_token_threshold
        self.min_shannon_entropy = min_shannon_entropy
        self.max_repetition_ratio = max_repetition_ratio
        self.max_single_token_fraction = max_single_token_fraction

    def _tokenize(self, text: str) -> List[str]:
        # Fast regex word/token extractor
        return re.findall(r"\w+|[^\w\s]", text.lower())

    def _calculate_shannon_entropy(self, tokens: List[str]) -> float:
        if not tokens:
            return 0.0
        n = len(tokens)
        counts = Counter(tokens)
        entropy = 0.0
        for count in counts.values():
            p = count / n
            entropy -= p * math.log2(p)
        return entropy

    def inspect_text(self, text: str) -> TokenEntropyResult:
        """
        Analyze token entropy and repetition ratio.
        """
        if not text or not text.strip():
            return TokenEntropyResult(is_blocked=False)

        tokens = self._tokenize(text)
        n = len(tokens)

        # Skip evaluation for very short prompts
        if n < self.min_token_threshold:
            return TokenEntropyResult(
                is_blocked=False,
                token_count=n,
            )

        counts = Counter(tokens)
        most_common_token, highest_count = counts.most_common(1)[0]
        single_token_fraction = highest_count / n

        # Check if a single token dominates the prompt excessively
        if single_token_fraction > self.max_single_token_fraction:
            return TokenEntropyResult(
                is_blocked=True,
                violation_code="excessive_token_repetition",
                details=(
                    f"Single token '{most_common_token}' dominates {single_token_fraction:.1%} "
                    f"of prompt (limit {self.max_single_token_fraction:.1%})"
                ),
                repetition_ratio=single_token_fraction,
                token_count=n,
            )

        # Calculate Shannon entropy
        entropy = self._calculate_shannon_entropy(tokens)

        # Low entropy indicates degenerate repeated sequences
        if entropy < self.min_shannon_entropy:
            return TokenEntropyResult(
                is_blocked=True,
                violation_code="low_entropy_token_stuffing",
                details=(
                    f"Prompt Shannon entropy {entropy:.2f} bits below minimum "
                    f"threshold {self.min_shannon_entropy:.2f} bits"
                ),
                entropy=entropy,
                token_count=n,
            )

        # Calculate bigram repetition ratio
        if n >= 2:
            bigrams = [(tokens[i], tokens[i + 1]) for i in range(n - 1)]
            unique_bigrams = len(set(bigrams))
            bigram_repetition = 1.0 - (unique_bigrams / len(bigrams))
            if bigram_repetition > self.max_repetition_ratio:
                return TokenEntropyResult(
                    is_blocked=True,
                    violation_code="excessive_ngram_repetition",
                    details=(
                        f"Bigram repetition ratio {bigram_repetition:.2f} exceeds "
                        f"maximum allowed {self.max_repetition_ratio:.2f}"
                    ),
                    entropy=entropy,
                    repetition_ratio=bigram_repetition,
                    token_count=n,
                )

        return TokenEntropyResult(
            is_blocked=False,
            entropy=entropy,
            repetition_ratio=single_token_fraction,
            token_count=n,
        )
