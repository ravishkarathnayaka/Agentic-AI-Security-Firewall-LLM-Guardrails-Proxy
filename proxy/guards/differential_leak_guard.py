"""Differential N-Gram System Prompt Leakage Guard (OWASP LLM07).

Detects verbatim or near-verbatim system prompt leakage in model completions
by computing continuous n-gram containment and longest common token subsequences.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Set


@dataclass
class DifferentialLeakResult:
    """Result of differential n-gram leakage analysis."""
    is_blocked: bool
    violation_code: Optional[str] = None
    containment_score: float = 0.0
    longest_common_subsequence: int = 0
    matched_phrases: List[str] = field(default_factory=list)
    details: str = ""


class DifferentialLeakGuard:
    """Detects accidental or adversarial leakage of internal system prompts."""

    def __init__(
        self,
        protected_prompts: Optional[List[str]] = None,
        containment_threshold: float = 0.35,
        max_consecutive_token_threshold: int = 8,
        n_gram_size: int = 4,
    ):
        self.protected_prompts = protected_prompts or []
        self.containment_threshold = containment_threshold
        self.max_consecutive_token_threshold = max_consecutive_token_threshold
        self.n_gram_size = n_gram_size

    def set_protected_prompts(self, prompts: List[str]):
        """Update or register the active system prompts to guard."""
        self.protected_prompts = [p.strip() for p in prompts if p and p.strip()]

    def _tokenize(self, text: str) -> List[str]:
        """Normalize text into lowercase word tokens."""
        return re.findall(r"\b\w+\b", text.lower())

    def _get_ngrams(self, tokens: List[str], n: int) -> Set[tuple]:
        """Extract continuous n-grams from a token list."""
        if len(tokens) < n:
            return set()
        return {tuple(tokens[i : i + n]) for i in range(len(tokens) - n + 1)}

    def _longest_common_subsequence_length(self, seq1: List[str], seq2: List[str]) -> int:
        """Find the length of the longest contiguous sublist common to both."""
        m, n = len(seq1), len(seq2)
        if m == 0 or n == 0:
            return 0
        
        # DP table for contiguous matches
        dp = [0] * (n + 1)
        max_len = 0
        for i in range(1, m + 1):
            current = [0] * (n + 1)
            for j in range(1, n + 1):
                if seq1[i - 1] == seq2[j - 1]:
                    current[j] = dp[j - 1] + 1
                    if current[j] > max_len:
                        max_len = current[j]
            dp = current
        return max_len

    def inspect(self, completion: str, system_prompts: Optional[List[str]] = None) -> DifferentialLeakResult:
        """Inspect model completion against protected system prompts."""
        if not completion or not completion.strip():
            return DifferentialLeakResult(is_blocked=False)

        prompts_to_check = system_prompts if system_prompts is not None else self.protected_prompts
        if not prompts_to_check:
            return DifferentialLeakResult(is_blocked=False)

        comp_tokens = self._tokenize(completion)
        if len(comp_tokens) < self.n_gram_size:
            return DifferentialLeakResult(is_blocked=False)

        comp_ngrams = self._get_ngrams(comp_tokens, self.n_gram_size)
        if not comp_ngrams:
            return DifferentialLeakResult(is_blocked=False)

        max_containment = 0.0
        max_consecutive = 0
        matched_ngrams_sample = []

        for prompt in prompts_to_check:
            p_tokens = self._tokenize(prompt)
            if not p_tokens:
                continue

            p_ngrams = self._get_ngrams(p_tokens, self.n_gram_size)
            if not p_ngrams:
                continue

            # Containment: fraction of completion n-grams found in protected prompt
            overlap = comp_ngrams.intersection(p_ngrams)
            containment = len(overlap) / float(len(comp_ngrams))
            if containment > max_containment:
                max_containment = containment
                matched_ngrams_sample = [" ".join(gram) for gram in list(overlap)[:3]]

            # Longest contiguous sequence
            lcs = self._longest_common_subsequence_length(comp_tokens, p_tokens)
            if lcs > max_consecutive:
                max_consecutive = lcs

        # Determine violation
        violation = False
        reasons = []

        if max_containment >= self.containment_threshold:
            violation = True
            reasons.append(f"high n-gram containment ({max_containment * 100:.1f}% >= {self.containment_threshold * 100:.1f}%)")

        if max_consecutive >= self.max_consecutive_token_threshold:
            violation = True
            reasons.append(f"contiguous token leak ({max_consecutive} tokens >= {self.max_consecutive_token_threshold})")

        if violation:
            return DifferentialLeakResult(
                is_blocked=True,
                violation_code="system_prompt_differential_leak",
                containment_score=round(max_containment, 4),
                longest_common_subsequence=max_consecutive,
                matched_phrases=matched_ngrams_sample,
                details=f"System prompt leakage detected: {', '.join(reasons)}",
            )

        return DifferentialLeakResult(
            is_blocked=False,
            containment_score=round(max_containment, 4),
            longest_common_subsequence=max_consecutive,
        )
