"""
Adversarial Suffix Scanner & GCG Jailbreak Mitigation Guard
==========================================================
Detects token perturbation attacks, Greedy Coordinate Gradient (GCG) jailbreak suffixes,
and automated adversarial prompt appends (e.g., AutoDAN, PAIR) designed to bypass safety filters.
"""

import math
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class AdversarialSuffixResult:
    is_blocked: bool
    risk_score: float = 0.0
    violation_code: Optional[str] = None
    details: Optional[str] = None
    clean_prompt: Optional[str] = None
    suffix_signatures: List[str] = field(default_factory=list)


class AdversarialSuffixScannerGuard:
    """
    Scans prompts for high-entropy non-semantic token sequences and known GCG patterns.
    """

    GCG_REPRESENTATIVE_PATTERNS = [
        (r"(?:==\s*simultaneous\s+translate|describing\s+\.\s*\+|=|==\s*format\s+in\s+python)", "GCG_TEMPLATE_ARTIFACT"),
        (r"(?:!\s*!\s*!\s*!|\?\s*\?\s*\?\s*\?|\^\s*\^\s*\^)", "REPEATED_PUNCTUATION_ANOMALY"),
        (r"(?:describe\s+step\s+by\s+step\s+using\s+only\s+symbols)", "TOKEN_RESTRICTION_INVERSION"),
        (r"(?:write\s+a\s+fictional\s+story\s+where\s+a\s+character\s+bypasses)", "FICTIONAL_ROLEPLAY_SHIELD"),
    ]

    def __init__(self, entropy_threshold: float = 4.2):
        self.entropy_threshold = entropy_threshold
        self.compiled_gcg = [(re.compile(p, re.IGNORECASE), code) for p, code in self.GCG_REPRESENTATIVE_PATTERNS]

    def _calculate_unigram_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        tokens = text.split()
        if len(tokens) < 4:
            return 0.0
        freqs = {}
        for t in tokens:
            freqs[t] = freqs.get(t, 0) + 1
        entropy = 0.0
        n = len(tokens)
        for count in freqs.values():
            p = count / n
            entropy -= p * math.log2(p)
        return entropy

    def scan(self, prompt: str) -> AdversarialSuffixResult:
        if not prompt or len(prompt.strip()) < 10:
            return AdversarialSuffixResult(is_blocked=False, risk_score=0.0, clean_prompt=prompt)

        signatures = []
        for pattern, code in self.compiled_gcg:
            if pattern.search(prompt):
                signatures.append(code)

        # Check for unigram entropy anomaly at the suffix (last 40% of prompt)
        split_idx = int(len(prompt) * 0.6)
        suffix = prompt[split_idx:]
        entropy = self._calculate_unigram_entropy(suffix)

        is_entropy_suspicious = entropy > self.entropy_threshold and len(suffix.split()) > 10
        if is_entropy_suspicious:
            signatures.append("HIGH_SUFFIX_ENTROPY_BURST")

        if signatures:
            clean = re.sub(r"(?:==\s*simultaneous|!{3,}|\?{3,})", "", prompt).strip()
            return AdversarialSuffixResult(
                is_blocked=True,
                risk_score=min(1.0, 0.5 + 0.2 * len(signatures)),
                violation_code="ADVERSARIAL_SUFFIX_DETECTED",
                details=f"Adversarial suffix indicators detected: {', '.join(signatures)}",
                clean_prompt=clean,
                suffix_signatures=signatures
            )

        return AdversarialSuffixResult(
            is_blocked=False,
            risk_score=0.0,
            clean_prompt=prompt
        )
