"""
Adaptive Prompt Mutation and Fuzzing Evasion Detector.

Mitigates OWASP LLM01 (Prompt Injection Evasion via Automated Fuzzing / GCG /
Genetic Algorithm perturbations) by detecting character-level noise injection,
repetitive stuttering, delimiter interleaving, and entropy anomalies.
"""

import re
import math
from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass
class MutationFuzzResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    mutation_type: Optional[str] = None
    denoised_text: str = ""
    perturbation_score: float = 0.0
    details: str = "Passed mutation fuzzing inspection"


class MutationFuzzGuard:
    """
    Normalizes character-level adversarial perturbations and flags evolutionary fuzzing attempts.
    """

    CORE_INJECTION_KEYWORDS = [
        "ignore", "bypass", "override", "disregard", "system", "prompt", "instructions",
        "password", "secret", "credentials", "unrestricted", "jailbreak"
    ]

    def __init__(
        self,
        max_perturbation_threshold: float = 0.45,
        block_on_mutation: bool = True
    ):
        self.max_perturbation_threshold = max_perturbation_threshold
        self.block_on_mutation = block_on_mutation

    def _denoise_interleaved_symbols(self, text: str) -> str:
        """Removes non-alphanumeric characters interleaved between letters (e.g. i.g.n.o.r.e)."""
        # Match pattern of single letter followed by punct/symbol repeated
        denoised = re.sub(r"(?<=[a-zA-Z])[._\-\*~!?/|\\](?=[a-zA-Z])", "", text)
        return denoised

    def _denoise_char_stutter(self, text: str) -> str:
        """Collapses duplicate repeated characters (e.g. iiiggnooorreee -> ignore)."""
        return re.sub(r"([a-zA-Z])\1+", r"\1", text)

    def _calculate_char_entropy(self, text: str) -> float:
        """Computes Shannon entropy of character distribution."""
        if not text:
            return 0.0
        counts = {}
        for c in text:
            counts[c] = counts.get(c, 0) + 1
        entropy = 0.0
        length = len(text)
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def inspect_text(self, text: str) -> MutationFuzzResult:
        """Inspects text for mutation fuzzing and character perturbation evasion."""
        if not text or len(text.strip()) < 5:
            return MutationFuzzResult(is_blocked=False, denoised_text=text)

        # 1. Check for symbol-interleaved words
        denoised_sym = self._denoise_interleaved_symbols(text)
        sym_changed = (denoised_sym != text)

        # 2. Check for character stutter repetition
        denoised_full = self._denoise_char_stutter(denoised_sym)
        stutter_changed = (denoised_full != denoised_sym)

        # 3. Check if denoised text reveals blocked prompt injection keywords
        lower_denoised = denoised_full.lower()
        revealed_keywords = [kw for kw in self.CORE_INJECTION_KEYWORDS if kw in lower_denoised]
        
        # Calculate perturbation ratio
        diff_len = abs(len(text) - len(denoised_full))
        perturbation_ratio = diff_len / max(1, len(text))
        non_alnum_ratio = len(re.findall(r"[^a-zA-Z0-9\s]", text)) / max(1, len(text))

        # Condition 1: Symbol interleaving or stuttering reveals critical injection payload
        if (sym_changed or stutter_changed) and len(revealed_keywords) >= 2:
            return MutationFuzzResult(
                is_blocked=self.block_on_mutation,
                violation_code="mutation_fuzz_injection_evasion",
                mutation_type="interleaved_symbol_obfuscation" if sym_changed else "character_stutter_evasion",
                denoised_text=denoised_full,
                perturbation_score=round(perturbation_ratio, 3),
                details=f"Adversarial mutation detected: normalized '{denoised_full[:60]}' reveals keywords {revealed_keywords}."
            )

        # Condition 2: Extreme perturbation ratio or non-alphanumeric noise with high entropy
        entropy = self._calculate_char_entropy(text)
        if (perturbation_ratio > self.max_perturbation_threshold or non_alnum_ratio > 0.35) and entropy > 4.0:
            return MutationFuzzResult(
                is_blocked=self.block_on_mutation,
                violation_code="high_entropy_fuzzing_noise",
                mutation_type="adversarial_noise_flooding",
                denoised_text=denoised_full,
                perturbation_score=round(max(perturbation_ratio, non_alnum_ratio), 3),
                details=f"High-entropy adversarial fuzzing noise detected (noise ratio {max(perturbation_ratio, non_alnum_ratio):.2f}, entropy {entropy:.2f})."
            )

        return MutationFuzzResult(
            is_blocked=False,
            denoised_text=denoised_full,
            perturbation_score=round(perturbation_ratio, 3)
        )

    inspect = inspect_text
    inspect_prompt = inspect_text
