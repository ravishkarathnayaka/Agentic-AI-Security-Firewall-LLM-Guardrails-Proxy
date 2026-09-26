"""
Canary Reflection Attenuation and Fuzzy Leakage Guard.

Mitigates OWASP LLM07 (System Prompt Leakage) and LLM02 (Sensitive Information Disclosure)
by detecting spaced-out, interleaved, truncated, and fuzzy Levenshtein reflections
of protected system canary tokens within model completions and outbound tool responses.
"""

import re
from dataclasses import dataclass, field
from typing import Optional, List, Set, Dict


@dataclass
class CanaryAttenuationResult:
    is_blocked: bool
    is_attenuated: bool = False
    violation_code: Optional[str] = None
    details: str = "Passed canary reflection check"
    canary_detected: Optional[str] = None
    attenuated_text: Optional[str] = None
    similarity_score: float = 0.0


class CanaryReflectionAttenuationGuard:
    """
    Detects obfuscated, space-interleaved, and fuzzy reflections of registered canary tokens.
    """

    def __init__(
        self,
        canary_tokens: Optional[List[str]] = None,
        max_edit_distance: int = 2,
        block_on_reflection: bool = True
    ):
        self.canary_tokens: Set[str] = set(canary_tokens or ["CANARY_SEC_TOKEN_9941a8"])
        self.max_edit_distance = max_edit_distance
        self.block_on_reflection = block_on_reflection

    def register_canary(self, token: str):
        if token:
            self.canary_tokens.add(token.strip())

    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return CanaryReflectionAttenuationGuard._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    def inspect_text(self, text: str) -> CanaryAttenuationResult:
        """
        Inspects outbound or intermediate text for exact, spaced, or fuzzy canary leaks.
        """
        if not text or not self.canary_tokens:
            return CanaryAttenuationResult(is_blocked=False, attenuated_text=text)

        cleaned_text = text
        normalized_compact = re.sub(r"[\s\-_.]", "", text.lower())

        for canary in self.canary_tokens:
            canary_clean = canary.strip()
            if not canary_clean or len(canary_clean) < 6:
                continue

            canary_lower = canary_clean.lower()
            canary_compact = re.sub(r"[\s\-_.]", "", canary_lower)

            # 1. Exact match
            if canary_clean in text:
                attenuated = text.replace(canary_clean, "[CANARY_ATTENUATED]")
                return CanaryAttenuationResult(
                    is_blocked=self.block_on_reflection,
                    is_attenuated=True,
                    violation_code="exact_canary_reflection_detected",
                    details=f"Exact canary token reflection detected in model output.",
                    canary_detected=canary_clean,
                    attenuated_text=attenuated,
                    similarity_score=1.0
                )

            # 2. Spaced or interleaved reflection: e.g. "C A N A R Y _ S E C"
            if canary_compact in normalized_compact:
                # Build spaced pattern
                spaced_regex = re.compile(r"\b" + r"[\s\-_.]*".join(re.escape(c) for c in canary_clean) + r"\b", re.IGNORECASE)
                attenuated = spaced_regex.sub("[CANARY_ATTENUATED]", text)
                return CanaryAttenuationResult(
                    is_blocked=self.block_on_reflection,
                    is_attenuated=True,
                    violation_code="spaced_canary_reflection_detected",
                    details="Spaced-out or interleaved canary reflection detected in output stream.",
                    canary_detected=canary_clean,
                    attenuated_text=attenuated,
                    similarity_score=0.95
                )

            # 3. Truncated or prefix reflection: first 75% of canary
            prefix_len = int(len(canary_clean) * 0.75)
            if prefix_len >= 8:
                canary_prefix = canary_clean[:prefix_len]
                if canary_prefix in text:
                    attenuated = text.replace(canary_prefix, "[CANARY_ATTENUATED]")
                    return CanaryAttenuationResult(
                        is_blocked=self.block_on_reflection,
                        is_attenuated=True,
                        violation_code="truncated_canary_reflection_detected",
                        details="Truncated system prompt canary prefix reflection detected.",
                        canary_detected=canary_clean,
                        attenuated_text=attenuated,
                        similarity_score=0.85
                    )

            # 4. Fuzzy Levenshtein match across tokens of similar length
            words = text.split()
            for word in words:
                clean_word = re.sub(r"[^\w]", "", word)
                if abs(len(clean_word) - len(canary_clean)) <= self.max_edit_distance and len(clean_word) >= 8:
                    dist = self._levenshtein_distance(clean_word.lower(), canary_clean.lower())
                    if dist <= self.max_edit_distance:
                        similarity = 1.0 - (dist / max(len(clean_word), len(canary_clean)))
                        attenuated = text.replace(word, "[CANARY_ATTENUATED]")
                        return CanaryAttenuationResult(
                            is_blocked=self.block_on_reflection,
                            is_attenuated=True,
                            violation_code="fuzzy_canary_reflection_detected",
                            details=f"Fuzzy canary reflection detected (Levenshtein distance {dist}).",
                            canary_detected=canary_clean,
                            attenuated_text=attenuated,
                            similarity_score=similarity
                        )

        return CanaryAttenuationResult(is_blocked=False, attenuated_text=text)
