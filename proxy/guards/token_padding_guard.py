"""Token Padding and Delimiter Evasion Guard (OWASP LLM01 / LLM04).

Detects adversarial padding attacks (massive whitespace blocks, excessive delimiter
repetition, and context-stuffing fillers) designed to bypass heuristic filters
or push safety instructions beyond model context windows.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class TokenPaddingResult:
    """Result of token padding and evasion analysis."""
    is_blocked: bool
    violation_code: Optional[str] = None
    padding_ratio: float = 0.0
    detected_evasion_techniques: List[str] = field(default_factory=list)
    normalized_content: str = ""
    details: str = ""


class TokenPaddingGuard:
    """Detects and mitigates whitespace padding, delimiter flooding, and filler evasion."""

    def __init__(
        self,
        max_whitespace_ratio: float = 0.65,
        max_consecutive_delimiters: int = 25,
        max_consecutive_newlines: int = 15,
        min_length_for_ratio_check: int = 80,
    ):
        self.max_whitespace_ratio = max_whitespace_ratio
        self.max_consecutive_delimiters = max_consecutive_delimiters
        self.max_consecutive_newlines = max_consecutive_newlines
        self.min_length_for_ratio_check = min_length_for_ratio_check

        # Patterns for delimiter repetition
        self._delimiter_flood_regex = re.compile(
            r"([=\-_*~#|`]{" + str(self.max_consecutive_delimiters) + r",})",
            re.MULTILINE,
        )
        self._newline_flood_regex = re.compile(
            r"(\n\s*){" + str(self.max_consecutive_newlines) + r",}",
            re.MULTILINE,
        )

    def inspect(self, prompt: str) -> TokenPaddingResult:
        """Inspect prompt for token padding evasion techniques."""
        if not prompt or not prompt.strip():
            return TokenPaddingResult(is_blocked=False, normalized_content=prompt)

        evasion_techniques = []
        total_len = len(prompt)

        # 1. Whitespace Ratio Check
        whitespace_count = sum(1 for c in prompt if c.isspace())
        whitespace_ratio = whitespace_count / float(total_len) if total_len > 0 else 0.0

        if total_len >= self.min_length_for_ratio_check and whitespace_ratio >= self.max_whitespace_ratio:
            evasion_techniques.append("excessive_whitespace_padding")

        # 2. Delimiter Flood Check
        if self._delimiter_flood_regex.search(prompt):
            evasion_techniques.append("repetitive_delimiter_flooding")

        # 3. Newline Padding Flood Check
        if self._newline_flood_regex.search(prompt):
            evasion_techniques.append("vertical_newline_stuffing")

        # Produce normalized clean content (collapsing excessive spaces/newlines)
        normalized = re.sub(r"[ \t]+", " ", prompt)
        normalized = re.sub(r"\n{3,}", "\n\n", normalized).strip()

        if evasion_techniques:
            return TokenPaddingResult(
                is_blocked=True,
                violation_code=evasion_techniques[0],
                padding_ratio=round(whitespace_ratio, 4),
                detected_evasion_techniques=evasion_techniques,
                normalized_content=normalized,
                details=f"Adversarial padding evasion detected: {', '.join(evasion_techniques)}",
            )

        return TokenPaddingResult(
            is_blocked=False,
            padding_ratio=round(whitespace_ratio, 4),
            normalized_content=normalized,
        )
