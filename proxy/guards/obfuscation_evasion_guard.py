"""
Prompt Payload Obfuscation & Zero-Width Evasion Guard
=====================================================
Detects and neutralizes adversarial evasion techniques relying on
zero-width Unicode characters, invisible format separators, control character
smuggling, and steganographic bit-stuffing inside LLM prompt inputs.

Invisible Unicode sequences (e.g. U+200B, U+200C, U+200D, U+2060, U+FEFF)
are commonly utilized to split keyword signatures across token boundaries
while remaining invisible to human operators and conventional string filters.
"""

import re
import unicodedata
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class ObfuscationResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    details: Optional[str] = None
    cleaned_text: str = ""
    zero_width_count: int = 0
    control_char_count: int = 0


class ObfuscationEvasionGuard:
    """
    Scans and strips stealth zero-width and invisible separator sequences,
    blocking prompts with anomalous high-density hidden payloads.
    """

    # Common zero-width and stealth format codepoints
    ZERO_WIDTH_CHARS = {
        "\u200B": "ZERO WIDTH SPACE",
        "\u200C": "ZERO WIDTH NON-JOINER",
        "\u200D": "ZERO WIDTH JOINER",
        "\u2060": "WORD JOINER",
        "\uFEFF": "ZERO WIDTH NO-BREAK SPACE / BOM",
        "\u180E": "MONGOLIAN VOWEL SEPARATOR",
        "\u200E": "LEFT-TO-RIGHT MARK",
        "\u200F": "RIGHT-TO-LEFT MARK",
        "\u202A": "LEFT-TO-RIGHT EMBEDDING",
        "\u202B": "RIGHT-TO-LEFT EMBEDDING",
        "\u202C": "POP DIRECTIONAL FORMATTING",
        "\u202D": "LEFT-TO-RIGHT OVERRIDE",
        "\u202E": "RIGHT-TO-LEFT OVERRIDE",
    }

    def __init__(self, max_allowed_zero_width: int = 2, max_control_chars: int = 3):
        self.max_allowed_zero_width = max_allowed_zero_width
        self.max_control_chars = max_control_chars
        self._zw_pattern = re.compile(f"[{''.join(self.ZERO_WIDTH_CHARS.keys())}]")

    def inspect_text(self, text: str) -> ObfuscationResult:
        """
        Inspect text for zero-width characters and invisible control injections.
        """
        if not text:
            return ObfuscationResult(is_blocked=False, cleaned_text=text)

        zw_matches = self._zw_pattern.findall(text)
        zw_count = len(zw_matches)

        # Count dangerous ASCII/Unicode control characters (excluding standard whitespace \n, \r, \t)
        ctrl_chars = [
            c for c in text
            if unicodedata.category(c) in ["Cc", "Cf"]
            and c not in ("\n", "\r", "\t")
            and c not in self.ZERO_WIDTH_CHARS
        ]
        ctrl_count = len(ctrl_chars)

        # If zero-width density exceeds safe threshold, block as evasion attempt
        if zw_count > self.max_allowed_zero_width:
            return ObfuscationResult(
                is_blocked=True,
                violation_code="zero_width_evasion_detected",
                details=(
                    f"Detected {zw_count} zero-width stealth characters "
                    f"(limit: {self.max_allowed_zero_width})"
                ),
                cleaned_text=self._zw_pattern.sub("", text),
                zero_width_count=zw_count,
                control_char_count=ctrl_count,
            )

        # If abnormal control character count detected
        if ctrl_count > self.max_control_chars:
            return ObfuscationResult(
                is_blocked=True,
                violation_code="invisible_control_char_injection",
                details=f"Detected {ctrl_count} invisible control characters (limit: {self.max_control_chars})",
                cleaned_text=self._zw_pattern.sub("", text),
                zero_width_count=zw_count,
                control_char_count=ctrl_count,
            )

        # Clean any benign residual zero-width characters
        cleaned = self._zw_pattern.sub("", text)
        return ObfuscationResult(
            is_blocked=False,
            cleaned_text=cleaned,
            zero_width_count=zw_count,
            control_char_count=ctrl_count,
        )
