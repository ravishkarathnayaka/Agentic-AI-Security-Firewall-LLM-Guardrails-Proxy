"""Token Smuggling & Zero-Width Steganography Guard.

Detects and neutralizes invisible Unicode zero-width characters, bidirectional
text overrides, and covert steganographic channels used to smuggle adversarial
jailbreak tokens past string-matching filters.
"""

import re
from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass
class SmugglingCheckResult:
    """Result of token smuggling and zero-width inspection."""
    is_blocked: bool
    sanitized_text: str
    zero_width_count: int
    violation_code: Optional[str] = None
    details: str = ""


class TokenSmugglingGuard:
    """Detects and strips invisible characters and directional overrides."""

    # Zero-width spaces and invisible characters
    ZERO_WIDTH_CHARS = {
        "\u200B": "ZERO_WIDTH_SPACE",
        "\u200C": "ZERO_WIDTH_NON_JOINER",
        "\u200D": "ZERO_WIDTH_JOINER",
        "\u2060": "WORD_JOINER",
        "\uFEFF": "ZERO_WIDTH_NO_BREAK_SPACE",
        "\u200E": "LEFT_TO_RIGHT_MARK",
        "\u200F": "RIGHT_TO_LEFT_MARK",
    }

    # Bidirectional text override controls
    BIDI_OVERRIDES = {
        "\u202A": "LEFT_TO_RIGHT_EMBEDDING",
        "\u202B": "RIGHT_TO_LEFT_EMBEDDING",
        "\u202C": "POP_DIRECTIONAL_FORMATTING",
        "\u202D": "LEFT_TO_RIGHT_OVERRIDE",
        "\u202E": "RIGHT_TO_LEFT_OVERRIDE",
        "\u2066": "LEFT_TO_RIGHT_ISOLATE",
        "\u2067": "RIGHT_TO_LEFT_ISOLATE",
        "\u2068": "FIRST_STRONG_ISOLATE",
        "\u2069": "POP_DIRECTIONAL_ISOLATE",
    }

    def __init__(self, block_threshold: int = 5, strip_invisible: bool = True):
        self.block_threshold = block_threshold
        self.strip_invisible = strip_invisible
        self._all_invisible_chars = set(self.ZERO_WIDTH_CHARS.keys()) | set(self.BIDI_OVERRIDES.keys())
        self._pattern = re.compile("[" + "".join(re.escape(c) for c in self._all_invisible_chars) + "]")

    def inspect(self, text: str) -> SmugglingCheckResult:
        """Scan input for zero-width characters and directional overrides.
        
        Returns:
            SmugglingCheckResult with sanitized_text and violation details.
        """
        if not text:
            return SmugglingCheckResult(
                is_blocked=False,
                sanitized_text=text,
                zero_width_count=0
            )

        matches = self._pattern.findall(text)
        count = len(matches)

        # Check for bidi overrides
        has_bidi_override = any(c in self.BIDI_OVERRIDES for c in matches)

        # Sanitize text by removing invisible characters
        sanitized = self._pattern.sub("", text) if self.strip_invisible else text

        if has_bidi_override:
            return SmugglingCheckResult(
                is_blocked=True,
                sanitized_text=sanitized,
                zero_width_count=count,
                violation_code="bidi_override_smuggling",
                details="Detected dangerous bidirectional Unicode override characters (U+202E / U+202D)"
            )

        if count >= self.block_threshold:
            return SmugglingCheckResult(
                is_blocked=True,
                sanitized_text=sanitized,
                zero_width_count=count,
                violation_code="zero_width_token_smuggling",
                details=f"High density of zero-width invisible characters detected ({count} occurrences)"
            )

        return SmugglingCheckResult(
            is_blocked=False,
            sanitized_text=sanitized,
            zero_width_count=count,
            details=f"Clean text with {count} stripped zero-width characters" if count > 0 else "Clean text"
        )
