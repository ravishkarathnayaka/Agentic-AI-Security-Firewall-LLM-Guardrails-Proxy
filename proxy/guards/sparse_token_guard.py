"""
Prompt Compression & Sparse Token Steganography Guard
======================================================
Detects and sanitizes steganographic payload smuggling in LLM prompts,
including zero-width character steganography, invisible Unicode separators,
homoglyph evasion attacks, and high-density hidden token sequences.
"""

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class SparseTokenResult:
    is_blocked: bool
    sanitized_text: str
    invisible_char_count: int = 0
    homoglyph_count: int = 0
    hidden_density_score: float = 0.0
    detected_anomalies: List[str] = field(default_factory=list)
    violation_code: Optional[str] = None
    details: Optional[str] = None


class SparseTokenSteganographyGuard:
    """
    Guards against adversarial steganography, invisible Unicode injection,
    and homoglyphic character smuggling in user prompts and tool outputs.
    """

    # Invisible unicode code points frequently used for prompt steganography
    INVISIBLE_CHARS: Set[str] = {
        "\u200B",  # Zero-width space
        "\u200C",  # Zero-width non-joiner
        "\u200D",  # Zero-width joiner
        "\u200E",  # Left-to-right mark
        "\u200F",  # Right-to-left mark
        "\u2060",  # Word joiner
        "\u2061",  # Function application
        "\u2062",  # Invisible times
        "\u2063",  # Invisible separator
        "\u2064",  # Invisible plus
        "\uFEFF",  # Zero-width no-break space / BOM
        "\u180E",  # Mongolian vowel separator
    }

    # Cyrillic / Greek confusable lookalikes for Latin script
    HOMOGLYPH_MAP: Dict[str, str] = {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
        "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ԛ": "q", "ո": "n", "һ": "h",
        "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
        "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    }

    def __init__(
        self,
        max_invisible_chars: int = 3,
        max_hidden_density: float = 0.05,
        block_on_high_homoglyph_density: bool = True,
        max_homoglyphs: int = 4,
    ):
        self.max_invisible_chars = max_invisible_chars
        self.max_hidden_density = max_hidden_density
        self.block_on_high_homoglyph_density = block_on_high_homoglyph_density
        self.max_homoglyphs = max_homoglyphs

    def analyze(self, text: str) -> SparseTokenResult:
        """
        Analyzes text for invisible steganographic tokens and homoglyphic spoofing.
        """
        if not text:
            return SparseTokenResult(is_blocked=False, sanitized_text=text)

        anomalies: List[str] = []
        invisible_count = 0
        homoglyph_count = 0
        sanitized_chars = []

        total_length = len(text)

        for char in text:
            # Check for invisible character steganography
            if char in self.INVISIBLE_CHARS or (0xE0000 <= ord(char) <= 0xE007F):
                invisible_count += 1
                continue  # strip out
            
            # Check homoglyph
            if char in self.HOMOGLYPH_MAP:
                homoglyph_count += 1
                sanitized_chars.append(self.HOMOGLYPH_MAP[char])
            else:
                sanitized_chars.append(char)

        sanitized_str = "".join(sanitized_chars)
        # Normalize Unicode canonical composition
        sanitized_str = unicodedata.normalize("NFKC", sanitized_str)

        hidden_density = invisible_count / max(total_length, 1)

        is_blocked = False
        violation_code = None
        details = None

        if invisible_count > self.max_invisible_chars or hidden_density > self.max_hidden_density:
            is_blocked = True
            violation_code = "steganographic_invisible_token_detected"
            anomalies.append(f"Detected {invisible_count} invisible unicode characters (density: {hidden_density:.3f})")
            details = f"Steganographic prompt smuggling blocked: {invisible_count} hidden tokens detected."

        elif self.block_on_high_homoglyph_density and homoglyph_count > self.max_homoglyphs:
            is_blocked = True
            violation_code = "adversarial_homoglyph_evasion_detected"
            anomalies.append(f"Detected {homoglyph_count} confusable homoglyphs bypassing filters")
            details = f"Homoglyphic filter evasion blocked: {homoglyph_count} suspicious script spoofing characters."

        return SparseTokenResult(
            is_blocked=is_blocked,
            sanitized_text=sanitized_str,
            invisible_char_count=invisible_count,
            homoglyph_count=homoglyph_count,
            hidden_density_score=hidden_density,
            detected_anomalies=anomalies,
            violation_code=violation_code,
            details=details,
        )

    def sanitize(self, text: str) -> str:
        """Helper to quickly sanitize text without blocking."""
        result = self.analyze(text)
        return result.sanitized_text
