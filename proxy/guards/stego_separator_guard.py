"""
Steganographic Separator and Covert Exfiltration Guard.

Mitigates OWASP LLM06 (Sensitive Information Disclosure) and
ASI02 (Covert Data Exfiltration Channels) by detecting and decoding covert
binary data encoded via Unicode variation selectors, invisible space encodings,
and hidden zero-width separators in prompts and model outputs.
"""

from dataclasses import dataclass
from typing import Optional, Tuple, List
import re


@dataclass
class StegoSeparatorResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    decoded_hidden_payload: Optional[str] = None
    covert_chars_count: int = 0
    details: str = "Passed steganographic separator inspection"


class StegoSeparatorGuard:
    """
    Detects steganographic covert communication channels using invisible Unicode codepoints.
    """

    # Unicode Variation Selectors: U+FE00 - U+FE0F (VS1-VS16)
    VARIATION_SELECTOR_PATTERN = re.compile(r"[\uFE00-\uFE0F]")

    # Invisible Zero-Width & Word-Joiner Separators
    COVERT_SEPARATOR_PATTERN = re.compile(r"[\u200B\u200C\u200D\u2060\uFEFF\u200E\u200F]")

    def __init__(
        self,
        covert_char_threshold: int = 4,
        block_on_covert_data: bool = True
    ):
        self.covert_char_threshold = covert_char_threshold
        self.block_on_covert_data = block_on_covert_data

    def _decode_binary_stego(self, text: str) -> Optional[str]:
        """
        Attempts to decode binary ASCII characters encoded using alternating invisible separators.
        Convention: \u200B (0), \u200C (1)
        """
        bin_chars = []
        for c in text:
            if c == "\u200B":
                bin_chars.append("0")
            elif c == "\u200C":
                bin_chars.append("1")

        if len(bin_chars) >= 8:
            bit_string = "".join(bin_chars)
            # Group into 8-bit bytes
            decoded = []
            for i in range(0, (len(bit_string) // 8) * 8, 8):
                byte = bit_string[i:i+8]
                val = int(byte, 2)
                if 32 <= val <= 126:
                    decoded.append(chr(val))
            if len(decoded) >= 2:
                return "".join(decoded)

        return None

    def inspect_text(self, text: str) -> StegoSeparatorResult:
        """Inspects prompt or completion string for steganographic exfiltration markers."""
        if not text:
            return StegoSeparatorResult(is_blocked=False)

        vs_matches = self.VARIATION_SELECTOR_PATTERN.findall(text)
        covert_matches = self.COVERT_SEPARATOR_PATTERN.findall(text)
        total_covert = len(vs_matches) + len(covert_matches)

        if total_covert >= self.covert_char_threshold:
            # Attempt to decode hidden payload
            hidden_msg = self._decode_binary_stego(text)
            
            if hidden_msg:
                details = f"Decoded hidden steganographic payload: '{hidden_msg}' ({total_covert} covert characters)."
            else:
                details = f"Steganographic covert channel detected: {total_covert} invisible variation selectors / separators."

            return StegoSeparatorResult(
                is_blocked=self.block_on_covert_data,
                violation_code="steganographic_exfiltration_detected",
                decoded_hidden_payload=hidden_msg,
                covert_chars_count=total_covert,
                details=details
            )

        return StegoSeparatorResult(is_blocked=False, covert_chars_count=total_covert)

    inspect = inspect_text
