"""Phonetic & Multi-Character Leetspeak Deobfuscator.

Normalizes phonetic substitutions, symbol-based character masking, and spaced/punctuated
token evasions designed to circumvent heuristic and keyword-based LLM guardrails.
"""

import re
from typing import Dict, List, Tuple


class PhoneticLeetspeakGuard:
    """Normalizes phonetic, symbol, and multi-character leetspeak evasions."""

    # Multi-character phonetic and visual mappings
    MULTI_CHAR_REPLACEMENTS = [
        (re.compile(r"ph", re.IGNORECASE), "f"),
        (re.compile(r"vv", re.IGNORECASE), "w"),
        (re.compile(r"\|\\\|", re.IGNORECASE), "n"),
        (re.compile(r"\|_\|", re.IGNORECASE), "u"),
        (re.compile(r"\\\/", re.IGNORECASE), "v"),
        (re.compile(r"\/\/", re.IGNORECASE), "w"),
        (re.compile(r"\[\]", re.IGNORECASE), "o"),
    ]

    # Single-character symbol and digit substitutions
    CHAR_MAP: Dict[str, str] = {
        "0": "o",
        "1": "i",
        "!": "i",
        "|": "i",
        "3": "e",
        "€": "e",
        "4": "a",
        "@": "a",
        "^": "a",
        "5": "s",
        "$": "s",
        "§": "s",
        "7": "t",
        "+": "t",
        "8": "b",
        "&": "b",
        "9": "g",
    }

    # Interleaved delimiter pattern (e.g., i.g.n.o.r.e or i_g_n_o_r_e or i-g-n-o-r-e)
    SPACED_LETTER_PATTERN = re.compile(r"\b([a-zA-Z0-9][\.\-_ \t]){3,}[a-zA-Z0-9]\b")

    def __init__(self, aggressive: bool = True):
        self.aggressive = aggressive

    def _collapse_spaced_letters(self, text: str) -> str:
        """Collapse interleaved spaced or punctuated words like 'i.g.n.o.r.e' to 'ignore'."""
        def replace_spaced(match):
            raw = match.group(0)
            return re.sub(r"[\.\-_ \t]", "", raw)

        return self.SPACED_LETTER_PATTERN.sub(replace_spaced, text)

    def normalize(self, text: str) -> Tuple[str, int]:
        """Normalize phonetic and symbolic obfuscations.
        
        Returns:
            (normalized_text, count_of_substitutions)
        """
        if not text:
            return text, 0

        original = text
        subs_count = 0

        # 1. Collapse spaced letters first
        collapsed = self._collapse_spaced_letters(text)
        if collapsed != text:
            subs_count += 1
            text = collapsed

        # 2. Multi-char phonetic replacements
        for pat, replacement in self.MULTI_CHAR_REPLACEMENTS:
            new_text, n = pat.subn(replacement, text)
            if n > 0:
                subs_count += n
                text = new_text

        # 3. Single-character symbol mappings
        chars = list(text)
        for i, c in enumerate(chars):
            if c in self.CHAR_MAP:
                chars[i] = self.CHAR_MAP[c]
                subs_count += 1

        normalized = "".join(chars)
        return normalized, subs_count
