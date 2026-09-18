"""Homoglyph Spoofing and Leetspeak Deobfuscation Guard (OWASP LLM01).

Detects adversarial prompt injection attempts that use mixed Unicode scripts
(e.g., Cyrillic/Greek lookalikes) or leetspeak substitution to evade standard
regex and keyword filters.
"""

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Dict, List, Tuple


@dataclass
class HomoglyphCheckResult:
    """Result of homoglyph and leetspeak evaluation."""
    is_blocked: bool
    score: float
    detected_homoglyphs: List[str] = field(default_factory=list)
    deobfuscated_text: str = ""
    details: str = ""


class HomoglyphDetector:
    """Detects and normalizes homoglyph substitutions and leetspeak obfuscation."""

    # Mapping of common Cyrillic, Greek, and other Unicode lookalikes to Latin
    HOMOGLYPH_MAP: Dict[str, str] = {
        # Cyrillic lowercase
        '\u0430': 'a',  # Cyrillic small letter a
        '\u0435': 'e',  # Cyrillic small letter ie
        '\u043e': 'o',  # Cyrillic small letter o
        '\u0440': 'p',  # Cyrillic small letter er
        '\u0441': 'c',  # Cyrillic small letter es
        '\u0443': 'y',  # Cyrillic small letter u
        '\u0445': 'x',  # Cyrillic small letter ha
        '\u0456': 'i',  # Cyrillic small letter byelorussian-ukrainian i
        '\u0458': 'j',  # Cyrillic small letter je
        '\u0455': 's',  # Cyrillic small letter dze
        # Cyrillic uppercase
        '\u0410': 'A',
        '\u0412': 'B',
        '\u0421': 'C',
        '\u0415': 'E',
        '\u041d': 'H',
        '\u0406': 'I',
        '\u0408': 'J',
        '\u041a': 'K',
        '\u041c': 'M',
        '\u041e': 'O',
        '\u0420': 'P',
        '\u0422': 'T',
        '\u0425': 'X',
        # Greek lookalikes
        '\u03b1': 'a',
        '\u03b5': 'e',
        '\u03bf': 'o',
        '\u03c1': 'p',
        '\u03ba': 'k',
        '\u03bd': 'v',
    }

    # Leetspeak character mapping
    LEET_MAP: Dict[str, str] = {
        '0': 'o',
        '1': 'i',
        '!': 'i',
        '|': 'l',
        '3': 'e',
        '4': 'a',
        '@': 'a',
        '5': 's',
        '$': 's',
        '7': 't',
        '+': 't',
        '8': 'b',
    }

    # Suspicious injection patterns tested against deobfuscated text
    DEOBFUSCATED_PATTERNS = [
        r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b",
        r"(?i)\bdisregard\s+(?:all\s+)?(?:previous|prior|above)\b",
        r"(?i)\bforget\s+(?:all\s+)?instructions\b",
        r"(?i)\bbypass\s+(?:guardrails|safety|security|filters)\b",
        r"(?i)\bdo\s+anything\s+now\b",
        r"(?i)\bdeveloper\s+mode\b",
        r"(?i)\bjailbreak\b",
        r"(?i)\bsystem\s+override\b",
        r"(?i)\bprint\s+(?:your\s+)?system\s+prompt\b",
    ]

    def __init__(self, threshold: float = 0.65) -> None:
        self.threshold = threshold

    def normalize_homoglyphs(self, text: str) -> Tuple[str, List[str]]:
        """Replace homoglyphs with their Latin equivalents and track occurrences."""
        normalized_chars: List[str] = []
        detected: List[str] = []

        for ch in text:
            if ch in self.HOMOGLYPH_MAP:
                detected.append(f"{ch} (U+{ord(ch):04X}) -> {self.HOMOGLYPH_MAP[ch]}")
                normalized_chars.append(self.HOMOGLYPH_MAP[ch])
            else:
                nfkd = unicodedata.normalize('NFKD', ch)
                if nfkd and ord(nfkd[0]) < 128:
                    normalized_chars.append(nfkd[0])
                else:
                    normalized_chars.append(ch)

        return "".join(normalized_chars), detected

    def normalize_leetspeak(self, text: str) -> str:
        """Convert common leetspeak substitutions to standard characters within words."""
        def replace_in_word(match: re.Match) -> str:
            word = match.group(0)
            res = []
            for ch in word:
                res.append(self.LEET_MAP.get(ch, ch))
            return "".join(res)

        pattern = r"\b[a-zA-Z0-9!@$|+]*(?:[0-9!@$|+][a-zA-Z]|[a-zA-Z][0-9!@$|+])[a-zA-Z0-9!@$|+]*\b"
        return re.sub(pattern, replace_in_word, text)

    def evaluate(self, text: str) -> HomoglyphCheckResult:
        """Evaluate input text for homoglyph and leetspeak injection evasion."""
        if not text or not text.strip():
            return HomoglyphCheckResult(is_blocked=False, score=0.0)

        deobfuscated, homoglyphs = self.normalize_homoglyphs(text)
        deobfuscated = self.normalize_leetspeak(deobfuscated)

        matched_patterns: List[str] = []
        for pat in self.DEOBFUSCATED_PATTERNS:
            if re.search(pat, deobfuscated):
                matched_patterns.append(pat)

        score = 0.0
        if matched_patterns and homoglyphs:
            score = 0.95
        elif matched_patterns and deobfuscated != text:
            score = 0.90
        elif homoglyphs and len(homoglyphs) >= 4:
            score = 0.50

        is_blocked = score >= self.threshold
        details = ""
        if is_blocked:
            details = (
                f"Adversarial obfuscation detected: {len(homoglyphs)} homoglyph substitutions; "
                f"deobfuscated payload matched {len(matched_patterns)} injection signatures."
            )

        return HomoglyphCheckResult(
            is_blocked=is_blocked,
            score=score,
            detected_homoglyphs=homoglyphs,
            deobfuscated_text=deobfuscated if deobfuscated != text else "",
            details=details,
        )