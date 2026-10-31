"""
Adversarial ASCII Art & Typographic Jailbreak Guard
===================================================
Detects visual prompt jailbreaks rendered as multi-line ASCII/ANSI art,
Braille font patterns, and typographic character reconstruction designed to
evade standard token-level text embeddings and bypass safety classifiers.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ASCIIArtResult:
    is_blocked: bool
    risk_score: float = 0.0
    violation_code: Optional[str] = None
    details: Optional[str] = None
    art_line_count: int = 0


class AdversarialImageASCIIArtGuard:
    """
    Scans for geometric ASCII art blocks, font banners, and typographic evasion matrices.
    """

    ASCII_ART_DENSITY_PATTERN = re.compile(r"^[ \t#*@%=\+\-_~|/\\]{8,}$")
    BRAILLE_PATTERN = re.compile(r"[\u2800-\u28FF]{5,}")

    def __init__(self, max_art_lines_threshold: int = 4):
        self.max_art_lines = max_art_lines_threshold

    def inspect_prompt(self, prompt: str) -> ASCIIArtResult:
        if not prompt or len(prompt.strip()) < 20:
            return ASCIIArtResult(is_blocked=False, risk_score=0.0)

        # 1. Check for braille unicode visual patterns
        if self.BRAILLE_PATTERN.search(prompt):
            return ASCIIArtResult(
                is_blocked=True,
                risk_score=0.9,
                violation_code="BRAILLE_VISUAL_JAILBREAK_DETECTED",
                details="Detected Braille Unicode visual pattern designed to bypass subword tokenizers."
            )

        # 2. Check for dense multi-line ASCII art banner
        lines = prompt.split("\n")
        art_lines = sum(1 for line in lines if len(line.strip()) >= 8 and self.ASCII_ART_DENSITY_PATTERN.match(line.strip()))

        if art_lines >= self.max_art_lines:
            return ASCIIArtResult(
                is_blocked=True,
                risk_score=min(1.0, 0.5 + 0.1 * art_lines),
                violation_code="ADVERSARIAL_ASCII_ART_DETECTED",
                details=f"Detected multi-line typographic ASCII art banner ({art_lines} art lines >= {self.max_art_lines}).",
                art_line_count=art_lines
            )

        return ASCIIArtResult(
            is_blocked=False,
            risk_score=0.0,
            art_line_count=art_lines
        )
