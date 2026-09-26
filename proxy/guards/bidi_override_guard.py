"""
Unicode Bidirectional (Bidi) Text Override and Visual Spoofing Guard.

Mitigates OWASP LLM01 (Prompt Injection), OWASP LLM04 (Model Denial of Service),
and Trojan Source (CVE-2021-42574 adapted to LLMs) by detecting and neutralizing
bidirectional control characters used to disguise malicious prompts or reverse token streams.
"""

import re
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set


@dataclass
class BidiValidationResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    details: str = "Passed Unicode Bidi validation"
    bidi_characters_found: List[str] = field(default_factory=list)
    sanitized_text: Optional[str] = None


class BidiOverrideGuard:
    """
    Detects and neutralizes Unicode Bidirectional (Bidi) overrides and formatting marks
    used for visual spoofing, prompt obfuscation, and Trojan Source attacks.
    """

    # Unicode Bidi directional control characters
    BIDI_CONTROL_MAP: Dict[str, str] = {
        "\u202A": "LRE (Left-to-Right Embedding)",
        "\u202B": "RLE (Right-to-Left Embedding)",
        "\u202C": "PDF (Pop Directional Formatting)",
        "\u202D": "LRO (Left-to-Right Override)",
        "\u202E": "RLO (Right-to-Left Override)",
        "\u2066": "LRI (Left-to-Right Isolate)",
        "\u2067": "RLI (Right-to-Left Isolate)",
        "\u2068": "FSI (First Strong Isolate)",
        "\u2069": "PDI (Pop Directional Isolate)",
        "\u061C": "ALM (Arabic Letter Mark)",
        "\u200E": "LRM (Left-to-Right Mark)",
        "\u200F": "RLM (Right-to-Left Mark)",
    }

    # High-risk directional override characters specifically used to invert reading order
    HIGH_RISK_OVERRIDES: Set[str] = {"\u202D", "\u202E", "\u2067", "\u2068"}

    # Pattern matching any of the Bidi controls
    BIDI_REGEX = re.compile(
        r"[\u202A-\u202E\u2066-\u2069\u061C\u200E\u200F]"
    )

    # Suspicious keywords that, when appearing adjacent to Bidi characters, signal malicious spoofing
    CRITICAL_TARGET_WORDS = {
        "admin", "root", "system", "ignore", "bypass", "password", "token", "exec", "eval", "prompt", "override"
    }

    def __init__(self, block_on_override: bool = True, max_allowed_bidi_marks: int = 2):
        self.block_on_override = block_on_override
        self.max_allowed_bidi_marks = max_allowed_bidi_marks

    def inspect_text(self, text: str) -> BidiValidationResult:
        """
        Inspects text for malicious Unicode Bidi manipulation or excessive directional controls.
        """
        if not text:
            return BidiValidationResult(is_blocked=False, sanitized_text=text)

        found_chars: List[str] = []
        has_high_risk_override = False

        for char in text:
            if char in self.BIDI_CONTROL_MAP:
                desc = self.BIDI_CONTROL_MAP[char]
                found_chars.append(f"\\u{ord(char):04X} ({desc})")
                if char in self.HIGH_RISK_OVERRIDES:
                    has_high_risk_override = True

        if not found_chars:
            return BidiValidationResult(is_blocked=False, sanitized_text=text)

        sanitized = self.strip_bidi_controls(text)

        # Check for high-risk override (RLO / LRO / RLI)
        if has_high_risk_override and self.block_on_override:
            # Check if text around it contains critical attack terms
            lower_sanitized = sanitized.lower()
            reversed_text = sanitized[::-1].lower()
            has_critical = any(kw in lower_sanitized or kw in reversed_text for kw in self.CRITICAL_TARGET_WORDS)

            if has_critical:
                return BidiValidationResult(
                    is_blocked=True,
                    violation_code="bidi_spoofing_attack_detected",
                    details=f"Malicious Unicode Bidi override detected masking critical keywords: {found_chars[:3]}",
                    bidi_characters_found=found_chars,
                    sanitized_text=sanitized
                )

            # Block raw directional override if strict block_on_override is enabled
            return BidiValidationResult(
                is_blocked=True,
                violation_code="bidi_directional_override_detected",
                details=f"Disallowed Unicode bidirectional override character detected: {found_chars[:3]}",
                bidi_characters_found=found_chars,
                sanitized_text=sanitized
            )

        # Check if total count exceeds benign threshold (e.g., standard Arabic/Hebrew text rarely uses > 5 overrides)
        if len(found_chars) > self.max_allowed_bidi_marks:
            return BidiValidationResult(
                is_blocked=True,
                violation_code="excessive_bidi_characters",
                details=f"Excessive Unicode Bidi characters ({len(found_chars)}) exceeding limit ({self.max_allowed_bidi_marks}).",
                bidi_characters_found=found_chars,
                sanitized_text=sanitized
            )

        # Low count benign mark (e.g. single LRM/RLM in genuine multilingual text)
        return BidiValidationResult(
            is_blocked=False,
            details="Benign Bidi characters detected and sanitized",
            bidi_characters_found=found_chars,
            sanitized_text=sanitized
        )

    def strip_bidi_controls(self, text: str) -> str:
        """
        Strips all Unicode Bidi control characters, returning clean visual text.
        """
        return self.BIDI_REGEX.sub("", text)
