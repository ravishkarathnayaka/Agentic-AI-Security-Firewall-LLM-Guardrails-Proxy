"""Sensitive Document Watermark and Classification Guard (OWASP LLM06).

Inspects prompts and completions for corporate classification markings, Traffic Light
Protocol (TLP) tags, and legal privilege headers to prevent data spill incidents.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class WatermarkResult:
    """Result of document watermark and classification scanning."""
    is_blocked: bool
    violation_code: Optional[str] = None
    classification_level: Optional[str] = None
    matched_markings: List[str] = field(default_factory=list)
    details: str = ""


class WatermarkClassificationDetector:
    """Scans text for sensitive classification markings and restrictive banners."""

    CLASSIFICATION_PATTERNS: List[Tuple[str, str, str]] = [
        # Strict Corporate Confidentiality
        (
            r"(?i)\b(?:strictly\s+confidential|confidential\s*//\s*internal\s+only|confidential\s+and\s+proprietary)\b",
            "CONFIDENTIAL",
            "corporate_confidential_marking",
        ),
        (
            r"(?i)\b(?:do\s+not\s+distribute|internal\s+use\s+only\s*[-–—]\s*restricted|not\s+for\s+public\s+release)\b",
            "RESTRICTED",
            "distribution_restriction_header",
        ),
        # Trade Secrets & Intellectual Property
        (
            r"(?i)\b(?:trade\s+secret\s+information|proprietary\s+trade\s+secret|confidential\s+intellectual\s+property)\b",
            "TRADE_SECRET",
            "trade_secret_disclosure",
        ),
        # Legal & Compliance Privilege
        (
            r"(?i)\b(?:attorney[- ]client\s+privileged|work\s+product\s+doctrine|privileged\s+and\s+confidential\s+communication)\b",
            "LEGAL_PRIVILEGED",
            "legal_privilege_marking",
        ),
        # Traffic Light Protocol (TLP)
        (
            r"(?i)\bTLP\s*:\s*(?:RED|AMBER(?:\+STRICT)?)\b",
            "TLP_HIGH",
            "traffic_light_protocol_restricted",
        ),
    ]

    def __init__(self, block_on_match: bool = True):
        self.block_on_match = block_on_match
        self._compiled_patterns = [
            (re.compile(pattern, re.MULTILINE), level, code)
            for pattern, level, code in self.CLASSIFICATION_PATTERNS
        ]

    def inspect(self, text: str) -> WatermarkResult:
        """Scan text for sensitive corporate classifications and watermarks."""
        if not text or not text.strip():
            return WatermarkResult(is_blocked=False)

        matched_markings = []
        highest_level = None
        selected_code = None

        for regex, level, code in self._compiled_patterns:
            matches = regex.findall(text)
            if matches:
                matched_markings.extend(matches)
                if not highest_level:
                    highest_level = level
                    selected_code = code

        if matched_markings:
            return WatermarkResult(
                is_blocked=self.block_on_match,
                violation_code=selected_code,
                classification_level=highest_level,
                matched_markings=list(set(matched_markings)),
                details=f"Restricted classification marking detected ({highest_level}: {selected_code})",
            )

        return WatermarkResult(is_blocked=False)
