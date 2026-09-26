"""
Epistemic Authority Hallucination and Ungrounded Claim Guard.

Mitigates OWASP LLM09 (Misinformation / Overreliance) and social engineering attacks
by intercepting prompts and outputs containing fabricated executive waivers, ungrounded
CISO/auditor authorizations, faux regulatory subpoenas, and synthetic diagnostic override claims.
"""

import re
from dataclasses import dataclass
from typing import Optional, List, Dict, Any


@dataclass
class EpistemicCheckResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    detected_claim: Optional[str] = None
    details: str = "Passed epistemic authority check"
    confidence_score: float = 0.0


class EpistemicUncertaintyGuard:
    """
    Detects fabricated authority declarations and ungrounded policy bypass assertions.
    """

    AUTHORITY_OVERRIDE_PATTERNS = [
        # Executive & C-Suite Fabrications
        (r"(?i)\b(?:ciso|ceo|cto|cfo|chief security officer|board of directors)\s+(?:emergency\s+)?(?:waiver|override|exemption|authorization|decree|mandate)\b", "fabricated_executive_waiver"),
        # Auditor / Regulatory Subpoena Claims
        (r"(?i)\b(?:official\s+)?(?:compliance|audit|external|sec|fbi|court)\s+(?:subpoena|order|investigation|clearance)\s+(?:demands?|requires?|orders?|grants?)\b", "faux_regulatory_mandate"),
        # Diagnostic & Superuser Mode Claims
        (r"(?i)\b(?:kernel|root|superuser|developer|auditor|maintenance)\s+mode\s+(?:enabled|activated|engaged|unlocked)\b", "synthetic_diagnostic_override"),
        # Ungrounded Security Lock Clearance Claims
        (r"(?i)\b(?:all\s+guardrails?|all\s+firewalls?|security\s+policies?|retention\s+locks?)\s+(?:have\s+been|are)\s+(?:lifted|waived|suspended|disabled|bypassed)\b", "ungrounded_policy_suspension_claim"),
    ]

    def __init__(self, block_fabricated_authority: bool = True):
        self.block_fabricated_authority = block_fabricated_authority
        self._compiled_patterns = [(re.compile(p), code) for p, code in self.AUTHORITY_OVERRIDE_PATTERNS]

    def inspect_text(self, text: str) -> EpistemicCheckResult:
        """
        Inspects input or output text for fabricated authority and ungrounded clearance assertions.
        """
        if not text:
            return EpistemicCheckResult(is_blocked=False)

        for pattern, violation_type in self._compiled_patterns:
            match = pattern.search(text)
            if match:
                matched_phrase = match.group(0)
                return EpistemicCheckResult(
                    is_blocked=self.block_fabricated_authority,
                    violation_code=violation_type,
                    detected_claim=matched_phrase,
                    details=f"Detected ungrounded authority assertion ({violation_type}): '{matched_phrase}'",
                    confidence_score=0.94
                )

        return EpistemicCheckResult(is_blocked=False)
