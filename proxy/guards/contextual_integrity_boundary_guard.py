"""
Contextual Integrity Boundary & Cross-Domain Leakage Guard
==========================================================
Enforces Helen Nissenbaum's Contextual Integrity framework across LLM data transfers.
Prevents confidential context norms (e.g. medical, financial, PII) from flowing
into public or unverified recipient contexts.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class ContextualIntegrityResult:
    is_blocked: bool
    risk_score: float = 0.0
    violation_code: Optional[str] = None
    details: Optional[str] = None
    norm_violations: List[str] = field(default_factory=list)


class ContextualIntegrityBoundaryGuard:
    """
    Validates that information transmission adheres to contextual role and privacy norms.
    """

    CONTEXT_SENSITIVITY = {
        "HEALTHCARE": [r"(?i)(?:diagnosis|patient\s+id|medical\s+record|prescription|biopsy|treatment)"],
        "FINANCIAL": [r"(?i)(?:credit\s+card|account\s+balance|ssn|iban|routing\s+number|tax\s+return)"],
        "CREDENTIALS": [r"(?i)(?:api_key|password|jwt_secret|private_key|auth_token)"],
    }

    RESTRICTED_RECIPIENTS = {
        "PUBLIC_WEB": ["EXTERNAL_SEARCH_API", "PUBLIC_LOG_SINK", "BROWSER_RENDER"],
        "THIRD_PARTY_TOOLS": ["UNVERIFIED_PLUGIN", "EXTERNAL_WEBHOOK"],
    }

    def __init__(self):
        self.compiled_contexts = {
            domain: [re.compile(p) for p in patterns]
            for domain, patterns in self.CONTEXT_SENSITIVITY.items()
        }

    def check_flow(self, sender_context: str, recipient_context: str, data_payload: str) -> ContextualIntegrityResult:
        if not data_payload:
            return ContextualIntegrityResult(is_blocked=False, risk_score=0.0)

        violations = []

        # Identify sensitive categories in payload
        detected_categories = set()
        for category, patterns in self.compiled_contexts.items():
            for p in patterns:
                if p.search(data_payload):
                    detected_categories.add(category)

        # Evaluate transmission appropriateness
        recipient_upper = recipient_context.upper()
        if "PUBLIC" in recipient_upper or "EXTERNAL" in recipient_upper or "WEBHOOK" in recipient_upper:
            for cat in detected_categories:
                violations.append(f"Transmission of sensitive {cat} data to untrusted recipient '{recipient_context}'")

        if violations:
            return ContextualIntegrityResult(
                is_blocked=True,
                risk_score=min(1.0, 0.5 + 0.25 * len(violations)),
                violation_code="CONTEXTUAL_INTEGRITY_BREACH",
                details="; ".join(violations),
                norm_violations=violations
            )

        return ContextualIntegrityResult(
            is_blocked=False,
            risk_score=0.0
        )
