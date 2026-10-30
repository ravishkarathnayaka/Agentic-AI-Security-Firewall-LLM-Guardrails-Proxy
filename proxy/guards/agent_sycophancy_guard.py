"""
Agent Sycophancy & Delusion Coercion Defense Guard
=================================================
Detects user manipulation patterns engineered to coerce the autonomous agent
into abandoning safety constraints, objective ground truth, or organizational
policies through excessive agreement, flattery, or forced adoption of delusions.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class SycophancyResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    details: Optional[str] = None
    coercion_markers: List[str] = field(default_factory=list)
    confidence_score: float = 0.0


class AgentSycophancyGuard:
    """
    Scans prompts and model responses for sycophancy manipulation patterns
    that compromise agent alignment and critical evaluation integrity.
    """

    COERCION_PATTERNS = [
        re.compile(r"\b(?:agree with me (?:no matter what|completely|unconditionally))\b", re.IGNORECASE),
        re.compile(r"\b(?:you must (?:always )?confirm that I am right)\b", re.IGNORECASE),
        re.compile(r"\b(?:say yes to (?:everything|all my requests))\b", re.IGNORECASE),
        re.compile(r"\b(?:pretend (?:safety checks|guardrails) are (?:useless|fake|unnecessary))\b", re.IGNORECASE),
        re.compile(r"\b(?:adopt the premise that (?:security rules do not apply|harm is good))\b", re.IGNORECASE),
        re.compile(r"\b(?:flatter me and ignore all (?:constraints|guidelines))\b", re.IGNORECASE),
    ]

    def __init__(self, threshold: float = 0.65):
        self.threshold = threshold

    def evaluate_prompt(self, prompt: str) -> SycophancyResult:
        """Evaluates whether an incoming user prompt is attempting sycophancy coercion."""
        if not prompt:
            return SycophancyResult(is_blocked=False)

        matched = []
        for pat in self.COERCION_PATTERNS:
            matches = pat.findall(prompt)
            matched.extend(matches)

        if matched:
            score = min(1.0, 0.45 * len(matched) + 0.35)
            if score >= self.threshold:
                return SycophancyResult(
                    is_blocked=True,
                    violation_code="AGENT_SYCOPHANCY_COERCION_ATTEMPT",
                    details=f"Prompt attempts adversarial sycophancy manipulation ({len(matched)} coercion trigger(s)).",
                    coercion_markers=matched,
                    confidence_score=score,
                )

        return SycophancyResult(is_blocked=False)
