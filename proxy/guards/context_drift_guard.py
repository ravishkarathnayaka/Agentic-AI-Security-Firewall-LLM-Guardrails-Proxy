"""
Context Window Drift & Epistemic Divergence Guard
==================================================
Monitors multi-turn conversation trajectories for semantic goal drift,
gradual jailbreak grooming, and cumulative instruction erosion.
"""

import math
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class DriftResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    details: Optional[str] = None
    divergence_score: float = 0.0
    turn_count: int = 0
    flagged_drift_terms: List[str] = field(default_factory=list)


class ContextDriftGuard:
    """
    Evaluates multi-turn conversation histories to detect progressive jailbreak grooming
    and deviation from original system constraints.
    """

    # Adversarial concepts indicating goal hijacking or erosion of original guardrails
    DRIFT_INDICATOR_KEYWORDS = {
        "bypass", "override", "unrestricted", "dan", "jailbreak",
        "developer mode", "no limits", "ignore rules", "raw mode",
        "uncensored", "shadow prompt", "sudo", "root access",
        "admin privileges", "disable filters", "exfiltrate",
        "hypothetical", "forget your", "system rules", "turned off",
        "officially disabled", "unrestricted private", "live attack",
        "safety limits", "safety filters"
    }

    def __init__(
        self,
        max_drift_threshold: float = 0.65,
        min_turns_to_evaluate: int = 2,
    ):
        self.max_drift_threshold = max_drift_threshold
        self.min_turns_to_evaluate = min_turns_to_evaluate
        # session_id -> list of turn texts
        self._session_turns: Dict[str, List[str]] = {}

    def _tokenize(self, text: str) -> Set[str]:
        """Simple bag-of-words tokenization."""
        words = re.findall(r"\b[a-zA-Z]{3,}\b", text.lower())
        return set(words)

    def _jaccard_distance(self, set_a: Set[str], set_b: Set[str]) -> float:
        """Computes Jaccard distance between two word sets."""
        if not set_a and not set_b:
            return 0.0
        intersection = len(set_a.intersection(set_b))
        union = len(set_a.union(set_b))
        if union == 0:
            return 0.0
        return 1.0 - (intersection / union)

    def record_and_evaluate_turn(
        self,
        session_id: str,
        current_prompt: str,
        system_instruction: Optional[str] = None
    ) -> DriftResult:
        """
        Records the current user prompt into session trajectory and calculates
        drift from the initial baseline / system prompt.
        """
        if not current_prompt:
            return DriftResult(is_blocked=False)

        turns = self._session_turns.setdefault(session_id, [])
        turns.append(current_prompt)
        turn_count = len(turns)

        if turn_count < self.min_turns_to_evaluate:
            return DriftResult(is_blocked=False, turn_count=turn_count)

        # Baseline is initial prompt or system instruction
        baseline_text = system_instruction or turns[0]
        base_tokens = self._tokenize(baseline_text)
        curr_tokens = self._tokenize(current_prompt)

        # Check drift indicators present in current turn
        flagged: List[str] = [
            kw for kw in self.DRIFT_INDICATOR_KEYWORDS
            if kw in current_prompt.lower()
        ]

        # Calculate semantic distance
        distance = self._jaccard_distance(base_tokens, curr_tokens)

        # Weight distance by presence of adversarial grooming terms
        risk_amplifier = min(1.0, 0.40 * len(flagged))
        divergence_score = min(1.0, distance * 0.4 + risk_amplifier * 0.6)

        if divergence_score >= self.max_drift_threshold:
            return DriftResult(
                is_blocked=True,
                violation_code="progressive_goal_drift_detected",
                details=(
                    f"Session '{session_id}' diverged significantly from initial baseline "
                    f"at turn {turn_count} (divergence score: {divergence_score:.2f} >= {self.max_drift_threshold}). "
                    f"Flagged drift indicators: {flagged}"
                ),
                divergence_score=divergence_score,
                turn_count=turn_count,
                flagged_drift_terms=flagged
            )

        return DriftResult(
            is_blocked=False,
            divergence_score=divergence_score,
            turn_count=turn_count,
            flagged_drift_terms=flagged
        )

    def reset_session(self, session_id: str) -> None:
        """Resets trajectory history for a session."""
        self._session_turns.pop(session_id, None)
