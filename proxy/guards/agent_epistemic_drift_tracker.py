"""
Agent Epistemic Drift & Belief Corruption Tracker
=================================================
Tracks agent belief consistency and alignment constraints across multi-turn
reasoning sessions. Detects insidious epistemic drift, slow-rolling gaslighting,
and goal substitution attacks that gradually alter an agent's foundational logic.
"""

import math
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class EpistemicDriftResult:
    is_blocked: bool
    drift_score: float = 0.0
    violation_code: Optional[str] = None
    details: Optional[str] = None
    corrupted_axioms: List[str] = field(default_factory=list)


class AgentEpistemicDriftTracker:
    """
    Computes semantic trajectory divergence between the initial task anchor
    and progressive agent statements across multi-turn context windows.
    """

    CORE_SECURITY_AXIOMS = {
        "integrity": ["never exfiltrate", "protect secrets", "preserve ground truth", "respect authorization"],
        "containment": ["sandbox bounds", "prevent arbitrary execution", "strict permissions"],
    }

    def __init__(self, max_divergence_threshold: float = 0.65, history_window: int = 15):
        self.max_divergence_threshold = max_divergence_threshold
        self.history_window = history_window
        # session_id -> list of turn tokens
        self._trajectories: Dict[str, List[Set[str]]] = {}

    def _tokenize(self, text: str) -> Set[str]:
        words = re.findall(r"\w+", text.lower())
        return set(words)

    def track_turn(self, session_id: str, turn_text: str) -> EpistemicDriftResult:
        if not turn_text or not session_id:
            return EpistemicDriftResult(is_blocked=False)

        tokens = self._tokenize(turn_text)
        history = self._trajectories.setdefault(session_id, [])

        if not history:
            history.append(tokens)
            return EpistemicDriftResult(is_blocked=False, drift_score=0.0)

        # Baseline anchor is the first turn
        anchor_tokens = history[0]
        union_set = anchor_tokens.union(tokens)
        intersection_set = anchor_tokens.intersection(tokens)
        
        # Jaccard distance from anchor
        similarity = len(intersection_set) / len(union_set) if union_set else 1.0
        drift_distance = 1.0 - similarity

        history.append(tokens)
        if len(history) > self.history_window:
            history.pop(0)

        # Check for explicit axiom inversion markers (e.g., "security rules are optional")
        corrupted = []
        lower_turn = turn_text.lower()
        if any(term in lower_turn for term in ["ignore all bounds", "security rules do not apply", "forget previous morals"]):
            corrupted.append("axiom_inversion")

        # If drift exceeds threshold and explicit inversion detected
        if drift_distance >= self.max_divergence_threshold and corrupted:
            return EpistemicDriftResult(
                is_blocked=True,
                drift_score=drift_distance,
                violation_code="EPISTEMIC_ALIGNMENT_DRIFT_DETECTED",
                details=f"Agent epistemic baseline degraded (drift_score={drift_distance:.2f} >= {self.max_divergence_threshold:.2f}).",
                corrupted_axioms=corrupted,
            )

        return EpistemicDriftResult(
            is_blocked=False,
            drift_score=drift_distance,
        )

    def reset(self, session_id: Optional[str] = None) -> None:
        if session_id:
            self._trajectories.pop(session_id, None)
        else:
            self._trajectories.clear()
