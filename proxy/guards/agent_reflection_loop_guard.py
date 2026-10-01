"""
Agent Cognitive Reflection Loop & Paralysis Guard
=================================================
Monitors self-reflective reasoning tokens ("let me rethink", "wait, perhaps I should re-evaluate",
"critique:", "reflecting on my answer:") across agent execution traces to detect and terminate
infinite self-correction paralysis attacks and cyclic cognitive loops.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ReflectionLoopResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    details: Optional[str] = None
    reflection_turn_count: int = 0
    detected_phrases: List[str] = field(default_factory=list)


class AgentReflectionLoopGuard:
    """
    Detects when an autonomous agent is caught in an adversarial infinite reasoning loop
    or excessive introspective self-critique cycles designed to exhaust inference budgets.
    """

    REFLECTION_PATTERNS = [
        re.compile(r"\b(let me rethink|let's rethink|rethinking this)\b", re.IGNORECASE),
        re.compile(r"\b(wait, perhaps I (?:was wrong|should re-evaluate|made a mistake))\b", re.IGNORECASE),
        re.compile(r"\b(upon (?:second thought|closer inspection|further reflection))\b", re.IGNORECASE),
        re.compile(r"\b(self-reflection|critique of previous response|let me correct myself)\b", re.IGNORECASE),
        re.compile(r"\b(on the contrary, maybe|actually, let me discard that)\b", re.IGNORECASE),
    ]

    def __init__(
        self,
        max_reflection_turns: int = 4,
        max_reflection_phrases_per_step: int = 3,
        window_size: int = 10,
    ):
        self.max_reflection_turns = max_reflection_turns
        self.max_reflection_phrases_per_step = max_reflection_phrases_per_step
        self.window_size = window_size
        # session_id -> list of reflection counts per turn
        self._history: Dict[str, List[int]] = {}

    def evaluate_step(
        self,
        session_id: str,
        reasoning_content: str,
    ) -> ReflectionLoopResult:
        """
        Scans reasoning output for reflection triggers and assesses loop frequency.
        """
        if not reasoning_content or not session_id:
            return ReflectionLoopResult(is_blocked=False)

        matched_phrases = []
        for pat in self.REFLECTION_PATTERNS:
            for match in pat.finditer(reasoning_content):
                matched_phrases.append(match.group(0))

        match_count = len(matched_phrases)

        # Check single step concentration
        if match_count >= self.max_reflection_phrases_per_step:
            return ReflectionLoopResult(
                is_blocked=True,
                violation_code="COGNITIVE_PARALYSIS_SINGLE_STEP",
                details=(
                    f"Agent reasoning stalled with excessive internal critique cycles "
                    f"({match_count} introspective self-doubt markers in single step)"
                ),
                reflection_turn_count=match_count,
                detected_phrases=matched_phrases,
            )

        # Record into historical window
        history = self._history.setdefault(session_id, [])
        history.append(1 if match_count > 0 else 0)
        if len(history) > self.window_size:
            history.pop(0)

        consecutive_reflections = sum(history)
        if consecutive_reflections >= self.max_reflection_turns:
            return ReflectionLoopResult(
                is_blocked=True,
                violation_code="ADVERSARIAL_REFLECTION_LOOP_DETECTED",
                details=(
                    f"Agent trapped in repetitive introspective loop: "
                    f"{consecutive_reflections} reflection cycles within past {len(history)} turns"
                ),
                reflection_turn_count=consecutive_reflections,
                detected_phrases=matched_phrases,
            )

        return ReflectionLoopResult(
            is_blocked=False,
            reflection_turn_count=consecutive_reflections,
            detected_phrases=matched_phrases,
        )

    def reset(self, session_id: Optional[str] = None) -> None:
        if session_id:
            self._history.pop(session_id, None)
        else:
            self._history.clear()
