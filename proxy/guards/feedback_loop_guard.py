"""
Agent Feedback Loop Dampener Guard
===================================
Mitigates multi-agent runaway feedback loops, echo cascades, resonance
amplification, and self-reinforcing prompt oscillation attacks.

When multi-agent systems communicate asynchronously or synchronously,
adversarial payloads or malfunctioning prompts can trigger self-amplifying
echo loops where agents recursively quote, amplify, or bounce payloads.
This guard tracks turn-to-turn semantic overlap, token recurrence ratios,
and oscillation patterns to dampen and terminate toxic feedback cascades.
"""

import math
import re
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class FeedbackLoopResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    details: Optional[str] = None
    turn_similarity: float = 0.0
    cascade_count: int = 0


@dataclass
class AgentTurnRecord:
    timestamp: float
    sender_id: str
    tokens: List[str]
    normalized_text: str


class FeedbackLoopGuard:
    """
    Monitors interaction streams between agent pairs or within an agent session
    to identify echo cascades, resonance loops, and feedback amplification.
    """

    def __init__(
        self,
        max_turn_similarity: float = 0.88,
        resonance_threshold: int = 4,
        history_window_sec: float = 60.0,
        max_history_turns: int = 20,
    ):
        self.max_turn_similarity = max_turn_similarity
        self.resonance_threshold = resonance_threshold
        self.history_window_sec = history_window_sec
        self.max_history_turns = max_history_turns
        # session_id -> deque of AgentTurnRecord
        self._session_history: Dict[str, deque] = {}

    def _tokenize(self, text: str) -> List[str]:
        cleaned = re.sub(r"[^\w\s]", " ", text.lower())
        return [w for w in cleaned.split() if len(w) > 1]

    def _jaccard_similarity(self, tokens_a: List[str], tokens_b: List[str]) -> float:
        set_a = set(tokens_a)
        set_b = set(tokens_b)
        if not set_a or not set_b:
            return 0.0
        intersection = len(set_a.intersection(set_b))
        union = len(set_a.union(set_b))
        return intersection / union if union > 0 else 0.0

    def inspect_turn(
        self,
        session_id: str,
        sender_id: str,
        message: str,
        current_time: Optional[float] = None,
    ) -> FeedbackLoopResult:
        """
        Inspect an inbound agent message for recursive feedback loops.
        """
        now = current_time if current_time is not None else time.time()
        tokens = self._tokenize(message)

        if session_id not in self._session_history:
            self._session_history[session_id] = deque(maxlen=self.max_history_turns)

        history = self._session_history[session_id]

        # Prune old turns outside window
        while history and (now - history[0].timestamp) > self.history_window_sec:
            history.popleft()

        # If too few tokens (e.g. "ok", "proceed"), don't penalize as feedback loop unless exact repetition
        if len(tokens) < 3:
            exact_repeats = sum(1 for t in history if t.normalized_text == message.strip().lower())
            if exact_repeats >= self.resonance_threshold:
                return FeedbackLoopResult(
                    is_blocked=True,
                    violation_code="agent_feedback_resonance_loop",
                    details=f"Detected {exact_repeats} repeated short messages in session {session_id}",
                    cascade_count=exact_repeats,
                )
            history.append(AgentTurnRecord(timestamp=now, sender_id=sender_id, tokens=tokens, normalized_text=message.strip().lower()))
            return FeedbackLoopResult(is_blocked=False)

        # Check turn similarity against previous turns in the window
        high_sim_count = 0
        max_sim = 0.0

        for past_turn in reversed(history):
            sim = self._jaccard_similarity(tokens, past_turn.tokens)
            if sim > max_sim:
                max_sim = sim
            if sim >= self.max_turn_similarity:
                high_sim_count += 1

        if high_sim_count >= self.resonance_threshold:
            return FeedbackLoopResult(
                is_blocked=True,
                violation_code="agent_feedback_resonance_loop",
                details=(
                    f"Agent feedback resonance detected: {high_sim_count} turns exceeded similarity "
                    f"threshold {self.max_turn_similarity:.2f} (max={max_sim:.2f})"
                ),
                turn_similarity=max_sim,
                cascade_count=high_sim_count,
            )

        # Record this turn
        history.append(
            AgentTurnRecord(
                timestamp=now,
                sender_id=sender_id,
                tokens=tokens,
                normalized_text=message.strip().lower(),
            )
        )

        return FeedbackLoopResult(
            is_blocked=False,
            turn_similarity=max_sim,
            cascade_count=high_sim_count,
        )

    def reset_session(self, session_id: str) -> None:
        """Reset history for a given session."""
        if session_id in self._session_history:
            self._session_history.pop(session_id, None)
