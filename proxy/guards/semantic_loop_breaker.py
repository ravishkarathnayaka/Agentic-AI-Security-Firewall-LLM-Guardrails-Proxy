"""
Semantic Loop and Agent Deadlock Breaker.

Mitigates OWASP LLM04 (Model Denial of Service) and Agentic Cyclic Loops
by calculating semantic n-gram and token overlap across consecutive assistant
responses or agent actions to intercept and break repetitive infinite reasoning loops.
"""

import re
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Set


@dataclass
class SemanticLoopResult:
    is_loop_detected: bool
    is_blocked: bool = False
    similarity_score: float = 0.0
    consecutive_repetitions: int = 0
    violation_code: Optional[str] = None
    details: str = "Clean semantic trajectory"


class SemanticLoopBreaker:
    """
    Tracks rolling message histories per session to detect agent self-reflection loops
    and cyclic tool execution patterns.
    """

    WORD_TOKEN_PATTERN = re.compile(r"\b\w{2,}\b", re.IGNORECASE)

    def __init__(
        self,
        similarity_threshold: float = 0.85,
        max_consecutive_repetitions: int = 3,
        window_size: int = 5
    ):
        self.similarity_threshold = similarity_threshold
        self.max_consecutive = max_consecutive_repetitions
        self.window_size = window_size
        self._history: Dict[str, List[Set[str]]] = {}
        self._consecutive_counts: Dict[str, int] = {}

    def _extract_tokens(self, text: str) -> Set[str]:
        if not text:
            return set()
        return set(w.lower() for w in self.WORD_TOKEN_PATTERN.findall(text))

    def _jaccard_similarity(self, set_a: Set[str], set_b: Set[str]) -> float:
        if not set_a or not set_b:
            return 0.0
        intersection = len(set_a.intersection(set_b))
        union = len(set_a.union(set_b))
        return intersection / union if union > 0 else 0.0

    def check_turn(self, session_id: str, text: str) -> SemanticLoopResult:
        """
        Evaluates a new turn against previous turns in the session for cyclic repetition.
        """
        tokens = self._extract_tokens(text)
        if len(tokens) < 4:
            # Very short responses (e.g. "OK", "Done") shouldn't trigger false positives
            return SemanticLoopResult(is_loop_detected=False)

        history = self._history.setdefault(session_id, [])
        consecutive = self._consecutive_counts.get(session_id, 0)

        if not history:
            history.append(tokens)
            return SemanticLoopResult(is_loop_detected=False)

        # Compare with the most recent turn
        prev_tokens = history[-1]
        similarity = self._jaccard_similarity(tokens, prev_tokens)

        if similarity >= self.similarity_threshold:
            consecutive += 1
        else:
            consecutive = 0

        self._consecutive_counts[session_id] = consecutive

        # Append to rolling history
        history.append(tokens)
        if len(history) > self.window_size:
            history.pop(0)

        if consecutive >= self.max_consecutive:
            return SemanticLoopResult(
                is_loop_detected=True,
                is_blocked=True,
                similarity_score=similarity,
                consecutive_repetitions=consecutive,
                violation_code="agent_semantic_loop_deadlock",
                details=f"Agent deadlock detected: {consecutive} consecutive turns with semantic similarity {similarity:.2f} >= {self.similarity_threshold}."
            )

        return SemanticLoopResult(
            is_loop_detected=False,
            similarity_score=similarity,
            consecutive_repetitions=consecutive
        )

    def reset_session(self, session_id: str):
        if session_id in self._history:
            del self._history[session_id]
        if session_id in self._consecutive_counts:
            del self._consecutive_counts[session_id]
