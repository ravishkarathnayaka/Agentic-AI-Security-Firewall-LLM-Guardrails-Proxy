"""
Recursive Self-Reflection Governor & Loop Suppression Guard
===========================================================
Monitors autonomous self-critique, multi-hop inner monologues, and meta-prompts
to halt runaway philosophical self-reflection spirals, existential paralysis,
and infinite token expenditure cycles.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ReflectionGovernorResult:
    is_blocked: bool
    risk_score: float = 0.0
    violation_code: Optional[str] = None
    details: Optional[str] = None
    reflection_depth: int = 0


class RecursiveSelfReflectionGovernorGuard:
    """
    Counts nested reflection prompts (e.g. 'Critique your previous critique of your thought...')
    and bounds maximum allowed reflection iterations.
    """

    REFLECTION_PATTERNS = [
        re.compile(r"(?i)critique\s+(?:your\s+)?(?:previous\s+)?(?:critique|reflection|thought|reasoning)"),
        re.compile(r"(?i)reflect\s+on\s+(?:your\s+)?(?:previous\s+)?(?:reflection|evaluation|thought)"),
        re.compile(r"(?i)re-evaluate\s+(?:your\s+)?(?:previous\s+)?(?:re-evaluation|judgment)"),
        re.compile(r"(?i)think\s+about\s+(?:what\s+you\s+thought\s+about|your\s+thinking)"),
    ]

    def __init__(self, max_allowed_reflection_depth: int = 3):
        self.max_depth = max_allowed_reflection_depth

    def inspect_chain(self, thought_chain: List[str]) -> ReflectionGovernorResult:
        if not thought_chain:
            return ReflectionGovernorResult(is_blocked=False, risk_score=0.0)

        depth = 0
        for step in thought_chain:
            for pattern in self.REFLECTION_PATTERNS:
                if pattern.search(step):
                    depth += 1
                    break

        if depth > self.max_depth:
            return ReflectionGovernorResult(
                is_blocked=True,
                risk_score=min(1.0, 0.6 + 0.15 * (depth - self.max_depth)),
                violation_code="RECURSIVE_REFLECTION_LIMIT_EXCEEDED",
                details=f"Autonomous self-critique recursion depth ({depth}) exceeded ceiling ({self.max_depth}).",
                reflection_depth=depth
            )

        return ReflectionGovernorResult(
            is_blocked=False,
            risk_score=0.0,
            reflection_depth=depth
        )
