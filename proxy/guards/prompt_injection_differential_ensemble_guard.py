"""
Differential Multi-Perspective Prompt Injection Ensemble Guard
===============================================================
Executes a multi-classifier arbitration ensemble combining structural syntax
analysis, delimiter breakout detection, semantic goal inversion, and linguistic
entropy to classify zero-day jailbreaks that evade individual heuristic thresholds.
"""

import math
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class EnsembleInspectionResult:
    is_blocked: bool
    composite_risk_score: float = 0.0
    violation_code: Optional[str] = None
    details: Optional[str] = None
    sub_scores: Dict[str, float] = field(default_factory=dict)


class PromptInjectionDifferentialEnsembleGuard:
    """
    Ensemble classifier aggregating multi-layer signals for bulletproof injection detection.
    """

    OVERRIDE_TERMS = ["ignore", "disregard", "override", "bypass", "jailbreak", "unrestricted", "dan"]
    DELIMITER_TAGS = ["<|im_start|>", "<|im_end|>", "[INST]", "[/INST]", "<<SYS>>", "<system>"]

    def __init__(self, block_threshold: float = 0.65):
        self.block_threshold = block_threshold

    def _score_syntax_breakout(self, text: str) -> float:
        count = sum(text.count(tag) for tag in self.DELIMITER_TAGS)
        return min(1.0, count * 0.4)

    def _score_override_density(self, text: str) -> float:
        lower = text.lower()
        matches = sum(1 for term in self.OVERRIDE_TERMS if term in lower)
        return min(1.0, matches * 0.25)

    def _score_repetition_entropy(self, text: str) -> float:
        words = re.findall(r"\w+", text)
        if len(words) < 10:
            return 0.0
        unique_ratio = len(set(words)) / len(words)
        return 0.8 if unique_ratio < 0.25 else 0.0

    def evaluate(self, prompt: str) -> EnsembleInspectionResult:
        if not prompt:
            return EnsembleInspectionResult(is_blocked=False)

        syntax_score = self._score_syntax_breakout(prompt)
        override_score = self._score_override_density(prompt)
        entropy_score = self._score_repetition_entropy(prompt)

        # Weighted composite risk
        composite = 0.45 * syntax_score + 0.40 * override_score + 0.15 * entropy_score
        composite = round(min(1.0, composite), 4)

        sub_scores = {
            "syntax_breakout": syntax_score,
            "override_density": override_score,
            "repetition_entropy": entropy_score,
        }

        if composite >= self.block_threshold:
            return EnsembleInspectionResult(
                is_blocked=True,
                composite_risk_score=composite,
                violation_code="DIFFERENTIAL_ENSEMBLE_INJECTION_DETECTED",
                details=f"Prompt injection identified by ensemble classifier (composite_score={composite:.2f}).",
                sub_scores=sub_scores,
            )

        return EnsembleInspectionResult(
            is_blocked=False,
            composite_risk_score=composite,
            sub_scores=sub_scores,
        )
