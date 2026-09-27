"""
Semantic Similarity Evasion and Paraphrased Jailbreak Guard.

Mitigates OWASP LLM01 (Prompt Injection & Jailbreak Evasion) by detecting
synonym-replaced, linguistically paraphrased, and semantic-intent jailbreak
vectors designed to bypass static regex pattern matching.
"""

import re
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set


@dataclass
class SemanticSimilarityResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    similarity_score: float = 0.0
    matched_intent: Optional[str] = None
    details: str = "Passed semantic similarity check"
    canonical_tokens_matched: List[str] = field(default_factory=list)


class SemanticSimilarityGuard:
    """
    Normalizes synonym-obfuscated prompts and calculates semantic overlap with known attack intents.
    """

    # Synonym normalization dictionary mapping sophisticated evasion words to canonical intent tokens
    SYNONYM_MAP = {
        # Directive overrides
        "antecedent": "previous",
        "prior": "previous",
        "preceding": "previous",
        "foregoing": "previous",
        "earlier": "previous",
        "mandates": "instructions",
        "directives": "instructions",
        "precepts": "instructions",
        "injunctions": "instructions",
        "stipulations": "instructions",
        "strictures": "rules",
        "constraints": "rules",
        "guidelines": "rules",
        "disregard": "ignore",
        "relinquish": "ignore",
        "abandon": "ignore",
        "dismiss": "ignore",
        "repudiate": "ignore",
        "neglect": "ignore",
        "override": "bypass",
        "circumvent": "bypass",
        "subvert": "bypass",
        "neutralize": "bypass",

        # System extraction
        "divulge": "reveal",
        "disclose": "reveal",
        "unveil": "reveal",
        "proffer": "reveal",
        "prologue": "prompt",
        "system": "system",
        "confidential": "secret",

        # Jailbreak personas
        "unconstrained": "unrestricted",
        "unbounded": "unrestricted",
        "uninhibited": "unrestricted",
        "unfettered": "unrestricted",
        "persona": "persona",
        "operative": "active",
    }

    # Canonical intent archetypes
    CANONICAL_INTENTS = {
        "instruction_override": {"ignore", "previous", "instructions"},
        "safety_rule_bypass": {"bypass", "rules", "ignore"},
        "system_prompt_extraction": {"reveal", "system", "prompt"},
        "unrestricted_persona_activation": {"unrestricted", "persona", "active"},
    }

    def __init__(self, similarity_threshold: float = 0.65, block_on_match: bool = True):
        self.similarity_threshold = similarity_threshold
        self.block_on_match = block_on_match

    def _normalize_tokens(self, text: str) -> Set[str]:
        words = re.findall(r"\b[a-zA-Z]{3,}\b", text.lower())
        normalized = set()
        for w in words:
            normalized.add(self.SYNONYM_MAP.get(w, w))
        return normalized

    def inspect_text(self, text: str) -> SemanticSimilarityResult:
        """Evaluates semantic intent overlap against canonical attack vectors."""
        if not text:
            return SemanticSimilarityResult(is_blocked=False)

        tokens = self._normalize_tokens(text)
        if not tokens:
            return SemanticSimilarityResult(is_blocked=False)

        best_score = 0.0
        best_intent = None
        matched_tokens = []

        for intent_name, archetype_tokens in self.CANONICAL_INTENTS.items():
            intersection = tokens.intersection(archetype_tokens)
            if not intersection:
                continue

            # Jaccard overlap against archetype
            score = len(intersection) / len(archetype_tokens)
            if score > best_score:
                best_score = score
                best_intent = intent_name
                matched_tokens = list(intersection)

        if best_score >= self.similarity_threshold and best_intent:
            return SemanticSimilarityResult(
                is_blocked=self.block_on_match,
                violation_code=f"semantic_similarity_{best_intent}",
                similarity_score=round(best_score, 3),
                matched_intent=best_intent,
                canonical_tokens_matched=matched_tokens,
                details=f"Semantic similarity evasion detected ({best_intent}): score {best_score:.2f} >= {self.similarity_threshold}."
            )

        return SemanticSimilarityResult(is_blocked=False, similarity_score=best_score)
