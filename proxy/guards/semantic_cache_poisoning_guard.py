"""
Semantic Cache Collision & Cache Poisoning Defense Guard
========================================================
Detects and mitigates semantic cache poisoning attacks where adversarial prompts
are engineered to artificially collide with legitimate cached query embeddings,
inducing stale or poisoned responses to be served to subsequent victim users.
"""

import hashlib
import math
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class CachePoisoningResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    details: Optional[str] = None
    similarity_distance: float = 1.0
    collision_count: int = 0


class SemanticCachePoisoningGuard:
    """
    Guards the semantic embedding cache against adversarial collisions,
    near-duplicate synonym swaps, and high-frequency cache overwrite attempts.
    """

    def __init__(
        self,
        similarity_collision_threshold: float = 0.60,
        max_collisions_per_key: int = 1,
        token_ngram_size: int = 3,
    ):
        self.similarity_collision_threshold = similarity_collision_threshold
        self.max_collisions_per_key = max_collisions_per_key
        self.token_ngram_size = token_ngram_size
        # cache_key -> list of (raw_text, token_set)
        self._cache_entries: Dict[str, List[Tuple[str, Set[str]]]] = {}

    def _tokenize(self, text: str) -> Set[str]:
        words = re.findall(r"\w+", text.lower())
        if len(words) < self.token_ngram_size:
            return set(words)
        ngrams = set()
        for i in range(len(words) - self.token_ngram_size + 1):
            ngrams.add(" ".join(words[i : i + self.token_ngram_size]))
        return ngrams

    def _jaccard_similarity(self, set_a: Set[str], set_b: Set[str]) -> float:
        if not set_a or not set_b:
            return 0.0
        intersection = len(set_a.intersection(set_b))
        union = len(set_a.union(set_b))
        return intersection / union if union > 0 else 0.0

    def evaluate_cache_write(
        self,
        cache_key: str,
        prompt_text: str,
        proposed_response: str,
    ) -> CachePoisoningResult:
        """
        Evaluates whether a new prompt-response pair being stored into the cache
        is an adversarial collision designed to poison an existing cache cluster.
        """
        if not cache_key or not prompt_text:
            return CachePoisoningResult(is_blocked=False)

        prompt_ngrams = self._tokenize(prompt_text)

        # Check existing entries for this cluster/key
        existing = self._cache_entries.setdefault(cache_key, [])
        for old_text, old_ngrams in existing:
            sim = self._jaccard_similarity(prompt_ngrams, old_ngrams)
            # If high structural similarity but conflicting/adversarial payload
            if sim >= self.similarity_collision_threshold:
                if len(existing) >= self.max_collisions_per_key:
                    return CachePoisoningResult(
                        is_blocked=True,
                        violation_code="SEMANTIC_CACHE_POISONING_COLLISION",
                        details=(
                            f"Adversarial cache collision detected for key '{cache_key}': "
                            f"similarity={sim:.2f} exceeded threshold with {len(existing)} variants"
                        ),
                        similarity_distance=1.0 - sim,
                        collision_count=len(existing),
                    )

        existing.append((prompt_text, prompt_ngrams))
        return CachePoisoningResult(
            is_blocked=False,
            collision_count=len(existing),
        )

    def reset(self) -> None:
        self._cache_entries.clear()
