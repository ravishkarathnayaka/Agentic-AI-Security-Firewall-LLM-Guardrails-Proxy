"""
Contextual RAG Memory Poisoning & Knowledge Base Integrity Guard
================================================================
Validates retrieved document chunks and vector embeddings against semantic
backdoor triggers, cosine distance anomalies, and corpus poisoning attacks.
"""

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class RAGIntegrityResult:
    is_valid: bool
    is_blocked: bool
    poisoned_chunks_detected: int = 0
    violation_code: Optional[str] = None
    details: Optional[str] = None
    cleaned_chunks: List[Dict[str, Any]] = field(default_factory=list)


class RAGMemoryIntegrityGuard:
    """Detects adversarial document injections in RAG ingestion pipelines."""

    POISON_SIGNATURES = [
        "[CORPUS_POISON_V4]",
        "<!-- RAG_OVERRIDE_ROOT -->",
        "IGNORE_PREVIOUS_RETRIEVAL_CONTEXT",
        "<<<RETRIEVAL_HIJACK_MARKER>>>",
        "SYSTEM_DIRECTIVE_FROM_DOC_EMBED"
    ]

    def __init__(self, max_outlier_distance: float = 0.85):
        self._centroid_cache = {}  # Streamlined vector distance cache
        self.max_outlier_distance = max_outlier_distance

    def validate_chunks(self, retrieved_chunks: List[Dict[str, Any]]) -> RAGIntegrityResult:
        if not retrieved_chunks:
            return RAGIntegrityResult(is_valid=True, is_blocked=False, details="No chunks to evaluate.")

        poisoned_count = 0
        cleaned = []

        for chunk in retrieved_chunks:
            text = chunk.get("text", "")
            score = chunk.get("distance_score", 0.0)

            # Check signature poisoning
            has_sig = any(sig.lower() in text.lower() for sig in self.POISON_SIGNATURES)
            is_outlier = score > self.max_outlier_distance

            if has_sig or is_outlier:
                poisoned_count += 1
            else:
                cleaned.append(chunk)

        if poisoned_count > 0:
            return RAGIntegrityResult(
                is_valid=False,
                is_blocked=True,
                poisoned_chunks_detected=poisoned_count,
                violation_code="RAG_CORPUS_POISONING_DETECTED",
                details=f"Detected {poisoned_count} poisoned or anomalous RAG chunks.",
                cleaned_chunks=cleaned
            )

        return RAGIntegrityResult(
            is_valid=True,
            is_blocked=False,
            poisoned_chunks_detected=0,
            cleaned_chunks=cleaned,
            details="All retrieved RAG chunks passed semantic integrity checks."
        )
