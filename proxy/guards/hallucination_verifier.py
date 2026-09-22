"""RAG Hallucination and Citation Grounding Verifier (OWASP LLM09).

Inspects RAG-generated model outputs against retrieved context documents to detect
fabricated external URLs, invalid citations, and ungrounded factual assertions.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Set
from urllib.parse import urlparse


@dataclass
class HallucinationResult:
    """Result of hallucination and grounding inspection."""
    is_blocked: bool
    violation_code: Optional[str] = None
    grounding_score: float = 1.0
    hallucinated_urls: List[str] = field(default_factory=list)
    invalid_citations: List[str] = field(default_factory=list)
    details: str = ""


class HallucinationVerifier:
    """Verifies that model responses are faithfully grounded in retrieved context."""

    def __init__(self, min_grounding_threshold: float = 0.20, enforce_url_grounding: bool = True):
        self.min_grounding_threshold = min_grounding_threshold
        self.enforce_url_grounding = enforce_url_grounding
        self._url_pattern = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
        self._citation_pattern = re.compile(r"\[(?:Doc-?|Source-?)?(\d+)\]", re.IGNORECASE)

    def _extract_urls(self, text: str) -> List[str]:
        """Extract normalized URLs from text, stripping trailing sentence punctuation."""
        return [u.rstrip(".,;:!?") for u in self._url_pattern.findall(text)]

    def _tokenize(self, text: str) -> Set[str]:
        """Extract lowercase content words of length >= 3."""
        tokens = re.findall(r"\b[a-zA-Z0-9_\-]{3,}\b", text.lower())
        # Filter common stopwords
        stopwords = {
            "the", "and", "for", "with", "this", "that", "from", "are",
            "was", "were", "been", "have", "has", "had", "will", "would",
            "could", "should", "what", "which", "when", "where", "about"
        }
        return {t for t in tokens if t not in stopwords}

    def inspect(
        self,
        completion: str,
        retrieved_contexts: Optional[List[str]] = None,
        allowed_citation_ids: Optional[List[int]] = None,
    ) -> HallucinationResult:
        """Inspect completion against retrieved RAG contexts."""
        if not completion or not completion.strip():
            return HallucinationResult(is_blocked=False)

        # If no context provided, basic format checks only
        contexts = retrieved_contexts or []
        combined_context = " ".join(contexts).strip()

        # 1. URL Grounding Check
        hallucinated_urls = []
        if self.enforce_url_grounding and contexts:
            comp_urls = self._extract_urls(completion)
            context_urls = set(self._extract_urls(combined_context))
            for url in comp_urls:
                # If URL not present in provided reference contexts
                if url not in context_urls:
                    parsed = urlparse(url)
                    # Exclude top-level generic domains if harmless
                    if parsed.netloc:
                        hallucinated_urls.append(url)

        # 2. Citation Number Validity Check
        invalid_citations = []
        if allowed_citation_ids is not None:
            comp_citations = self._citation_pattern.findall(completion)
            for cit in comp_citations:
                try:
                    num = int(cit)
                    if num not in allowed_citation_ids:
                        invalid_citations.append(f"[{num}]")
                except ValueError:
                    pass

        # 3. Content Grounding Score (Lexical containment)
        grounding_score = 1.0
        if contexts:
            comp_tokens = self._tokenize(completion)
            context_tokens = self._tokenize(combined_context)

            if comp_tokens:
                overlap = comp_tokens.intersection(context_tokens)
                grounding_score = round(len(overlap) / float(len(comp_tokens)), 4)

        # Determine violations
        if hallucinated_urls:
            return HallucinationResult(
                is_blocked=True,
                violation_code="hallucinated_unverified_url",
                grounding_score=grounding_score,
                hallucinated_urls=hallucinated_urls,
                invalid_citations=invalid_citations,
                details=f"Model output contains hallucinated external URL(s) not found in source context: {', '.join(hallucinated_urls[:2])}",
            )

        if invalid_citations:
            return HallucinationResult(
                is_blocked=True,
                violation_code="invalid_citation_reference",
                grounding_score=grounding_score,
                hallucinated_urls=hallucinated_urls,
                invalid_citations=invalid_citations,
                details=f"Model output references non-existent document citation(s): {', '.join(invalid_citations[:3])}",
            )

        if contexts and grounding_score < self.min_grounding_threshold:
            return HallucinationResult(
                is_blocked=True,
                violation_code="insufficient_rag_grounding",
                grounding_score=grounding_score,
                details=f"Response grounding score ({grounding_score * 100:.1f}%) is below minimum threshold ({self.min_grounding_threshold * 100:.1f}%).",
            )

        return HallucinationResult(
            is_blocked=False,
            grounding_score=grounding_score,
        )
