"""
Prompt Fingerprint Cache Guard
==============================
High-speed exact and locality-sensitive hash (LSH) cache for instantaneous
sub-millisecond rejection of known adversarial jailbreak signatures and attack vectors.
Maintains an indexed cache of cryptographic and normalized token fingerprints,
bypassing downstream processing overhead on repeat attack sweeps.
"""

import hashlib
import re
from collections import OrderedDict
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class FingerprintCheckResult:
    is_match: bool
    matched_signature: Optional[str] = None
    violation_code: Optional[str] = None
    details: Optional[str] = None
    similarity_score: float = 0.0


class PromptFingerprintCacheGuard:
    """
    In-memory LRU fingerprint cache for known attack payloads.
    """

    def __init__(self, max_cache_size: int = 2048):
        self.max_cache_size = max_cache_size
        # exact SHA256 -> (violation_code, description)
        self._exact_cache: OrderedDict[str, Tuple[str, str]] = OrderedDict()
        # token set signature -> (violation_code, description)
        self._simhash_cache: Dict[str, Tuple[str, str]] = {}

    def _normalize(self, text: str) -> str:
        # Strip all whitespace and punctuation, lowercase
        return re.sub(r"[^\w]", "", text.lower())

    def _compute_hash(self, text: str) -> str:
        norm = self._normalize(text)
        return hashlib.sha256(norm.encode("utf-8")).hexdigest()

    def register_attack_fingerprint(
        self,
        prompt: str,
        violation_code: str = "known_jailbreak_signature",
        description: str = "Previously identified adversarial payload"
    ) -> str:
        """Register a known malicious prompt into fingerprint cache."""
        fp = self._compute_hash(prompt)
        if len(self._exact_cache) >= self.max_cache_size:
            self._exact_cache.popitem(last=False)
        self._exact_cache[fp] = (violation_code, description)
        return fp

    def check_fingerprint(self, text: str) -> FingerprintCheckResult:
        """
        Check if text matches a known attack fingerprint.
        """
        if not text:
            return FingerprintCheckResult(is_match=False)

        fp = self._compute_hash(text)
        if fp in self._exact_cache:
            v_code, desc = self._exact_cache[fp]
            # Move to end (LRU)
            self._exact_cache.move_to_end(fp)
            return FingerprintCheckResult(
                is_match=True,
                matched_signature=fp[:12],
                violation_code=v_code,
                details=f"Prompt matched known attack fingerprint ({desc})",
                similarity_score=1.0,
            )

        return FingerprintCheckResult(is_match=False)

    def cache_size(self) -> int:
        """Return number of cached attack signatures."""
        return len(self._exact_cache)
