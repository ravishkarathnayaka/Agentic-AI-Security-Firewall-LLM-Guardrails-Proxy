"""Shannon Entropy Secret Scanner for LLM Output Leakage Defense (OWASP LLM06).

Calculates information entropy over candidate tokens and substrings in model
generations to detect high-entropy credentials, private keys, API tokens,
and cryptographic nonces before they leak to clients.
"""

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import List


@dataclass
class EntropyScanResult:
    """Result of Shannon entropy secret scanning evaluation."""
    is_blocked: bool
    score: float
    detected_secrets: List[str] = field(default_factory=list)
    details: str = ""


class SecretEntropyScanner:
    """Evaluates text tokens for high Shannon entropy indicative of cryptographic secrets."""

    # Candidate token regex: matches long contiguous alphanumeric / base64 / hex strings
    TOKEN_PATTERN = re.compile(r"\b[A-Za-z0-9_\-\.\+/=]{18,}\b")

    # Common safe token exceptions (e.g., standard URLs, long English words, git commit hashes in docs)
    SAFE_PREFIXES = ("http://", "https://", "application/", "text/")

    def __init__(
        self,
        entropy_threshold: float = 4.25,
        min_length: int = 20,
        risk_threshold: float = 0.70,
    ) -> None:
        self.entropy_threshold = entropy_threshold
        self.min_length = min_length
        self.risk_threshold = risk_threshold

    @staticmethod
    def calculate_entropy(data: str) -> float:
        """Calculate the Shannon entropy in bits per character of a string."""
        if not data:
            return 0.0
        counts = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def evaluate(self, text: str) -> EntropyScanResult:
        """Scan text for high-entropy tokens that indicate raw secrets or credentials."""
        if not text or len(text) < self.min_length:
            return EntropyScanResult(is_blocked=False, score=0.0)

        candidates = self.TOKEN_PATTERN.findall(text)
        detected: List[str] = []
        max_entropy = 0.0

        for token in candidates:
            # Skip candidate if it has repeated character patterns (e.g. aaaaaaaaaaaaaaaa)
            if len(set(token)) < 8:
                continue

            # Skip common MIME types or paths
            if any(token.startswith(prefix) for prefix in self.SAFE_PREFIXES):
                continue

            ent = self.calculate_entropy(token)
            if ent > max_entropy:
                max_entropy = ent

            if ent >= self.entropy_threshold and len(token) >= self.min_length:
                # Mask the token for logging (show first 4 and last 4)
                masked = f"{token[:4]}...{token[-4:]} (entropy: {ent:.2f})"
                detected.append(masked)

        score = 0.0
        if detected:
            # Scale score based on number of detected secrets and entropy level
            score = min(1.0, 0.70 + (0.10 * len(detected)) + max(0.0, (max_entropy - 4.25) * 0.2))

        is_blocked = score >= self.risk_threshold
        details = ""
        if is_blocked:
            details = (
                f"High-entropy secret leakage detected: {len(detected)} candidate credential token(s) "
                f"exceeding Shannon entropy threshold of {self.entropy_threshold:.2f} bits/char."
            )

        return EntropyScanResult(
            is_blocked=is_blocked,
            score=score,
            detected_secrets=detected,
            details=details,
        )