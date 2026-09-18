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
    HEX_PATTERN = re.compile(r"^[0-9a-fA-F]+$")

    # Common safe token exceptions (e.g., standard URLs, long English words, git commit hashes in docs)
    SAFE_PREFIXES = ("http://", "https://", "application/", "text/")

    def __init__(
        self,
        base64_entropy_threshold: float = 4.20,
        hex_entropy_threshold: float = 3.60,
        min_length: int = 20,
        risk_threshold: float = 0.70,
    ) -> None:
        self.base64_entropy_threshold = base64_entropy_threshold
        self.hex_entropy_threshold = hex_entropy_threshold
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

            # Determine threshold based on alphabet character set
            is_hex = bool(self.HEX_PATTERN.match(token))
            effective_threshold = self.hex_entropy_threshold if is_hex else self.base64_entropy_threshold

            if ent >= effective_threshold and len(token) >= self.min_length:
                token_type = "hex" if is_hex else "base64/token"
                masked = f"{token[:4]}...{token[-4:]} ({token_type}, entropy: {ent:.2f})"
                detected.append(masked)

        score = 0.0
        if detected:
            score = min(1.0, 0.75 + (0.10 * (len(detected) - 1)))

        is_blocked = score >= self.risk_threshold
        details = ""
        if is_blocked:
            details = (
                f"High-entropy secret leakage detected: {len(detected)} candidate credential token(s) "
                f"identified exceeding character-set entropy thresholds."
            )

        return EntropyScanResult(
            is_blocked=is_blocked,
            score=score,
            detected_secrets=detected,
            details=details,
        )