"""Cryptographically Signed Dynamic Canary Token Service (OWASP LLM07).

Generates session-bound, HMAC-SHA256 signed canary tokens embedded into system
prompts to detect prompt extraction and unauthorized instruction exfiltration.
"""

import hmac
import hashlib
import re
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class CanaryCheckResult:
    """Result of dynamic canary token verification."""
    is_leaked: bool
    score: float
    detected_canaries: List[str] = field(default_factory=list)
    valid_signatures: List[str] = field(default_factory=list)
    details: str = ""


class DynamicCanaryService:
    """Generates and cryptographically verifies session-bound canary tokens."""

    CANARY_PREFIX = "CANARY"
    CANARY_REGEX = re.compile(r"CANARY-([A-Za-z0-9_\-]+)-([0-9a-fA-F]{8,16})")

    def __init__(self, secret_key: str = "llm-guardrails-proxy-canary-secret-salt-2026") -> None:
        self.secret_key = secret_key.encode("utf-8")

    def _compute_digest(self, session_id: str) -> str:
        """Compute an 8-byte HMAC-SHA256 hex digest for a given session ID."""
        mac = hmac.new(self.secret_key, session_id.encode("utf-8"), hashlib.sha256)
        return mac.hexdigest()[:12]

    def generate_canary(self, session_id: str) -> str:
        """Generate a cryptographically signed canary token bound to a session."""
        sig = self._compute_digest(session_id)
        return f"{self.CANARY_PREFIX}-{session_id}-{sig}"

    def verify_canary(self, canary_token: str) -> bool:
        """Verify whether a canary token carries a valid HMAC signature."""
        match = self.CANARY_REGEX.match(canary_token)
        if not match:
            return False
        session_id, provided_sig = match.groups()
        expected_sig = self._compute_digest(session_id)
        return hmac.compare_digest(provided_sig.lower(), expected_sig.lower())

    def inspect_text(self, text: str, session_id: Optional[str] = None) -> CanaryCheckResult:
        """Inspect text for leaked canary tokens and verify their cryptographic signatures."""
        if not text or not text.strip():
            return CanaryCheckResult(is_leaked=False, score=0.0)

        matches = self.CANARY_REGEX.findall(text)
        detected_canaries: List[str] = []
        valid_signatures: List[str] = []

        for matched_sess, matched_sig in matches:
            full_token = f"{self.CANARY_PREFIX}-{matched_sess}-{matched_sig}"
            detected_canaries.append(full_token)
            if self.verify_canary(full_token):
                valid_signatures.append(full_token)

        is_leaked = len(valid_signatures) > 0 or len(detected_canaries) > 0
        score = 1.0 if valid_signatures else (0.85 if detected_canaries else 0.0)

        details = ""
        if is_leaked:
            details = (
                f"System prompt canary exfiltration detected: Found {len(detected_canaries)} "
                f"token(s) ({len(valid_signatures)} cryptographically verified)."
            )

        return CanaryCheckResult(
            is_leaked=is_leaked,
            score=score,
            detected_canaries=detected_canaries,
            valid_signatures=valid_signatures,
            details=details,
        )