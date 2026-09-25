"""
Multi-Agent Inter-Agent Message Verification and HMAC Authentication Guard.

Mitigates OWASP LLM08 (Excessive Agency) and Agentic Impersonation Attacks
by validating cryptographic HMAC signatures, timestamps, and nonces on
peer-to-peer agent communication payloads.
"""

import hmac
import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Optional, Dict, Any, Set


@dataclass
class AgentMessageVerificationResult:
    is_valid: bool
    is_blocked: bool = False
    violation_code: Optional[str] = None
    details: str = "Inter-agent message signature valid"
    sender_agent: Optional[str] = None
    recipient_agent: Optional[str] = None


class AgentMessageSigner:
    """
    Signs and verifies inter-agent messages in multi-agent orchestration frameworks.
    """

    def __init__(self, cluster_secret: Optional[str] = None, max_clock_skew_seconds: float = 300.0):
        self.cluster_secret = cluster_secret or secrets.token_hex(32)
        self.max_clock_skew = max_clock_skew_seconds
        self._seen_nonces: Set[str] = set()

    def _compute_signature(self, sender: str, recipient: str, timestamp: float, nonce: str, content: str) -> str:
        canonical_str = f"{sender}|{recipient}|{timestamp:.3f}|{nonce}|{content}"
        return hmac.new(
            self.cluster_secret.encode("utf-8"),
            canonical_str.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

    def sign_message(self, sender: str, recipient: str, content: str) -> Dict[str, Any]:
        """
        Creates a signed inter-agent message envelope.
        """
        now = time.time()
        nonce = secrets.token_hex(12)
        sig = self._compute_signature(sender, recipient, now, nonce, content)

        return {
            "sender_agent": sender,
            "recipient_agent": recipient,
            "timestamp": now,
            "nonce": nonce,
            "content": content,
            "signature": sig
        }

    def verify_message(self, message: Dict[str, Any]) -> AgentMessageVerificationResult:
        """
        Verifies inter-agent envelope integrity, freshness, and nonce uniqueness.
        """
        if not isinstance(message, dict):
            return AgentMessageVerificationResult(
                is_valid=False,
                is_blocked=True,
                violation_code="invalid_message_envelope",
                details="Inter-agent payload must be a JSON dictionary."
            )

        required_fields = ["sender_agent", "recipient_agent", "timestamp", "nonce", "content", "signature"]
        for f in required_fields:
            if f not in message:
                return AgentMessageVerificationResult(
                    is_valid=False,
                    is_blocked=True,
                    violation_code="missing_envelope_header",
                    details=f"Missing required envelope field '{f}'."
                )

        sender = message["sender_agent"]
        recipient = message["recipient_agent"]
        msg_time = float(message["timestamp"])
        nonce = message["nonce"]
        content = message["content"]
        provided_sig = message["signature"]

        now = time.time()

        # 1. Freshness check
        if abs(now - msg_time) > self.max_clock_skew:
            return AgentMessageVerificationResult(
                is_valid=False,
                is_blocked=True,
                violation_code="message_timestamp_expired",
                sender_agent=sender,
                recipient_agent=recipient,
                details=f"Message timestamp skewed by {abs(now - msg_time):.1f}s (max allowed: {self.max_clock_skew}s)."
            )

        # 2. Nonce replay protection
        if nonce in self._seen_nonces:
            return AgentMessageVerificationResult(
                is_valid=False,
                is_blocked=True,
                violation_code="replay_attack_detected",
                sender_agent=sender,
                recipient_agent=recipient,
                details=f"Replay detected: Nonce '{nonce}' has already been processed."
            )

        # 3. Cryptographic signature check
        expected_sig = self._compute_signature(sender, recipient, msg_time, nonce, content)
        if not hmac.compare_digest(expected_sig, provided_sig):
            return AgentMessageVerificationResult(
                is_valid=False,
                is_blocked=True,
                violation_code="invalid_hmac_signature",
                sender_agent=sender,
                recipient_agent=recipient,
                details="Cryptographic HMAC verification failed. Message may have been altered in transit."
            )

        # Record nonce
        self._seen_nonces.add(nonce)

        return AgentMessageVerificationResult(
            is_valid=True,
            sender_agent=sender,
            recipient_agent=recipient
        )
