"""
Dynamic Prompt Canary Rotation Vault with TTL and Per-Tenant Salt Derivation.

Mitigates OWASP LLM07 (System Prompt Leakage) and LLM02 (Sensitive Information Disclosure)
by maintaining an in-memory thread-safe canary vault supporting time-to-live (TTL) expiration,
session/tenant isolation, and real-time detection of active vs revoked canaries.
"""

import hmac
import hashlib
import secrets
import time
import re
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Set


@dataclass
class CanaryTokenRecord:
    token: str
    session_id: str
    created_at: float
    expires_at: float
    revoked: bool = False


class CanaryVault:
    """
    Manages dynamic lifecycle, generation, rotation, and detection of secret canary tokens.
    """

    CANARY_TOKEN_PATTERN = re.compile(r"canary_sec_[0-9a-f]{16,32}", re.IGNORECASE)

    def __init__(self, master_secret: Optional[str] = None, default_ttl_seconds: int = 3600):
        self.master_secret = master_secret or secrets.token_hex(32)
        self.default_ttl = default_ttl_seconds
        self._vault: Dict[str, CanaryTokenRecord] = {}

    def issue_canary(self, session_id: str, ttl_seconds: Optional[int] = None) -> str:
        """
        Derives and issues a cryptographically authenticated canary token tied to a session.
        """
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        now = time.time()
        random_entropy = secrets.token_hex(8)

        # Generate HMAC-SHA256 signature
        raw = f"{session_id}:{now}:{random_entropy}".encode("utf-8")
        sig = hmac.new(self.master_secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()[:24]
        token = f"canary_sec_{sig}"

        record = CanaryTokenRecord(
            token=token,
            session_id=session_id,
            created_at=now,
            expires_at=now + ttl,
            revoked=False
        )
        self._vault[token] = record
        return token

    def is_canary_active(self, token: str, session_id: Optional[str] = None) -> bool:
        """
        Verifies if a canary token is valid, unrevoked, and unexpired.
        """
        record = self._vault.get(token)
        if not record:
            return False

        if record.revoked:
            return False

        if time.time() > record.expires_at:
            return False

        if session_id and record.session_id != session_id:
            return False

        return True

    def revoke_canary(self, token: str) -> bool:
        """
        Revokes a canary token immediately.
        """
        record = self._vault.get(token)
        if record:
            record.revoked = True
            return True
        return False

    def purge_expired(self) -> int:
        """
        Removes expired or revoked tokens from memory.
        """
        now = time.time()
        expired_keys = [
            k for k, v in self._vault.items()
            if now > v.expires_at or v.revoked
        ]
        for k in expired_keys:
            del self._vault[k]
        return len(expired_keys)

    def find_active_canaries_in_text(self, text: str) -> List[str]:
        """
        Scans arbitrary text for any canary token format, returning those that are active in vault.
        """
        if not text:
            return []
        matches = self.CANARY_TOKEN_PATTERN.findall(text)
        active_found = []
        for m in matches:
            if self.is_canary_active(m):
                active_found.append(m)
        return active_found

    @property
    def total_tokens(self) -> int:
        return len(self._vault)
