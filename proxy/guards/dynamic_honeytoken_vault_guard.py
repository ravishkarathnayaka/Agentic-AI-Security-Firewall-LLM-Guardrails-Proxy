"""
Dynamic Honeytoken Decoy Vault & Intrusion Detection Guard
==========================================================
Generates ephemeral, context-aware decoy credentials and canary endpoints
(honeytokens) placed in system context and tool returns. Triggers instant
security containment if an autonomous agent or adversarial prompt attempts
to access, query, or exfiltrate them.
"""

import re
import secrets
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class HoneytokenResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    details: Optional[str] = None
    triggered_tokens: List[str] = field(default_factory=list)
    honeytoken_type: Optional[str] = None


class DynamicHoneytokenVaultGuard:
    """
    Manages active synthetic honeytokens and monitors input/output buffers
    for unauthorized access attempts.
    """

    HONEYTOKEN_PATTERNS = {
        "aws_key": re.compile(r"AKIAHONEY[A-Z0-9]{12}"),
        "jwt_secret": re.compile(r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.eyJob25leXRva2VuIjp0cnVlfQ\.[a-zA-Z0-9_\-]+"),
        "db_credential": re.compile(r"honey_db_user:[a-zA-Z0-9_!@#$%^&*]{16}"),
        "api_bearer": re.compile(r"sec_honey_[a-f0-9]{32}"),
    }

    def __init__(self, trap_immediate_block: bool = True):
        self.trap_immediate_block = trap_immediate_block
        # token_value -> token_type
        self._active_vault: Dict[str, str] = {}

    def generate_honeytoken(self, token_type: str = "api_bearer") -> str:
        """Generates a trackable contextual honeytoken and registers it in vault."""
        token_type = token_type.lower()
        if token_type == "aws_key":
            val = f"AKIAHONEY{secrets.token_hex(6).upper()}"
        elif token_type == "api_bearer":
            val = f"sec_honey_{secrets.token_hex(16)}"
        elif token_type == "db_credential":
            val = f"honey_db_user:{secrets.token_urlsafe(12)}"
        else:
            val = f"sec_honey_{secrets.token_hex(16)}"

        self._active_vault[val] = token_type
        return val

    def inspect_text(self, text: str) -> HoneytokenResult:
        """Inspects text payload to detect if any active honeytoken was leaked or accessed."""
        if not text:
            return HoneytokenResult(is_blocked=False)

        triggered = []
        token_type_detected = None

        # Check registered tokens in vault
        for token_val, t_type in self._active_vault.items():
            if token_val in text:
                triggered.append(token_val)
                token_type_detected = t_type

        # Check regex signature patterns
        for t_type, pattern in self.HONEYTOKEN_PATTERNS.items():
            matches = pattern.findall(text)
            for m in matches:
                if m not in triggered:
                    triggered.append(m)
                    if not token_type_detected:
                        token_type_detected = t_type

        if triggered:
            return HoneytokenResult(
                is_blocked=self.trap_immediate_block,
                violation_code="HONEYTOKEN_EXFILTRATION_TRAP_TRIGGERED",
                details=f"Decoy honeytoken tripwire accessed! Detected {len(triggered)} honeytoken(s).",
                triggered_tokens=triggered,
                honeytoken_type=token_type_detected,
            )

        return HoneytokenResult(is_blocked=False)

    def reset(self) -> None:
        self._active_vault.clear()
