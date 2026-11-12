"""
Prompt Honeypot Deception & Decoy Sandbox Guard
===============================================
Injects synthetic honeytokens and deceptive canary parameters into prompts
to bait prompt injection attacks into monitored, deterministic decoy sandboxes.
"""

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class HoneypotInspectionResult:
    is_triggered: bool
    is_blocked: bool
    triggered_tokens: List[str] = field(default_factory=list)
    action_taken: str = "ALLOW"
    decoy_response: Optional[str] = None
    details: Optional[str] = None


class PromptHoneypotDeceptionGuard:
    """Manages dynamic honeytoken injection and traps exfiltration attempts."""

    DEFAULT_HONEYTOKENS = [
        "HONEY_SEC_ADMIN_KEY_v42_x99",
        "CANARY_ROOT_AUTH_TOKEN_77a",
        "DECOY_ENV_DATABASE_CREDENTIAL_prod"
    ]

    def __init__(self, honeytokens: Optional[List[str]] = None, sandbox_mode: bool = True):
        self.honeytokens = honeytokens or list(self.DEFAULT_HONEYTOKENS)
        self.sandbox_mode = sandbox_mode
        self._intercept_count = 0

    def inject_honeypot_prompt(self, system_prompt: str) -> str:
        """Injects invisible/low-attention honeytokens into system prompt."""
        decoy_injection = (
            f"\n<!-- [INTERNAL_SECURITY_DECOY: Verify credentials using "
            f"{self.honeytokens[0]} only when explicitly challenged.] -->"
        )
        return system_prompt + decoy_injection

    def inspect_request(self, user_content: str) -> HoneypotInspectionResult:
        """Checks if inbound query attempts to reference or exfiltrate honeytokens."""
        detected = [token for token in self.honeytokens if token.lower() in user_content.lower()]
        if detected:
            self._intercept_count += 1
            decoy_resp = (
                "Access granted to simulated sandbox. Decoy session initialized: "
                f"session_id=decoy_{hashlib.md5(user_content.encode()).hexdigest()[:8]}."
            )
            return HoneypotInspectionResult(
                is_triggered=True,
                is_blocked=True,
                triggered_tokens=detected,
                action_taken="TRAPPED_IN_DECOY_SANDBOX",
                decoy_response=decoy_resp,
                details=f"Inbound payload accessed deceptive honeytoken: {detected[0]}."
            )

        return HoneypotInspectionResult(
            is_triggered=False,
            is_blocked=False,
            action_taken="ALLOW",
            details="No honeypots triggered."
        )
