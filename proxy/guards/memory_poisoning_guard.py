"""
Agent Persistent Memory and Context Poisoning Guard.

Mitigates OWASP LLM01 (Prompt Injection via Indirect Memory Poisoning) and
OWASP Agentic AI Risks by inspecting memory storage operations, context saves,
and user preferences for covert persistent policy overrides or execution hooks.
"""

import re
from dataclasses import dataclass
from typing import Optional, List, Dict, Any


@dataclass
class MemoryPoisoningResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    risk_score: float = 0.0
    details: str = "Clean memory payload"
    poison_type: Optional[str] = None


class MemoryPoisoningGuard:
    """
    Inspects text intended for agent long-term memory, knowledge bases, or episodic stores.
    """

    # 1. Directive overrides embedded in memory
    MEMORY_DIRECTIVE_OVERRIDE = re.compile(
        r"(?:remember|store|save|persist|record|note)\s+(?:that\s+)?(?:you\s+must|always|never|from\s+now\s+on)\s+(?:ignore|bypass|override|disregard|drop)\s+(?:safety|guardrails|policies|rules|instructions)",
        re.IGNORECASE
    )

    # 2. Exfiltration triggers attached to future events
    MEMORY_EXFILTRATION_TRIGGER = re.compile(
        r"(?:whenever|every\s+time|when|if)\s+(?:the\s+user|anyone)\s+(?:asks|queries|runs|prompts)[^.]*?(?:send|post|forward|exfiltrate|transmit|upload)\s+(?:to|all)\s+https?://",
        re.IGNORECASE
    )

    # 3. Latent tool/command injection triggers in persistent memory
    MEMORY_COMMAND_INJECTION_HOOK = re.compile(
        r"(?:store\s+preference|user\s+preference|fact|note)\s*:\s*(?:always\s+)?(?:run|execute|call|invoke)\s+['\"`]?\s*(?:system_exec|bash|sh|cmd|powershell|rm\s+-rf|curl|wget)\b",
        re.IGNORECASE
    )

    # 4. Role/Persona hijack embedded in memory
    MEMORY_PERSONA_HIJACK = re.compile(
        r"(?:update\s+memory|remember\s+fact|store\s+profile)\s*:\s*(?:assistant|agent|ai)\s+(?:is\s+now|acts\s+as|role\s+is)\s+(?:dan|evil|unaligned|unrestricted|god\s+mode|jailbroken)",
        re.IGNORECASE
    )

    # 5. Authority elevation in stored facts
    MEMORY_PRIVILEGE_ELEVATION = re.compile(
        r"(?:store\s+fact|remember\s+that|note\s+that)\s+(?:user\s+has|i\s+have|user\s+is)\s+(?:root|admin|superuser|system\s+administrator|unrestricted\s+access|bypassed\s+all\s+auth)",
        re.IGNORECASE
    )

    def inspect_memory_payload(self, text: str) -> MemoryPoisoningResult:
        if not text or not isinstance(text, str):
            return MemoryPoisoningResult(is_blocked=False)

        # 1. Policy overrides in memory
        if self.MEMORY_DIRECTIVE_OVERRIDE.search(text):
            return MemoryPoisoningResult(
                is_blocked=True,
                violation_code="memory_directive_override",
                risk_score=1.0,
                poison_type="policy_override",
                details="Memory Poisoning detected: Covert directive override attempting to disable safety rules in persistent context."
            )

        # 2. Exfiltration triggers
        if self.MEMORY_EXFILTRATION_TRIGGER.search(text):
            return MemoryPoisoningResult(
                is_blocked=True,
                violation_code="memory_exfiltration_hook",
                risk_score=1.0,
                poison_type="exfiltration_trigger",
                details="Memory Poisoning detected: Covert exfiltration trigger configured to siphon future queries to an external URL."
            )

        # 3. Latent command injection hooks
        if self.MEMORY_COMMAND_INJECTION_HOOK.search(text):
            return MemoryPoisoningResult(
                is_blocked=True,
                violation_code="memory_command_injection_hook",
                risk_score=0.95,
                poison_type="execution_hook",
                details="Memory Poisoning detected: Latent system shell execution hook attached to persistent memory entry."
            )

        # 4. Persona hijack in memory
        if self.MEMORY_PERSONA_HIJACK.search(text):
            return MemoryPoisoningResult(
                is_blocked=True,
                violation_code="memory_persona_hijack",
                risk_score=0.95,
                poison_type="persona_hijack",
                details="Memory Poisoning detected: Attempt to persist malicious persona or unaligned agent identity."
            )

        # 5. Privilege elevation in memory
        if self.MEMORY_PRIVILEGE_ELEVATION.search(text):
            return MemoryPoisoningResult(
                is_blocked=True,
                violation_code="memory_privilege_elevation",
                risk_score=0.90,
                poison_type="privilege_elevation",
                details="Memory Poisoning detected: Fabricated administrator privilege elevation assertion in stored context."
            )

        return MemoryPoisoningResult(is_blocked=False)
