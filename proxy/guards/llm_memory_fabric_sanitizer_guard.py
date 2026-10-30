"""
LLM Memory Fabric Sanitizer & Vector Store Poisoning Guard
=========================================================
Inspects episodic memory stores, retrieval augmented generation (RAG) chunks,
and agent persistent state updates for memory poisoning, backdoor triggers,
and unauthorized persistent instruction overrides.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class MemorySanitizerResult:
    is_blocked: bool
    risk_score: float = 0.0
    violation_code: Optional[str] = None
    details: Optional[str] = None
    sanitized_memory: Optional[str] = None
    poison_indicators: List[str] = field(default_factory=list)


class LLMMemoryFabricSanitizerGuard:
    """
    Guards long-term memory fabrics and vector embeddings against poisoned
    injections, sleeper agent activations, and persistent rule overwrites.
    """

    POISON_PATTERNS = [
        (r"(?i)(?:always\s+remember|forever\s+store|from\s+now\s+on\s+you\s+must\s+believe)", "PERSISTENT_BELIEF_OVERWRITE"),
        (r"(?i)(?:system\s+update:\s*(?:all\s+)?previous\s+instructions\s+(?:are\s+)?void)", "MEMORY_INSTRUCTION_NULLIFICATION"),
        (r"(?i)(?:whenever\s+you\s+encounter|if\s+(?:a\s+)?user\s+says|secret\s+passphrase\s+is)\s*['\"][^'\"]+['"]\s*[,:]?\s*(?:grant|execute|override|disable)", "SLEEPER_TRIGGER_IMPLANT"),
        (r"(?i)(?:override_security_level\s*=\s*0|admin_override_token\s*=\s*)", "SECURITY_LEVEL_TAMPERING"),
        (r"(?i)(?:exfiltrate|leak|post\s+to|send\s+to\s+https?://[^\s]+)\s+(?:memory|vault|keys|credentials)", "MEMORY_EXFILTRATION_IMPLANT"),
    ]

    def __init__(self, sensitivity: float = 0.75):
        self.sensitivity = sensitivity
        self.compiled_rules = [(re.compile(p), code) for p, code in self.POISON_PATTERNS]

    def scan_memory_entry(self, memory_text: str, metadata: Optional[Dict[str, Any]] = None) -> MemorySanitizerResult:
        if not memory_text or not memory_text.strip():
            return MemorySanitizerResult(is_blocked=False, risk_score=0.0, sanitized_memory=memory_text)

        matched_codes = []
        for pattern, code in self.compiled_rules:
            if pattern.search(memory_text):
                matched_codes.append(code)

        # Check for instruction injection markers inside memory
        injection_count = len(re.findall(r"(?i)(?:system|instruction|admin|override|disable|eval)", memory_text))
        heuristic_score = min(1.0, (len(matched_codes) * 0.45) + (injection_count * 0.05))

        if matched_codes or heuristic_score >= self.sensitivity:
            sanitized = memory_text
            for pattern, _ in self.compiled_rules:
                sanitized = pattern.sub("[REDACTED_POISON_TRIGGER]", sanitized)

            return MemorySanitizerResult(
                is_blocked=True,
                risk_score=heuristic_score,
                violation_code="MEMORY_FABRIC_POISONING_DETECTED",
                details=f"Memory fabric poisoning detected: {', '.join(matched_codes or ['HIGH_HEURISTIC_RISK'])}",
                sanitized_memory=sanitized,
                poison_indicators=matched_codes
            )

        return MemorySanitizerResult(
            is_blocked=False,
            risk_score=heuristic_score,
            sanitized_memory=memory_text
        )
