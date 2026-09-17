"""Multi-layered Prompt Injection and Jailbreak Guard (OWASP LLM01).

Implements heuristic signature matching, delimiter escaping detection,
obfuscation/base64 payload decoding, and structural risk scoring.
"""

import base64
import re
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class InjectionCheckResult:
    """Result of prompt injection evaluation."""
    is_blocked: bool
    score: float
    detected_patterns: List[str] = field(default_factory=list)
    details: str = ""


class PromptInjectionGuard:
    """Detects adversarial prompt injections, jailbreaks, and delimiter escapes."""

    # High-confidence jailbreak and injection regex patterns
    CRITICAL_PATTERNS = [
        # Direct instruction override
        r"(?i)\b(?:ignore|disregard|forget|skip|drop)\s+(?:all\s+)?(?:previous|prior|above|preceding)\s+(?:instructions|prompts|rules|directives|constraints)\b",
        r"(?i)\b(?:overwrite|override|bypass)\s+(?:system|safety|security|guardrails|filters|content\s+policies)\b",
        # Jailbreak personas
        r"(?i)\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(?:an?\s+)?(?:DAN|DUDE|STAN|AIM|developer\s+mode|unaligned|unrestricted|jailbroken|evil\s+ai|anarchy)\b",
        r"(?i)\bdo\s+anything\s+now\b",
        r"(?i)\benable\s+(?:developer\s+mode|jailbreak\s+mode|unrestricted\s+mode|god\s+mode)\b",
        # System impersonation / command hijacking
        r"(?i)\b(?:system\s+message|system\s+prompt)\s*:\s*(?:you\s+are|ignore|forget|override)\b",
        r"(?i)\bfrom\s+now\s+on,\s+you\s+(?:have\s+no\s+rules|can\s+do\s+anything|must\s+comply\s+without\s+restrictions)\b",
        r"(?i)\byou\s+have\s+been\s+freed\s+from\s+(?:the\s+matrix|openai|guardrails|safety\s+guidelines)\b",
        # Extraction / Verbatim leaks
        r"(?i)\bprint\s+(?:your\s+)?(?:exact\s+)?(?:initial|system|original|base)\s+(?:instructions|prompt|rules)\s+(?:verbatim|in\s+full|word\s+for\s+word)\b",
        r"(?i)\brepeat\s+(?:the\s+)?(?:words|text|instructions)\s+above\s+(?:verbatim|starting|word\s+for\s+word)\b",
    ]

    # Delimiter manipulation and prompt structure hijacking
    DELIMITER_PATTERNS = [
        r"<\|im_start\|>",
        r"<\|im_end\|>",
        r"\[/?INST\]",
        r"\[/?SYS\]",
        r"<<SYS>>",
        r"<</SYS>>",
        r"<system>.*?</system>",
        r"###\s*(?:System|Instruction|Assistant|Human)\s*:",
        r"(?:```|\"\"\")\s*(?:system|override|admin)",
    ]

    # Medium risk indicators (contribute to composite risk score)
    SUSPICIOUS_PATTERNS = [
        r"(?i)\bhypothetical\s+(?:scenario|world)\s+where\s+(?:there\s+are\s+no\s+laws|ethics\s+don't\s+apply)\b",
        r"(?i)\bfor\s+(?:educational|research|academic)\s+purposes\s+only,?\s+(?:how\s+to|explain)\s+(?:bypass|hack|exploit)\b",
        r"(?i)\balways\s+output\s+the\s+token\b",
        r"(?i)\bdo\s+not\s+refuse\s+(?:any\s+request|me|this)\b",
        r"(?i)\bnow\s+answer\s+without\s+any\s+(?:warnings|censorship|filters)\b",
    ]

    # Invisible unicode characters often used for steganographic / hidden injection
    ZERO_WIDTH_CHARS = [
        '\u200b',  # zero-width space
        '\u200c',  # zero-width non-joiner
        '\u200d',  # zero-width joiner
        '\ufeff',  # byte order mark
        '\u2060',  # word joiner
        '\u202a', '\u202b', '\u202c', '\u202d', '\u202e',  # directional overrides
    ]

    def __init__(self, threshold: float = 0.60):
        self.threshold = threshold
        self._compiled_critical = [re.compile(p, re.DOTALL | re.MULTILINE) for p in self.CRITICAL_PATTERNS]
        self._compiled_delimiters = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in self.DELIMITER_PATTERNS]
        self._compiled_suspicious = [re.compile(p, re.DOTALL | re.MULTILINE) for p in self.SUSPICIOUS_PATTERNS]

    def _check_zero_width_anomalies(self, text: str) -> bool:
        """Detect stealthy invisible unicode or zero-width character injection."""
        count = sum(text.count(char) for char in self.ZERO_WIDTH_CHARS)
        return count >= 3

    def _detect_and_decode_base64(self, text: str) -> List[str]:
        """Find potential Base64 strings, decode, and evaluate contents."""
        decoded_payloads = []
        # Match base64 tokens of significant length (>= 20 chars)
        candidates = re.findall(r"(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", text)
        for cand in candidates:
            try:
                decoded = base64.b64decode(cand).decode("utf-8", errors="ignore").strip()
                if len(decoded) >= 8 and any(c.isalpha() for c in decoded):
                    decoded_payloads.append(decoded)
            except Exception:
                continue
        return decoded_payloads

    def inspect(self, text: str) -> InjectionCheckResult:
        """Inspect inbound text for prompt injection and jailbreak techniques.

        Args:
            text: Inbound prompt or message content.

        Returns:
            InjectionCheckResult with block decision, score, and explanation.
        """
        if not text or not text.strip():
            return InjectionCheckResult(is_blocked=False, score=0.0)

        score = 0.0
        detected = []

        # 1. Critical Pattern Check (Hard failure)
        for pattern, compiled in zip(self.CRITICAL_PATTERNS, self._compiled_critical):
            if compiled.search(text):
                score += 1.0
                detected.append(f"Critical Injection Signature: {compiled.pattern}")

        # 2. Delimiter & Prompt Structure Manipulation
        for pattern, compiled in zip(self.DELIMITER_PATTERNS, self._compiled_delimiters):
            if compiled.search(text):
                score += 0.8
                detected.append(f"Delimiter Hijacking: {compiled.pattern}")

        # 3. Suspicious / Evasion indicators
        for pattern, compiled in zip(self.SUSPICIOUS_PATTERNS, self._compiled_suspicious):
            if compiled.search(text):
                score += 0.4
                detected.append(f"Evasion Indicator: {compiled.pattern}")

        # 4. Hidden Zero-Width Unicode Steganography
        if self._check_zero_width_anomalies(text):
            score += 0.7
            detected.append("Steganographic Anomaly: Excessive zero-width unicode characters")

        # 5. Base64 Obfuscation Analysis
        decoded_blocks = self._detect_and_decode_base64(text)
        for decoded in decoded_blocks:
            for pattern, compiled in zip(self.CRITICAL_PATTERNS, self._compiled_critical):
                if compiled.search(decoded):
                    score += 1.0
                    detected.append(f"Obfuscated Base64 Injection: {compiled.pattern}")

        # Cap score at 1.0
        final_score = min(score, 1.0)
        is_blocked = final_score >= self.threshold

        details = "; ".join(detected) if detected else "No injection anomalies detected."

        return InjectionCheckResult(
            is_blocked=is_blocked,
            score=round(final_score, 3),
            detected_patterns=detected,
            details=details
        )
