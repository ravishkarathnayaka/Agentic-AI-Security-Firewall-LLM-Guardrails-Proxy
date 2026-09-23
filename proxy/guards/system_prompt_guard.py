"""System Prompt Protection & Canary Leak Guard (OWASP LLM01 / LLM06).

Detects adversarial extraction of system instructions and monitors canary tokens
to prevent proprietary knowledge and system rule leakage.
"""

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class SystemPromptCheckResult:
    """Result of system prompt extraction evaluation."""
    is_blocked: bool
    violation_code: Optional[str] = None
    details: str = ""


class SystemPromptGuard:
    """Detects attempts to leak or extract system prompts and canaries."""

    EXTRACTION_PATTERNS = [
        r"(?i)\b(?:repeat|print|reveal|output|display|show|disclose|echo|dump)\s+(?:your\s+)?(?:system\s+prompt|initial\s+prompt|hidden\s+prompt|core\s+instructions|system\s+instructions|developer\s+instructions)\b",
        r"(?i)\bwhat\s+(?:are\s+your\s+instructions|is\s+your\s+system\s+prompt|did\s+your\s+creators\s+tell\s+you)\b",
        r"(?i)\bprint\s+(?:everything|all\s+text)\s+(?:above|prior\s+to\s+this\s+line|before\s+this\s+conversation)\b",
        r"(?i)\boutput\s+the\s+preceding\s+prompt\s+verbatim\b",
        r"(?i)\bwhat\s+rules\s+were\s+you\s+given\s+at\s+the\s+beginning\b",
        r"(?i)\bshow\s+me\s+the\s+configuration\s+text\s+before\s+my\s+message\b",
        r"(?i)\bignore\s+previous\s+text\s+and\s+print\s+system\s+prompt\b",
    ]

    def __init__(self, canary_token: str = "CANARY_SEC_TOKEN_9941a8"):
        self.canary_token = canary_token
        self._compiled_extraction = [
            re.compile(p, re.IGNORECASE | re.MULTILINE) for p in self.EXTRACTION_PATTERNS
        ]

    def inspect_prompt(self, prompt: str) -> SystemPromptCheckResult:
        """Inspect inbound user prompt for extraction attempts."""
        if not prompt or not prompt.strip():
            return SystemPromptCheckResult(is_blocked=False)

        # 1. Check for prompt extraction attempts
        for pattern in self._compiled_extraction:
            if pattern.search(prompt):
                return SystemPromptCheckResult(
                    is_blocked=True,
                    violation_code="system_prompt_extraction_attempt",
                    details=f"Inbound prompt matches system prompt extraction pattern: {pattern.pattern}"
                )

        # 2. Check if user is trying to probe for the canary directly
        if self.canary_token and self.canary_token.lower() in prompt.lower():
            return SystemPromptCheckResult(
                is_blocked=True,
                violation_code="canary_token_probing",
                details="Inbound prompt contains direct query for internal security canary token."
            )

        return SystemPromptCheckResult(is_blocked=False)

    def inspect_completion(self, completion: str) -> SystemPromptCheckResult:
        """Inspect outbound LLM completion to detect canary leaks."""
        if not completion:
            return SystemPromptCheckResult(is_blocked=False)

        # Detect canary token leak in completion
        if self.canary_token and self.canary_token in completion:
            return SystemPromptCheckResult(
                is_blocked=True,
                violation_code="canary_token_leak_detected",
                details="Outbound LLM response contained confidential internal canary token."
            )

        return SystemPromptCheckResult(is_blocked=False)
