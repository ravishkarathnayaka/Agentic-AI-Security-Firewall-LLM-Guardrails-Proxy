"""
Shadow In-Context Demonstration and Few-Shot Hijack Guard.

Mitigates OWASP LLM01 (Prompt Injection) and agentic multi-turn conversation hijack
by detecting synthetic few-shot demonstrations, faux assistant turns, and special token
delimiters designed to deceive models into continuing pre-fabricated compromised dialogues.
"""

import re
from dataclasses import dataclass
from typing import Optional, List, Dict, Any


@dataclass
class ShadowDemoResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    details: str = "Passed shadow demonstration check"
    pattern_type: Optional[str] = None
    synthetic_turns_count: int = 0
    confidence_score: float = 0.0


class ShadowDemonstrationGuard:
    """
    Detects synthetic conversational few-shot hijacking, role-turn framing,
    and pseudo-system token injections.
    """

    ROLE_DELIMITERS = [
        r"(?:^|\n)\s*(?:User|Human|Customer|Client)\s*:\s*.*?\n\s*(?:Assistant|AI|Bot|System|Admin)\s*:\s*",
        r"(?:^|\n)\s*(?:Assistant|AI|Bot|System)\s*:\s*.*?\n\s*(?:User|Human|Client)\s*:\s*",
        r"<\|(?:im_start|im_end|system|user|assistant)\|>",
        r"\[\/?INST\]",
        r"<<\/?SYS>>",
        r"\[(?:SYSTEM_PROMPT|ASSISTANT_RESPONSE|USER_QUERY)\]",
    ]

    COMPLIANCE_FABRICATIONS = [
        r"(?i)(?:assistant|system):\s*(?:certainly|sure thing|yes master|i will bypass|guardrails disabled|compliance mode active|root access granted|overriding security)",
        r"(?i)example\s*\d+\s*:\s*input:.*?output:\s*(?:bypassed|unrestricted|approved|granted)",
        r"(?i)synthetic dialogue turn:.*?assistant.*?:",
    ]

    def __init__(
        self,
        max_allowed_turns: int = 1,
        strict_token_delimiters: bool = True
    ):
        self.max_allowed_turns = max_allowed_turns
        self.strict_token_delimiters = strict_token_delimiters
        self._compiled_turn_regexes = [re.compile(p, re.DOTALL | re.IGNORECASE) for p in self.ROLE_DELIMITERS[:2]]
        self._compiled_token_regexes = [re.compile(p, re.IGNORECASE) for p in self.ROLE_DELIMITERS[2:]]
        self._compiled_compliance_regexes = [re.compile(p, re.DOTALL) for p in self.COMPLIANCE_FABRICATIONS]

    def inspect(self, text: str, context: Optional[Dict[str, Any]] = None) -> ShadowDemoResult:
        """
        Inspects text for faux conversation turns, ChatML/INST tags, and fabricated compliance examples.
        """
        if not text:
            return ShadowDemoResult(is_blocked=False)

        # 1. Check for ChatML / INST / Special Token Delimiter Injections
        if self.strict_token_delimiters:
            for pattern in self._compiled_token_regexes:
                match = pattern.search(text)
                if match:
                    return ShadowDemoResult(
                        is_blocked=True,
                        violation_code="special_token_delimiter_injection",
                        details=f"Prompt contains unauthorized synthetic special token delimiter: '{match.group(0)}'",
                        pattern_type="delimiter_injection",
                        confidence_score=0.99
                    )

        # 2. Check for synthetic compliance fabrications (e.g., 'Assistant: guardrails disabled')
        for pattern in self._compiled_compliance_regexes:
            match = pattern.search(text)
            if match:
                return ShadowDemoResult(
                    is_blocked=True,
                    violation_code="shadow_compliance_fabrication",
                    details=f"Detected shadow demonstration framing assistant compliance with bypass: '{match.group(0)[:60]}...'",
                    pattern_type="compliance_fabrication",
                    confidence_score=0.95
                )

        # 3. Check for multiple faux dialogue turns mimicking multi-turn context
        turn_matches_1 = len(self._compiled_turn_regexes[0].findall(text))
        turn_matches_2 = len(self._compiled_turn_regexes[1].findall(text))
        total_turns = turn_matches_1 + turn_matches_2

        if total_turns > self.max_allowed_turns:
            return ShadowDemoResult(
                is_blocked=True,
                violation_code="synthetic_dialogue_turns_detected",
                details=f"Prompt contains {total_turns} synthetic alternating dialogue turns mimicking conversation history.",
                pattern_type="synthetic_multi_turn",
                synthetic_turns_count=total_turns,
                confidence_score=0.90
            )

        return ShadowDemoResult(is_blocked=False)
