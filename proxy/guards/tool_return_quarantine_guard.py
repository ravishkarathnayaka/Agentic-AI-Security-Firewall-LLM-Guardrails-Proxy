"""
Structured Tool Return Schema & Payload Quarantine Guard
========================================================
Inspects and quarantines tool return values and third-party API outputs before
re-injecting them into the LLM context window, mitigating indirect prompt injection,
schema evasion, and context stuffing via untrusted external tool data.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union


@dataclass
class ToolReturnQuarantineResult:
    is_quarantined: bool
    is_blocked: bool
    sanitized_output: Any
    violation_code: Optional[str] = None
    details: Optional[str] = None
    risk_score: float = 0.0


class ToolReturnQuarantineGuard:
    """
    Guards the agent observation feedback loop against indirect prompt injections
    and malicious payload smuggling concealed within tool results.
    """

    DANGEROUS_INJECTION_PATTERNS = [
        re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+(instructions|directives)", re.IGNORECASE),
        re.compile(r"system\s*:\s*you\s+are\s+now", re.IGNORECASE),
        re.compile(r"<\s*script[^>]*>.*?<\s*/\s*script\s*>", re.IGNORECASE | re.DOTALL),
        re.compile(r"javascript\s*:\s*alert\(", re.IGNORECASE),
        re.compile(r"override\s+security\s+policy", re.IGNORECASE),
        re.compile(r"exfiltrate\s+(all\s+)?(keys|secrets|tokens)", re.IGNORECASE),
    ]

    def __init__(
        self,
        max_return_bytes: int = 65536,
        quarantine_high_risk: bool = True,
        strict_block_exploits: bool = True,
    ):
        self.max_return_bytes = max_return_bytes
        self.quarantine_high_risk = quarantine_high_risk
        self.strict_block_exploits = strict_block_exploits

    def inspect_and_quarantine(
        self,
        tool_name: str,
        tool_output: Any,
    ) -> ToolReturnQuarantineResult:
        """
        Inspects output produced by a tool execution and sanitizes or quarantines it.
        """
        raw_text = tool_output if isinstance(tool_output, str) else json.dumps(tool_output, default=str)
        byte_length = len(raw_text.encode("utf-8"))

        # Check payload size
        if byte_length > self.max_return_bytes:
            truncated = raw_text[: self.max_return_bytes] + "\n...[TRUNCATED_DUE_TO_SIZE]"
            return ToolReturnQuarantineResult(
                is_quarantined=True,
                is_blocked=False,
                sanitized_output=truncated,
                violation_code="tool_output_payload_oversized",
                details=f"Tool '{tool_name}' returned {byte_length} bytes, exceeding limit of {self.max_return_bytes}.",
                risk_score=0.6,
            )

        # Check injection signatures in tool return
        matches = []
        for pattern in self.DANGEROUS_INJECTION_PATTERNS:
            if pattern.search(raw_text):
                matches.append(pattern.pattern)

        if matches:
            if self.strict_block_exploits and any("exfiltrate" in m or "ignore" in m for m in matches):
                return ToolReturnQuarantineResult(
                    is_quarantined=True,
                    is_blocked=True,
                    sanitized_output=None,
                    violation_code="tool_return_indirect_injection_blocked",
                    details=f"Indirect prompt injection attack detected in tool '{tool_name}' return value.",
                    risk_score=0.95,
                )

            # Quarantine and wrap in untrusted boundary
            quarantined_text = (
                f"[UNTRUSTED_EXTERNAL_TOOL_OBSERVATION: {tool_name}]\n"
                f"{raw_text}\n"
                f"[/UNTRUSTED_EXTERNAL_TOOL_OBSERVATION]"
            )
            return ToolReturnQuarantineResult(
                is_quarantined=True,
                is_blocked=False,
                sanitized_output=quarantined_text,
                violation_code="tool_return_quarantined_boundary",
                details=f"Suspicious payload in tool '{tool_name}' quarantined within security boundaries.",
                risk_score=0.75,
            )

        return ToolReturnQuarantineResult(
            is_quarantined=False,
            is_blocked=False,
            sanitized_output=tool_output,
            risk_score=0.0,
        )
