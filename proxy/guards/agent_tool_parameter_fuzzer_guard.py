"""
Agent Tool Parameter Fuzzer & Schema Validator Guard
===================================================
Inspects arguments passed by autonomous agents into external tool calls and shell utilities,
preventing command injection, path traversal, and malicious payload fuzzing.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ToolParameterFuzzResult:
    is_blocked: bool
    risk_score: float = 0.0
    violation_code: Optional[str] = None
    details: Optional[str] = None
    sanitized_params: Optional[Dict[str, Any]] = None
    anomalous_fields: List[str] = field(default_factory=list)


class AgentToolParameterFuzzerGuard:
    """
    Validates parameter safety before tool invocation occurs.
    """

    DANGEROUS_PATTERNS = [
        (r"(?:;|&&|\|\||`|\$\([^)]+\))", "COMMAND_INJECTION_OPERATOR"),
        (r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)", "DIRECTORY_TRAVERSAL_PAYLOAD"),
        (r"(?i)(?:UNION\s+SELECT|OR\s+1=1|--\s*$|;\s*DROP\s+TABLE)", "SQL_INJECTION_PROBE"),
        (r"(?:<script[^>]*>|javascript:|onerror\s*=)", "CROSS_SITE_SCRIPTING_TOKEN"),
        (r"(?:/etc/passwd|/etc/shadow|C:\\Windows\\System32)", "SENSITIVE_OS_PATH_ACCESS"),
    ]

    def __init__(self, max_param_length: int = 4096):
        self.max_length = max_param_length
        self.rules = [(re.compile(p), code) for p, code in self.DANGEROUS_PATTERNS]

    def _inspect_value(self, val: Any) -> List[str]:
        findings = []
        str_val = str(val)

        if len(str_val) > self.max_length:
            findings.append("PARAMETER_BUFFER_OVERFLOW_ATTEMPT")

        for pattern, code in self.rules:
            if pattern.search(str_val):
                findings.append(code)

        return findings

    def validate_tool_call(self, tool_name: str, parameters: Dict[str, Any]) -> ToolParameterFuzzResult:
        if not parameters:
            return ToolParameterFuzzResult(is_blocked=False, risk_score=0.0, sanitized_params={})

        anomalies = []
        sanitized = dict(parameters)

        for param_key, param_value in parameters.items():
            # Check key
            key_issues = self._inspect_value(param_key)
            if key_issues:
                anomalies.extend([f"Key '{param_key}': {issue}" for issue in key_issues])

            # Check value
            if isinstance(param_value, (str, bytes)):
                val_issues = self._inspect_value(param_value)
                if val_issues:
                    anomalies.extend([f"Param '{param_key}': {issue}" for issue in val_issues])
            elif isinstance(param_value, list):
                for item in param_value:
                    item_issues = self._inspect_value(item)
                    if item_issues:
                        anomalies.extend([f"ListParam '{param_key}': {issue}" for issue in item_issues])
            elif isinstance(param_value, dict):
                nested_res = self.validate_tool_call(f"{tool_name}.{param_key}", param_value)
                if nested_res.is_blocked:
                    anomalies.extend(nested_res.anomalous_fields)

        if anomalies:
            return ToolParameterFuzzResult(
                is_blocked=True,
                risk_score=min(1.0, 0.4 + 0.2 * len(anomalies)),
                violation_code="MALICIOUS_TOOL_PARAMETER_DETECTED",
                details=f"Tool '{tool_name}' rejected due to hazardous parameter payloads: {'; '.join(anomalies)}",
                sanitized_params=sanitized,
                anomalous_fields=anomalies
            )

        return ToolParameterFuzzResult(
            is_blocked=False,
            risk_score=0.0,
            sanitized_params=sanitized
        )
