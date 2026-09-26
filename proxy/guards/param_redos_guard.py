"""
Catastrophic Parameter ReDoS and Regex Complexity Guard.

Mitigates OWASP LLM04 (Model Denial of Service) and CWE-1333 (Regular Expression
Denial of Service) by statically analyzing regex patterns in user prompts and agent tool
arguments to detect exponential/polynomial backtracking vulnerabilities and excessive quantifiers.
"""

import re
from dataclasses import dataclass
from typing import Optional, List, Dict, Any


@dataclass
class ReDoSResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    vulnerability_type: Optional[str] = None
    details: str = "Passed ReDoS complexity check"
    offending_subpattern: Optional[str] = None


class ParamReDoSGuard:
    """
    Detects catastrophic backtracking patterns and resource-exhausting regex structures.
    """

    # Signatures of polynomial and exponential backtracking (nested quantifiers & overlapping alternations)
    REDOS_PATTERNS = [
        # Nested repetition: (a+)+, ([a-z]*)+, (\d+)*, etc.
        (r"\((?:[^\)]*(?:\+|\*|\{[0-9]+,\}))\)(?:\+|\*|\{[0-9]+,\})", "nested_quantifiers_exponential_backtracking"),
        # Overlapping repeated alternation: (a|aa)+, (.*|.+)+
        (r"\([a-zA-Z0-9_\.]+\|[a-zA-Z0-9_\.]+\)(?:\+|\*|\{[0-9]+,\})", "overlapping_alternation_repetition"),
        # Nested wildcard quantifier: (.*)+ or (.+)*
        (r"\(\.[*+]\)[*+]", "nested_wildcard_quantifier"),
        # Star height > 1: ((a*)*)*
        (r"\(\([^)]*\)[*+]\)[*+]", "high_star_height_nested_repetition"),
    ]

    REGEX_PARAM_KEYS = {"regex", "pattern", "filter", "grep", "matcher", "query"}

    def __init__(
        self,
        max_pattern_length: int = 500,
        max_quantifier_value: int = 1000
    ):
        self.max_pattern_length = max_pattern_length
        self.max_quantifier_value = max_quantifier_value
        self._compiled_redos_checks = [(re.compile(p), name) for p, name in self.REDOS_PATTERNS]
        self._quantifier_range_regex = re.compile(r"\{(\d+)(?:,\s*(\d+)?)?\}")

    def inspect_pattern(self, pattern: str) -> ReDoSResult:
        """
        Analyzes a regular expression string for ReDoS vulnerabilities.
        """
        if not pattern:
            return ReDoSResult(is_blocked=False)

        # 1. Check excessive pattern length
        if len(pattern) > self.max_pattern_length:
            return ReDoSResult(
                is_blocked=True,
                violation_code="excessive_regex_length",
                vulnerability_type="buffer_complexity",
                details=f"Regex pattern length ({len(pattern)}) exceeds maximum limit of {self.max_pattern_length} chars."
            )

        # 2. Check for extreme quantifier bounds (e.g. {1000000})
        for match in self._quantifier_range_regex.finditer(pattern):
            start_val = int(match.group(1))
            end_val = int(match.group(2)) if match.group(2) else start_val
            if start_val > self.max_quantifier_value or end_val > self.max_quantifier_value:
                return ReDoSResult(
                    is_blocked=True,
                    violation_code="excessive_quantifier_bound",
                    vulnerability_type="quantifier_exhaustion",
                    offending_subpattern=match.group(0),
                    details=f"Quantifier '{match.group(0)}' exceeds maximum safe threshold ({self.max_quantifier_value})."
                )

        # 3. Check for nested quantifier / catastrophic backtracking signatures
        for compiled_rx, vuln_name in self._compiled_redos_checks:
            m = compiled_rx.search(pattern)
            if m:
                return ReDoSResult(
                    is_blocked=True,
                    violation_code="catastrophic_redos_signature",
                    vulnerability_type=vuln_name,
                    offending_subpattern=m.group(0),
                    details=f"Pattern exhibits catastrophic backtracking via {vuln_name}: '{m.group(0)}'"
                )

        # 4. Verify syntactical validity with standard compiler
        try:
            re.compile(pattern)
        except re.error as e:
            return ReDoSResult(
                is_blocked=True,
                violation_code="invalid_regex_syntax",
                vulnerability_type="compilation_error",
                details=f"Malformed regex syntax: {str(e)}"
            )

        return ReDoSResult(is_blocked=False)

    def inspect_tool_call(self, tool_name: str, parameters: Dict[str, Any]) -> ReDoSResult:
        """
        Inspects regex-like tool parameters for catastrophic backtracking patterns.
        """
        if not parameters or not isinstance(parameters, dict):
            return ReDoSResult(is_blocked=False)

        for key, val in parameters.items():
            if any(k in key.lower() for k in self.REGEX_PARAM_KEYS) and isinstance(val, str):
                result = self.inspect_pattern(val)
                if result.is_blocked:
                    return result

        return ReDoSResult(is_blocked=False)
