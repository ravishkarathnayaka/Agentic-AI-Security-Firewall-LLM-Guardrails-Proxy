"""
Tool Call Argument Sanitizer Guard
==================================
Deep semantic and lexical sanitizer for autonomous agent tool invocations.
Neutralizes null-byte injections, raw terminal escape sequences (ANSI injection),
control character smuggling, and dangerous unquoted shell metacharacters
inside structured tool arguments before dispatch to execution backends.
"""

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union


@dataclass
class ArgumentSanitizerResult:
    is_blocked: bool
    sanitized_args: Optional[Dict[str, Any]] = None
    violation_code: Optional[str] = None
    details: Optional[str] = None
    modifications_made: int = 0


class ToolCallArgumentSanitizerGuard:
    """
    Validates and sanitizes structured dictionary arguments intended for tool calls.
    """

    ANSI_ESCAPE_PATTERN = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    NULL_BYTE_PATTERN = re.compile(r"(\x00|%00|\\u0000)")
    COMMAND_SUBST_PATTERN = re.compile(r"(`[^`]+`|\$\([^\)]+\))")

    def __init__(
        self,
        block_null_bytes: bool = True,
        strip_ansi_escapes: bool = True,
        block_command_substitution: bool = True,
        max_string_length: int = 16384,
        max_depth: int = 10,
    ):
        self.block_null_bytes = block_null_bytes
        self.strip_ansi_escapes = strip_ansi_escapes
        self.block_command_substitution = block_command_substitution
        self.max_string_length = max_string_length
        self.max_depth = max_depth

    def _sanitize_value(
        self,
        val: Any,
        depth: int = 0
    ) -> Tuple[bool, Any, Optional[str], Optional[str], int]:
        """
        Recursively inspects and sanitizes a parameter value.
        Returns: (is_blocked, sanitized_val, violation_code, details, mod_count)
        """
        if depth > self.max_depth:
            return (
                True,
                None,
                "argument_nesting_depth_exceeded",
                f"Tool argument nesting depth exceeded limit ({self.max_depth})",
                0,
            )

        if isinstance(val, str):
            mods = 0
            # Check length
            if len(val) > self.max_string_length:
                return (
                    True,
                    None,
                    "argument_string_length_exceeded",
                    f"Argument string length ({len(val)}) exceeds maximum ({self.max_string_length})",
                    0,
                )

            # Check null bytes
            if self.block_null_bytes and self.NULL_BYTE_PATTERN.search(val):
                return (
                    True,
                    None,
                    "null_byte_injection_detected",
                    "Null byte sequence (%00 or \\x00) detected in tool argument",
                    0,
                )

            # Check command substitution
            if self.block_command_substitution and self.COMMAND_SUBST_PATTERN.search(val):
                return (
                    True,
                    None,
                    "shell_command_substitution_detected",
                    "Shell command substitution (`...` or $(...)) detected in tool argument",
                    0,
                )

            # Strip ANSI escape sequences
            cleaned_str = val
            if self.strip_ansi_escapes and self.ANSI_ESCAPE_PATTERN.search(cleaned_str):
                cleaned_str = self.ANSI_ESCAPE_PATTERN.sub("", cleaned_str)
                mods += 1

            return False, cleaned_str, None, None, mods

        elif isinstance(val, dict):
            new_dict = {}
            total_mods = 0
            for k, v in val.items():
                if not isinstance(k, str) or self.NULL_BYTE_PATTERN.search(k):
                    return (
                        True,
                        None,
                        "invalid_argument_key",
                        f"Dangerous or non-string key detected: '{k}'",
                        0,
                    )
                is_b, s_v, v_code, details, m_count = self._sanitize_value(v, depth + 1)
                if is_b:
                    return True, None, v_code, details, 0
                new_dict[k] = s_v
                total_mods += m_count
            return False, new_dict, None, None, total_mods

        elif isinstance(val, list):
            new_list = []
            total_mods = 0
            for item in val:
                is_b, s_v, v_code, details, m_count = self._sanitize_value(item, depth + 1)
                if is_b:
                    return True, None, v_code, details, 0
                new_list.append(s_v)
                total_mods += m_count
            return False, new_list, None, None, total_mods

        # Primitive scalars (int, float, bool, None) are safe
        return False, val, None, None, 0

    def sanitize_arguments(
        self,
        tool_name: str,
        arguments: Union[Dict[str, Any], str]
    ) -> ArgumentSanitizerResult:
        """
        Sanitize arguments for a given tool.
        """
        parsed_args = arguments
        if isinstance(arguments, str):
            try:
                parsed_args = json.loads(arguments)
            except Exception as e:
                return ArgumentSanitizerResult(
                    is_blocked=True,
                    violation_code="malformed_argument_json",
                    details=f"Failed to parse tool argument JSON: {str(e)}",
                )

        if not isinstance(parsed_args, dict):
            return ArgumentSanitizerResult(
                is_blocked=True,
                violation_code="invalid_argument_structure",
                details="Tool arguments must resolve to a JSON object/dictionary",
            )

        is_blocked, sanitized, v_code, details, mods = self._sanitize_value(parsed_args, 0)
        if is_blocked:
            return ArgumentSanitizerResult(
                is_blocked=True,
                violation_code=v_code,
                details=f"Tool '{tool_name}' rejected: {details}",
            )

        return ArgumentSanitizerResult(
            is_blocked=False,
            sanitized_args=sanitized,
            modifications_made=mods,
        )
