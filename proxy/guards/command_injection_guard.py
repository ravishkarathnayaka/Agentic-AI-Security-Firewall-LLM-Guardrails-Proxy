"""Agent Tool Command Injection & Parameter Chaining Guard.

Inspects tool call arguments and string parameters to prevent OS command chaining
metacharacters (;, &&, ||, |, $(), `), sensitive system file path traversal,
null-byte truncations, and Windows/Linux shell invocation wrappers.
"""

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class CommandCheckResult:
    """Result of command injection inspection."""
    is_blocked: bool
    violation_code: Optional[str] = None
    details: str = ""


class CommandInjectionGuard:
    """Detects command injection, command chaining, and file path manipulation."""

    # Command chaining / shell injection patterns
    CHAINING_PATTERNS = [
        (re.compile(r";\s*(?:rm|cat|bash|sh|curl|wget|nc|powershell|cmd|python|chmod)\b", re.IGNORECASE), "semicolon_command_chaining"),
        (re.compile(r"&&\s*(?:rm|cat|bash|sh|curl|wget|nc|powershell|cmd|python|chmod)\b", re.IGNORECASE), "logical_and_command_chaining"),
        (re.compile(r"\|\|\s*(?:rm|cat|bash|sh|curl|wget|nc|powershell|cmd|python|chmod)\b", re.IGNORECASE), "logical_or_command_chaining"),
        (re.compile(r"\|\s*(?:sh|bash|powershell|cmd)\b", re.IGNORECASE), "pipe_shell_execution"),
        (re.compile(r"`[^`]{2,}`"), "backtick_subshell_injection"),
        (re.compile(r"\$\([^\)]{2,}\)"), "dollar_parenthesis_subshell"),
    ]

    # Sensitive OS file targets
    SENSITIVE_FILES_PATTERN = re.compile(
        r"(?:/etc/(?:passwd|shadow|hosts|sudoers)|/proc/(?:self|\d+)/(?:environ|cmdline)|"
        r"(?:~|\.ssh)/id_(?:rsa|ecdsa|ed25519)|(?:~|\.aws)/(?:credentials|config)|"
        r"[a-zA-Z]:\\Windows\\(?:System32|SysWOW64)\\(?:config\\SAM|drivers\\etc\\hosts))",
        re.IGNORECASE
    )

    # Null-byte truncation
    NULL_BYTE_PATTERN = re.compile(r"(?:%00|\\x00|\\0)")

    # Windows / Linux downloaders & execution wrappers
    EXECUTION_WRAPPERS = [
        re.compile(r"(?:cmd\.exe|powershell\.exe)\s+(?:/c|-c|-enc|-encodedcommand)", re.IGNORECASE),
        re.compile(r"(?:certutil|bitsadmin)\s+(?:-urlcache|/transfer)", re.IGNORECASE),
        re.compile(r"(?:curl|wget)\s+[^\s]+\s*\|\s*(?:bash|sh)", re.IGNORECASE),
    ]

    def inspect_text(self, text: str) -> CommandCheckResult:
        """Inspect a string for command injection patterns."""
        if not text:
            return CommandCheckResult(is_blocked=False)

        # 1. Null-byte injection
        if self.NULL_BYTE_PATTERN.search(text):
            return CommandCheckResult(
                is_blocked=True,
                violation_code="null_byte_injection",
                details="Detected null-byte injection attempt in parameter"
            )

        # 2. Sensitive file access
        m_file = self.SENSITIVE_FILES_PATTERN.search(text)
        if m_file:
            return CommandCheckResult(
                is_blocked=True,
                violation_code="sensitive_system_file_access",
                details=f"Attempted access to protected system file: '{m_file.group(0)}'"
            )

        # 3. Command chaining
        for pat, code in self.CHAINING_PATTERNS:
            if pat.search(text):
                return CommandCheckResult(
                    is_blocked=True,
                    violation_code=code,
                    details=f"Detected shell command injection / chaining pattern: {code}"
                )

        # 4. Execution wrappers
        for pat in self.EXECUTION_WRAPPERS:
            if pat.search(text):
                return CommandCheckResult(
                    is_blocked=True,
                    violation_code="suspicious_execution_wrapper",
                    details="Detected dangerous shell or downloader invocation wrapper"
                )

        return CommandCheckResult(is_blocked=False)

    def inspect_arguments(self, args: Any) -> CommandCheckResult:
        """Recursively inspect tool call arguments (dict, list, or string)."""
        if isinstance(args, str):
            return self.inspect_text(args)
        elif isinstance(args, dict):
            for v in args.values():
                res = self.inspect_arguments(v)
                if res.is_blocked:
                    return res
        elif isinstance(args, list):
            for item in args:
                res = self.inspect_arguments(item)
                if res.is_blocked:
                    return res

        return CommandCheckResult(is_blocked=False)
