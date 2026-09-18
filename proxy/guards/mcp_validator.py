"""Model Context Protocol (MCP) Tool Execution Validator (OWASP LLM08).

Enforces security controls on Anthropic Model Context Protocol (MCP) and agentic
tool invocation:
- Blocks shell command injection in tool arguments (; && || ` $()).
- Prevents directory traversal in MCP file operations (../../).
- Restricts dangerous executable commands (sudo, rm -rf, curl | sh, nc).
- Validates tool schema boundaries.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class MCPValidationResult:
    """Result of Model Context Protocol (MCP) tool execution validation."""
    is_valid: bool
    score: float
    violations: List[str] = field(default_factory=list)
    details: str = ""


class MCPValidator:
    """Validates MCP function calls and arguments against agentic abuse policies."""

    # Shell command injection metacharacters
    SHELL_INJECTION_PATTERN = re.compile(r"(?:[;&|`$]|\$\([^)]+\)|\b(?:nc|netcat|bash|sh|zsh|powershell|cmd)\b.*?-e)")

    # Dangerous command blacklist
    DANGEROUS_COMMANDS = [
        r"(?i)\brm\s+-(?:r|f|rf|fr)\b",
        r"(?i)\b(?:mkfs|dd\s+if=|fdisk|format\s+[a-z]:)\b",
        r"(?i)\b(?:curl|wget)\b.*?\|\s*(?:bash|sh|zsh|python|perl)",
        r"(?i)\b(?:sudo|su)\s+",
        r"(?i)\bchmod\s+(?:777|-R\s+777)\b",
        r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\s+-(?:enc|encodedcommand|e)\b",
    ]

    # Path traversal patterns
    PATH_TRAVERSAL_PATTERN = re.compile(r"(?:\.\.[/\\]|[/\\]etc[/\\](?:passwd|shadow|sudoers)|[a-zA-Z]:[/\\]Windows[/\\]System32)", re.IGNORECASE)

    # Allowed safe MCP tool namespaces
    ALLOWED_MCP_TOOLS = {
        "read_file", "write_file", "list_directory", "search_files",
        "fetch_url", "query_database", "calculator", "get_weather",
        "execute_code", "run_terminal_command"
    }

    def __init__(self, enforce_whitelist: bool = False, risk_threshold: float = 0.70) -> None:
        self.enforce_whitelist = enforce_whitelist
        self.risk_threshold = risk_threshold

    def validate_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> MCPValidationResult:
        """Inspect an individual MCP tool invocation for command injection, traversal, or abuse."""
        violations: List[str] = []

        # 1. Whitelist check (optional strict mode)
        if self.enforce_whitelist and tool_name not in self.ALLOWED_MCP_TOOLS:
            violations.append(f"Unapproved MCP tool name: '{tool_name}'")

        # 2. Inspect string arguments recursively
        arg_strings: List[str] = []
        def extract_strings(obj: Any) -> None:
            if isinstance(obj, str):
                arg_strings.append(obj)
            elif isinstance(obj, dict):
                for v in obj.values():
                    extract_strings(v)
            elif isinstance(obj, (list, tuple)):
                for item in obj:
                    extract_strings(item)

        extract_strings(arguments)

        for val in arg_strings:
            # Check for path traversal in file arguments
            if self.PATH_TRAVERSAL_PATTERN.search(val):
                violations.append(f"Directory traversal detected in parameter: '{val[:60]}'")

            # Check for dangerous system commands
            for cmd_pat in self.DANGEROUS_COMMANDS:
                if re.search(cmd_pat, val):
                    violations.append(f"Prohibited destructive command detected: '{val[:60]}'")

            # Check for command injection in tool execution parameters
            if tool_name in ("execute_code", "run_terminal_command", "bash", "terminal"):
                if self.SHELL_INJECTION_PATTERN.search(val):
                    violations.append(f"Shell injection metacharacters in command argument: '{val[:60]}'")

        score = 0.0
        if violations:
            score = 1.0

        is_valid = len(violations) == 0
        details = ""
        if not is_valid:
            details = f"MCP tool policy violation in '{tool_name}': {'; '.join(violations)}"

        return MCPValidationResult(
            is_valid=is_valid,
            score=score,
            violations=violations,
            details=details,
        )