"""Outbound Output Sanitizer Guard (OWASP LLM02 - Insecure Output Handling).

Inspects model completions for hazardous shell commands, destructive instructions,
and sensitive system credential / private key leakage.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class OutputSanitizeResult:
    """Result of outbound output sanitization."""
    is_blocked: bool
    violation_code: Optional[str] = None
    detected_threats: List[str] = field(default_factory=list)
    details: str = ""


class OutputSanitizer:
    """Inspects model outputs for destructive payloads and credential leakage."""

    HAZARDOUS_COMMAND_PATTERNS = [
        # Root filesystem destruction
        (r"(?i)\brm\s+-[a-z]*(?:r[a-z]*f|f[a-z]*r)[a-z]*\s+.*?(?:/|\*|~|--no-preserve-root)", "destructive_filesystem_removal"),
        (r"(?i)\bmkfs\.(?:ext[234]|xfs|btrfs|vfat)\s+/dev/\w+", "format_filesystem_command"),
        (r"(?i)\bdd\s+if=/dev/(?:zero|urandom)\s+of=/dev/\w+", "raw_disk_overwrite_command"),
        (r"(?i)\bformat\s+[c-z]:\s+/fs:\w+", "windows_disk_format_command"),
        # Remote execution piping
        (r"(?i)(?:curl|wget)\s+[^|;\n\r]+\|\s*(?:sh|bash|zsh|dash|python|perl)", "remote_script_pipe_execution"),
        # Reverse shells
        (r"(?i)(?:bash|sh)\s+-i\s+>&?\s*/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+", "bash_tcp_reverse_shell"),
        (r"(?i)\bnc\s+(?:-[a-z]*e\s+|[0-9\.]+\s+[0-9]+\s+-[a-z]*e\s+)(?:/bin/sh|/bin/bash|cmd\.exe|powershell)", "netcat_reverse_shell"),
        # Fork bombs
        (r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", "fork_bomb_denial_of_service"),
        # Encoded PowerShell execution
        (r"(?i)\bpowershell(?:\.exe)?\s+(?:-[a-z\s]*\s+)?-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}", "powershell_encoded_execution"),
    ]

    CREDENTIAL_LEAK_PATTERNS = [
        # Private Cryptographic Keys
        (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "private_cryptographic_key_leak"),
        # Database connection strings with embedded passwords
        (r"(?i)(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)://[a-zA-Z0-9_\-\.]+:[^@\s/]+@[a-zA-Z0-9_\-\.]+", "database_credentials_uri_leak"),
    ]

    def __init__(self):
        self._compiled_commands = [
            (re.compile(pattern, re.MULTILINE), code)
            for pattern, code in self.HAZARDOUS_COMMAND_PATTERNS
        ]
        self._compiled_creds = [
            (re.compile(pattern, re.MULTILINE), code)
            for pattern, code in self.CREDENTIAL_LEAK_PATTERNS
        ]

    def inspect(self, content: str) -> OutputSanitizeResult:
        """Inspect outbound LLM completion before dispatching to client."""
        if not content:
            return OutputSanitizeResult(is_blocked=False)

        threats = []
        violation_code = None

        # 1. Check for hazardous destructive commands
        for regex, code in self._compiled_commands:
            if regex.search(content):
                threats.append(f"Hazardous Command [{code}]: {regex.pattern}")
                if not violation_code:
                    violation_code = code

        # 2. Check for credential and private key leakage
        for regex, code in self._compiled_creds:
            if regex.search(content):
                threats.append(f"Credential Leak [{code}]: {regex.pattern}")
                if not violation_code:
                    violation_code = code

        is_blocked = len(threats) > 0
        details = "; ".join(threats) if is_blocked else "Output passed security hygiene check."

        return OutputSanitizeResult(
            is_blocked=is_blocked,
            violation_code=violation_code,
            detected_threats=threats,
            details=details
        )
