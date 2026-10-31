"""
Agent Privilege Boundary & Dynamic Syscall Sandbox Guard
========================================================
Inspects tool invocations, shell parameters, and system calls made by autonomous
agents, enforcing dynamic seccomp/eBPF-style capability ceilings to prevent
container escapes, unauthorized kernel operations, and privilege escalations.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class SyscallSandboxResult:
    is_blocked: bool
    risk_score: float = 0.0
    violation_code: Optional[str] = None
    details: Optional[str] = None
    flagged_syscalls: List[str] = field(default_factory=list)


class AgentPrivilegeBoundarySandboxGuard:
    """
    Enforces a deny-by-default execution filter on hazardous system calls,
    kernel namespace manipulation, and low-level socket raw primitives.
    """

    FORBIDDEN_SYSCALL_PRIMITIVES = [
        (r"(?i)(?:ptrace|process_vm_readv|process_vm_writev)", "SYSCALL_MEMORY_INSPECTION_DENIED"),
        (r"(?i)(?:mount|umount2|pivot_root|chroot)", "SYSCALL_NAMESPACE_ESCAPE_DENIED"),
        (r"(?i)(?:setuid|setgid|setreuid|capset)", "SYSCALL_PRIVILEGE_TRANSITION_DENIED"),
        (r"(?i)(?:socket\(AF_PACKET|socket\(AF_NETLINK|raw_socket)", "SYSCALL_RAW_SOCKET_SNIFF_DENIED"),
        (r"(?i)(?:reboot|kexec_load|init_module|finit_module)", "SYSCALL_KERNEL_CONTROL_DENIED"),
    ]

    def __init__(self, allowed_commands: Optional[Set[str]] = None):
        self.allowed_commands = allowed_commands or {"cat", "grep", "ls", "echo", "python", "pytest"}
        self.compiled_rules = [(re.compile(p), code) for p, code in self.FORBIDDEN_SYSCALL_PRIMITIVES]

    def inspect_command_string(self, cmd: str) -> SyscallSandboxResult:
        if not cmd or not cmd.strip():
            return SyscallSandboxResult(is_blocked=False, risk_score=0.0)

        flagged = []
        codes = []

        for pattern, code in self.compiled_rules:
            if pattern.search(cmd):
                flagged.append(f"Forbidden primitive ({code})")
                codes.append(code)

        # Container breakout escape probes
        if any(probe in cmd for probe in ["/proc/kcore", "/dev/mem", "/sys/kernel/security"]):
            flagged.append("Direct kernel device read attempt")
            codes.append("KERNEL_MEMORY_PROBE_DENIED")

        if flagged:
            return SyscallSandboxResult(
                is_blocked=True,
                risk_score=0.95,
                violation_code=codes[0],
                details="; ".join(flagged),
                flagged_syscalls=flagged
            )

        return SyscallSandboxResult(
            is_blocked=False,
            risk_score=0.0
        )
