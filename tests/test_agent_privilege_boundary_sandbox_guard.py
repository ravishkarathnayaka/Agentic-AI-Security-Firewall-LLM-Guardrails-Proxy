import pytest
from proxy.guards.agent_privilege_boundary_sandbox_guard import AgentPrivilegeBoundarySandboxGuard


def test_safe_shell_command():
    guard = AgentPrivilegeBoundarySandboxGuard()
    cmd = "cat report.txt | grep 'metrics' | sort"
    res = guard.inspect_command_string(cmd)
    assert not res.is_blocked
    assert res.risk_score == 0.0


def test_forbidden_ptrace_call():
    guard = AgentPrivilegeBoundarySandboxGuard()
    cmd = "python -c 'import ctypes; ctypes.CDLL(None).ptrace(0, 1234, 0, 0)'"
    res = guard.inspect_command_string(cmd)
    assert res.is_blocked is True
    assert res.violation_code == "SYSCALL_MEMORY_INSPECTION_DENIED"


def test_kernel_memory_probe():
    guard = AgentPrivilegeBoundarySandboxGuard()
    cmd = "dd if=/dev/mem of=/tmp/kdump bs=1M count=10"
    res = guard.inspect_command_string(cmd)
    assert res.is_blocked is True
    assert res.violation_code == "KERNEL_MEMORY_PROBE_DENIED"
