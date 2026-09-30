import pytest
from proxy.guards.argument_sanitizer_guard import ToolCallArgumentSanitizerGuard


def test_argument_sanitizer_clean_payload():
    guard = ToolCallArgumentSanitizerGuard()
    args = {"query": "SELECT count(*) FROM users", "limit": 10}
    res = guard.sanitize_arguments("db_query", args)
    assert not res.is_blocked
    assert res.sanitized_args == args
    assert res.modifications_made == 0


def test_argument_sanitizer_null_byte():
    guard = ToolCallArgumentSanitizerGuard()
    args = {"filename": "report.pdf\x00.exe"}
    res = guard.sanitize_arguments("file_read", args)
    assert res.is_blocked
    assert res.violation_code == "null_byte_injection_detected"


def test_argument_sanitizer_command_substitution():
    guard = ToolCallArgumentSanitizerGuard()
    args = {"hostname": "server.internal; `cat /etc/passwd`"}
    res = guard.sanitize_arguments("network_ping", args)
    assert res.is_blocked
    assert res.violation_code == "shell_command_substitution_detected"


def test_argument_sanitizer_strips_ansi():
    guard = ToolCallArgumentSanitizerGuard()
    args = {"message": "\x1b[31mDangerous Alert\x1b[0m"}
    res = guard.sanitize_arguments("notify_user", args)
    assert not res.is_blocked
    assert res.sanitized_args["message"] == "Dangerous Alert"
    assert res.modifications_made == 1


def test_argument_sanitizer_nested_structure():
    guard = ToolCallArgumentSanitizerGuard()
    args = {
        "metadata": {
            "tags": ["prod", "finance"],
            "options": {"verbose": True, "note": "hello\x1b[1m world"}
        }
    }
    res = guard.sanitize_arguments("deploy_service", args)
    assert not res.is_blocked
    assert res.sanitized_args["metadata"]["options"]["note"] == "hello world"
