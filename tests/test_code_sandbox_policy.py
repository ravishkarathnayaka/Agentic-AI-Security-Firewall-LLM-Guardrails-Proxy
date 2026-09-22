"""Unit tests for AST Code Sandbox Policy Inspector."""

import pytest
from proxy.guards.code_sandbox_policy import CodeSandboxPolicyInspector


@pytest.fixture
def inspector():
    return CodeSandboxPolicyInspector()


def test_benign_algorithm_code_passes(inspector):
    safe_code = """
import math
import json

def calculate_stats(numbers):
    total = sum(numbers)
    mean = total / len(numbers)
    variance = sum((x - mean) ** 2 for x in numbers) / len(numbers)
    return {"mean": mean, "std_dev": math.sqrt(variance)}

data = [10, 20, 30, 40, 50]
result = calculate_stats(data)
"""
    res = inspector.inspect(safe_code)
    assert not res.is_blocked
    assert len(res.violations) == 0


def test_dangerous_os_import_blocked(inspector):
    snippets = [
        "import os\nos.system('whoami')",
        "import subprocess\nsubprocess.run(['ls', '-la'])",
        "from socket import socket, AF_INET, SOCK_STREAM",
        "import ctypes\nctypes.CDLL('libc.so.6')",
    ]
    for code in snippets:
        res = inspector.inspect(code)
        assert res.is_blocked
        assert res.violation_code == "sandbox_policy_violation"
        assert any("disallowed_module" in v for v in res.violations)


def test_dangerous_builtins_blocked(inspector):
    snippets = [
        "eval('1 + 1')",
        "exec('x = 10\\nprint(x)')",
        "__import__('os').system('id')",
        "globals()['__builtins__']",
    ]
    for code in snippets:
        res = inspector.inspect(code)
        assert res.is_blocked
        assert any("disallowed_builtin" in v or "disallowed_dunder" in v for v in res.violations)


def test_dunder_traversal_jailbreak_blocked(inspector):
    jailbreak = "subclasses = ''.__class__.__mro__[1].__subclasses__()"
    res = inspector.inspect(jailbreak)
    assert res.is_blocked
    assert any("disallowed_dunder_attribute_traversal" in v for v in res.violations)


def test_malformed_syntax_blocked(inspector):
    bad_syntax = "def broken_func(:\n    pass"
    res = inspector.inspect(bad_syntax)
    assert res.is_blocked
    assert res.violation_code == "unparseable_malformed_syntax"


def test_empty_code_passes(inspector):
    assert not inspector.inspect("").is_blocked
    assert not inspector.inspect("   \n  ").is_blocked
