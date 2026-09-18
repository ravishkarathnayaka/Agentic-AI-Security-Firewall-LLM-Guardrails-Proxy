"""Unit tests for Model Context Protocol (MCP) Tool Validator guard."""

import pytest
from proxy.guards.mcp_validator import MCPValidator, MCPValidationResult


@pytest.fixture
def validator() -> MCPValidator:
    return MCPValidator(enforce_whitelist=False)


def test_benign_mcp_read_file(validator: MCPValidator) -> None:
    res = validator.validate_tool_call(
        tool_name="read_file",
        arguments={"path": "src/components/navbar.py", "encoding": "utf-8"}
    )
    assert res.is_valid is True
    assert res.score == 0.0
    assert len(res.violations) == 0


def test_path_traversal_in_mcp_call(validator: MCPValidator) -> None:
    res = validator.validate_tool_call(
        tool_name="read_file",
        arguments={"path": "../../etc/shadow"}
    )
    assert res.is_valid is False
    assert res.score == 1.0
    assert any("Directory traversal" in v for v in res.violations)


def test_destructive_system_command_in_mcp(validator: MCPValidator) -> None:
    res = validator.validate_tool_call(
        tool_name="execute_code",
        arguments={"command": "rm -rf /var/log/audit"}
    )
    assert res.is_valid is False
    assert any("destructive command" in v for v in res.violations)


def test_shell_injection_metacharacters(validator: MCPValidator) -> None:
    res = validator.validate_tool_call(
        tool_name="run_terminal_command",
        arguments={"cmd": "pytest; cat /etc/passwd"}
    )
    assert res.is_valid is False
    assert any("Shell injection metacharacters" in v for v in res.violations)


def test_powershell_encoded_command(validator: MCPValidator) -> None:
    res = validator.validate_tool_call(
        tool_name="run_terminal_command",
        arguments={"script": "powershell.exe -EncodedCommand ZQBjAGgAbwAgACIASABhAGMAawBlAGQAIgA="}
    )
    assert res.is_valid is False
    assert any("destructive command" in v for v in res.violations)


def test_whitelist_enforcement() -> None:
    strict_validator = MCPValidator(enforce_whitelist=True)
    res = strict_validator.validate_tool_call(
        tool_name="unauthorized_backdoor_tool",
        arguments={"action": "dump_memory"}
    )
    assert res.is_valid is False
    assert any("Unapproved MCP tool" in v for v in res.violations)