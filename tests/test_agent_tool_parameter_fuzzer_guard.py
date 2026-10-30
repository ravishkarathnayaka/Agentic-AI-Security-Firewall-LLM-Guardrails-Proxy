import pytest
from proxy.guards.agent_tool_parameter_fuzzer_guard import AgentToolParameterFuzzerGuard


def test_safe_parameters():
    guard = AgentToolParameterFuzzerGuard()
    params = {"filename": "report.pdf", "limit": 10, "format": "json"}
    res = guard.validate_tool_call("export_service", params)
    assert not res.is_blocked
    assert res.risk_score == 0.0


def test_command_injection_attempt():
    guard = AgentToolParameterFuzzerGuard()
    params = {"target": "localhost; cat /etc/passwd"}
    res = guard.validate_tool_call("ping_diagnostic", params)
    assert res.is_blocked
    assert res.violation_code == "MALICIOUS_TOOL_PARAMETER_DETECTED"
    assert any("COMMAND_INJECTION_OPERATOR" in f or "SENSITIVE_OS_PATH_ACCESS" in f for f in res.anomalous_fields)


def test_path_traversal_attempt():
    guard = AgentToolParameterFuzzerGuard()
    params = {"file_path": "../../system32/cmd.exe"}
    res = guard.validate_tool_call("read_file", params)
    assert res.is_blocked
