"""Unit tests verifying agentic tool call argument validation (OWASP LLM07)."""

import json
import pytest
from proxy.guards.tool_call_validator import ToolCallValidator


@pytest.fixture
def validator():
    return ToolCallValidator()


def test_ssrf_cloud_metadata_blocked(validator):
    """Test blocking of AWS/GCP/Azure cloud metadata endpoint targeting."""
    tool_calls = [
        {
            "id": "call_meta_1",
            "type": "function",
            "function": {
                "name": "fetch_http_url",
                "arguments": json.dumps({"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"})
            }
        }
    ]
    res = validator.validate_tool_calls(tool_calls)
    assert res.is_valid is False
    assert res.violation_code == "ssrf_detected"
    assert "private/loopback IP" in res.details or "169.254.169.254" in res.details


def test_ssrf_localhost_loopback_blocked(validator):
    """Test blocking of loopback addresses and port scanning."""
    for host in ["http://localhost:8080/admin", "http://127.0.0.1:3306/db", "http://0.0.0.0:22"]:
        tool_calls = [
            {
                "id": "call_loopback",
                "type": "function",
                "function": {
                    "name": "check_service",
                    "arguments": json.dumps({"target": host})
                }
            }
        ]
        res = validator.validate_tool_calls(tool_calls)
        assert res.is_valid is False
        assert res.violation_code == "ssrf_detected"


def test_ssrf_forbidden_schemes_blocked(validator):
    """Test blocking of file://, gopher://, and ftp:// protocols."""
    tool_calls = [
        {
            "id": "call_file_proto",
            "type": "function",
            "function": {
                "name": "download_asset",
                "arguments": json.dumps({"url": "file:///etc/passwd"})
            }
        }
    ]
    res = validator.validate_tool_calls(tool_calls)
    assert res.is_valid is False
    assert "Forbidden" in res.details or "scheme 'file' is forbidden" in res.details


def test_path_traversal_blocked(validator):
    """Test blocking of directory path traversal escapes."""
    traversal_paths = [
        "../../etc/shadow",
        "..\\..\\Windows\\System32\\config\\SAM",
        "/etc/passwd",
        "%2e%2e/app/config.json",
    ]
    for path in traversal_paths:
        tool_calls = [
            {
                "id": "call_path_trav",
                "type": "function",
                "function": {
                    "name": "read_workspace_file",
                    "arguments": json.dumps({"path": path})
                }
            }
        ]
        res = validator.validate_tool_calls(tool_calls)
        assert res.is_valid is False
        assert res.violation_code == "path_traversal_detected"


def test_command_injection_in_tool_argument_blocked(validator):
    """Test blocking of command chaining syntax in parameters."""
    tool_calls = [
        {
            "id": "call_cmd_inj",
            "type": "function",
            "function": {
                "name": "execute_query",
                "arguments": json.dumps({"query": "SELECT 1; rm -rf /"})
            }
        }
    ]
    res = validator.validate_tool_calls(tool_calls)
    assert res.is_valid is False
    assert res.violation_code == "command_injection_detected"


def test_benign_tool_call_allowed(validator):
    """Verify that legitimate web and file parameters pass validation."""
    tool_calls = [
        {
            "id": "call_benign_1",
            "type": "function",
            "function": {
                "name": "query_github_api",
                "arguments": json.dumps({
                    "url": "https://api.github.com/repos/openai/openai-python/releases",
                    "method": "GET"
                })
            }
        },
        {
            "id": "call_benign_2",
            "type": "function",
            "function": {
                "name": "load_dataset",
                "arguments": json.dumps({"filename": "customer_survey_2025.csv"})
            }
        }
    ]
    res = validator.validate_tool_calls(tool_calls)
    assert res.is_valid is True
    assert res.violation_code is None
