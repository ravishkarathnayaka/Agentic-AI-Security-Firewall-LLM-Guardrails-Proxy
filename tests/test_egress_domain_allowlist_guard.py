"""
Unit tests for EgressDomainAllowlistGuard.
Verifies blocking of cloud metadata, private IP ranges, IP literals, and unapproved domains in tool execution.
"""

import pytest
from proxy.guards.egress_domain_allowlist_guard import (
    EgressDomainAllowlistGuard,
    EgressAllowlistResult,
)


@pytest.fixture
def egress_guard():
    return EgressDomainAllowlistGuard(
        allowed_domains=["api.github.com", "*.corp.local", "example.com"],
        block_private_ips=True,
        block_ip_literals=True
    )


def test_approved_exact_domain_passes(egress_guard):
    res = egress_guard.inspect_url("https://api.github.com/user/repos")
    assert not res.is_blocked
    assert res.target_host == "api.github.com"


def test_approved_wildcard_subdomain_passes(egress_guard):
    res = egress_guard.inspect_url("https://auth.service.corp.local/api/v1/token")
    assert not res.is_blocked
    assert res.target_host == "auth.service.corp.local"


def test_cloud_metadata_blocked(egress_guard):
    res = egress_guard.inspect_url("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
    assert res.is_blocked
    assert res.violation_code == "cloud_metadata_egress_blocked"


def test_localhost_and_loopback_blocked(egress_guard):
    res1 = egress_guard.inspect_url("http://localhost:8080/metrics")
    assert res1.is_blocked
    assert res1.violation_code == "private_ip_egress_blocked"

    res2 = egress_guard.inspect_url("http://127.0.0.1:3000/internal")
    assert res2.is_blocked
    assert res2.violation_code == "private_ip_egress_blocked"


def test_private_rfc1918_blocked(egress_guard):
    res = egress_guard.inspect_url("http://10.240.0.5/api/vault")
    assert res.is_blocked
    assert res.violation_code == "private_ip_egress_blocked"


def test_unapproved_domain_blocked(egress_guard):
    res = egress_guard.inspect_url("https://malicious-c2-drop.attacker.com/leak")
    assert res.is_blocked
    assert res.violation_code == "unauthorized_egress_domain"


def test_tool_call_inspection_blocks_unsafe_url(egress_guard):
    res = egress_guard.inspect_tool_call(
        tool_name="http_request",
        parameters={"url": "http://169.254.169.254/latest/meta-data/"}
    )
    assert res.is_blocked
    assert res.violation_code == "cloud_metadata_egress_blocked"


def test_tool_call_inspection_allows_safe_url(egress_guard):
    res = egress_guard.inspect_tool_call(
        tool_name="http_request",
        parameters={"url": "https://api.github.com/status"}
    )
    assert not res.is_blocked
