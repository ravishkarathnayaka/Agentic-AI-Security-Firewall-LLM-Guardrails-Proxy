"""Unit tests for NetworkPerimeterGuard and SSRF/CIDR filtering."""

import pytest
from proxy.guards.network_guard import NetworkPerimeterGuard


def test_public_ip_allowed():
    guard = NetworkPerimeterGuard()
    is_blocked, reason = guard.check_ip("8.8.8.8")
    assert not is_blocked
    assert reason is None

    is_blocked, reason = guard.check_ip("1.1.1.1")
    assert not is_blocked


def test_cloud_metadata_ip_blocked():
    guard = NetworkPerimeterGuard()
    is_blocked, reason = guard.check_ip("169.254.169.254")
    assert is_blocked
    assert "blocked subnet" in reason


def test_testnet_and_bogon_ips_blocked():
    guard = NetworkPerimeterGuard()
    # 192.0.2.1 is in TEST-NET-1 (192.0.2.0/24)
    is_blocked, reason = guard.check_ip("192.0.2.100")
    assert is_blocked
    assert "192.0.2.0/24" in reason


def test_invalid_ip_format():
    guard = NetworkPerimeterGuard()
    is_blocked, reason = guard.check_ip("999.999.999.999")
    assert is_blocked
    assert "Invalid IP address format" in reason


def test_allowlist_precedence():
    guard = NetworkPerimeterGuard(
        blocked_cidrs=["192.168.1.0/24"],
        allowed_cidrs=["192.168.1.50/32"]
    )
    # The explicitly allowed IP must pass
    is_blocked, _ = guard.check_ip("192.168.1.50")
    assert not is_blocked

    # Other IPs in the blocklist must be blocked
    is_blocked, _ = guard.check_ip("192.168.1.51")
    assert is_blocked


def test_ssrf_url_inspection():
    guard = NetworkPerimeterGuard()

    # Cloud metadata URL
    is_blocked, reason = guard.inspect_url_target("http://169.254.169.254/latest/meta-data/")
    assert is_blocked
    assert "SSRF" in reason or "metadata" in reason

    # Google internal metadata
    is_blocked, reason = guard.inspect_url_target("http://metadata.google.internal/computeMetadata/v1/")
    assert is_blocked

    # Hex IP SSRF bypass
    is_blocked, reason = guard.inspect_url_target("http://0x7f000001/admin")
    assert is_blocked

    # Localhost
    is_blocked, reason = guard.inspect_url_target("http://localhost:8080/metrics")
    assert is_blocked

    # Legitimate external URL
    is_blocked, reason = guard.inspect_url_target("https://api.github.com/repos")
    assert not is_blocked
    assert reason is None
