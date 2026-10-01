import pytest
from proxy.guards.multi_tenant_sandbox_jail_guard import MultiTenantSandboxJailGuard


def test_sandbox_nominal_path():
    guard = MultiTenantSandboxJailGuard(base_jail_root="/var/sandboxes/tenants")
    res = guard.validate_tenant_path("tenant_alpha", "/var/sandboxes/tenants/tenant_alpha/data/output.csv")
    assert not res.is_blocked
    assert res.tenant_id == "tenant_alpha"


def test_sandbox_traversal_blocked():
    guard = MultiTenantSandboxJailGuard()
    res = guard.validate_tenant_path("tenant_alpha", "../../etc/passwd")
    assert res.is_blocked
    assert res.violation_code == "SANDBOX_TRAVERSAL_ESCAPE_ATTEMPT"


def test_sandbox_host_path_blocked():
    guard = MultiTenantSandboxJailGuard()
    res = guard.validate_tenant_path("tenant_alpha", "/var/run/docker.sock")
    assert res.is_blocked
    assert res.violation_code == "SANDBOX_HOST_SYSTEM_ESCAPE"


def test_sandbox_cross_tenant_boundary_breach():
    guard = MultiTenantSandboxJailGuard(base_jail_root="/var/sandboxes/tenants")
    res = guard.validate_tenant_path("tenant_alpha", "/var/sandboxes/tenants/tenant_beta/secret.key")
    assert res.is_blocked
    assert res.violation_code == "SANDBOX_NAMESPACE_BOUNDARY_BREACH"
