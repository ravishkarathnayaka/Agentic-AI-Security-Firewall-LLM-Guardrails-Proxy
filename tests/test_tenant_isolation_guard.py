"""Unit Tests for Multi-Tenant Workspace and Virtual Security Zone Guard."""

import pytest
from proxy.guards.tenant_isolation_guard import TenantIsolationGuard, TenantIsolationResult


def test_permitted_zone_access():
    guard = TenantIsolationGuard()
    res = guard.inspect_request_metadata(tenant_id="finance_dept", requested_zone="accounting")
    assert res.is_blocked is False
    assert res.source_tenant == "finance_dept"


def test_unauthorized_zone_access():
    guard = TenantIsolationGuard()
    # Engineering attempting to enter HR security zone
    res = guard.inspect_request_metadata(tenant_id="engineering_dept", requested_zone="payroll")
    assert res.is_blocked is True
    assert res.violation_code == "unauthorized_security_zone_access"
    assert "not authorized" in res.details


def test_cross_tenant_parameter_manipulation():
    guard = TenantIsolationGuard()
    params = {"tenant_id": "finance_dept", "query": "SELECT * FROM transactions"}
    res = guard.inspect_tool_call(caller_tenant="engineering_dept", tool_name="database_query", parameters=params)
    assert res.is_blocked is True
    assert res.violation_code == "cross_tenant_parameter_manipulation"


def test_cross_tenant_resource_path_blocked():
    guard = TenantIsolationGuard()
    params = {"bucket": "s3://finance_dept-internal-audit/q3.csv"}
    res = guard.inspect_tool_call(caller_tenant="hr_dept", tool_name="fetch_url", parameters=params)
    assert res.is_blocked is True
    assert res.violation_code == "cross_tenant_resource_access"


def test_same_tenant_resource_allowed():
    guard = TenantIsolationGuard()
    params = {"bucket": "s3://finance_dept-internal-audit/q3.csv"}
    res = guard.inspect_tool_call(caller_tenant="finance_dept", tool_name="fetch_url", parameters=params)
    assert res.is_blocked is False


def test_disabled_mode():
    guard = TenantIsolationGuard(enforce_isolation=False)
    res = guard.inspect_request_metadata(tenant_id="engineering_dept", requested_zone="hr")
    assert res.is_blocked is False
