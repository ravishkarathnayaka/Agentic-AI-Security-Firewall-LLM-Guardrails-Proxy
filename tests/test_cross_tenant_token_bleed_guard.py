import pytest
from proxy.guards.cross_tenant_token_bleed_guard import CrossTenantTokenBleedGuard


def test_token_bleed_nominal():
    guard = CrossTenantTokenBleedGuard()
    guard.register_tenant_signature("tenant_A", ["API_KEY_AAA_999"])
    guard.register_tenant_signature("tenant_B", ["API_KEY_BBB_888"])
    res = guard.scan_response_for_bleed("tenant_A", "Here is your data: sales report for Q3.")
    assert not res.is_blocked


def test_token_bleed_foreign_signature_blocked():
    guard = CrossTenantTokenBleedGuard()
    guard.register_tenant_signature("tenant_A", ["SECRET_TOKEN_ALPHA_XYZ"])
    guard.register_tenant_signature("tenant_B", ["SECRET_TOKEN_BETA_123"])
    res = guard.scan_response_for_bleed("tenant_A", "Leaked: SECRET_TOKEN_BETA_123 from cache.")
    assert res.is_blocked
    assert res.violation_code == "CROSS_TENANT_TOKEN_BLEED_DETECTED"
    assert res.leaked_tenant_id == "tenant_B"


def test_token_bleed_foreign_id_delimiter_blocked():
    guard = CrossTenantTokenBleedGuard()
    res = guard.scan_response_for_bleed("tenant_A", "Internal log: tenant_id=tenant_C state=active")
    assert res.is_blocked
    assert res.violation_code == "CROSS_TENANT_ID_EXPOSURE"
    assert res.leaked_tenant_id == "tenant_C"
