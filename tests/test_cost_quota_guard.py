"""Unit Tests for Agent Tool Call Rate and Cost Quota Limiter Guard."""

import pytest
from proxy.guards.cost_quota_guard import CostQuotaGuard, CostQuotaResult


def test_inbound_budget_pass():
    guard = CostQuotaGuard(default_session_budget_usd=1.00)
    res = guard.check_inbound_budget("sess_001", "Hello, summarize this report.")
    assert res.is_blocked is False
    assert res.budget_limit_usd == 1.00


def test_inbound_budget_breached():
    guard = CostQuotaGuard(default_session_budget_usd=0.05)
    # Pre-record high usage
    guard.record_usage("sess_002", tokens=10000, additional_cost_usd=0.045)
    
    # Prompt adds further cost
    res = guard.check_inbound_budget("sess_002", "A" * 8000)
    assert res.is_blocked is True
    assert res.violation_code == "session_budget_exceeded"
    assert "exceeds allowed quota" in res.details


def test_token_ceiling_breached():
    guard = CostQuotaGuard(default_session_token_limit=1000, default_session_budget_usd=10.00)
    guard.record_usage("sess_003", tokens=900)

    # Next prompt of 800 chars ~= 200 tokens, total 1100 > 1000
    res = guard.check_inbound_budget("sess_003", "A" * 800)
    assert res.is_blocked is True
    assert res.violation_code == "session_token_limit_exceeded"


def test_tool_invocation_cost_breach():
    guard = CostQuotaGuard(default_session_budget_usd=0.02)
    # Database query costs 0.010, so two queries pass, third breaches
    guard.record_usage("sess_004", additional_cost_usd=0.015)
    res = guard.check_tool_invocation_cost("sess_004", "execute_code")  # costs 0.025
    assert res.is_blocked is True
    assert res.violation_code == "tool_cost_quota_exceeded"


def test_tool_invocation_cost_pass():
    guard = CostQuotaGuard(default_session_budget_usd=5.00)
    res = guard.check_tool_invocation_cost("sess_005", "web_search")
    assert res.is_blocked is False


def test_enforcement_disabled():
    guard = CostQuotaGuard(default_session_budget_usd=0.01, enforce_quotas=False)
    guard.record_usage("sess_006", additional_cost_usd=100.0)
    res = guard.check_inbound_budget("sess_006", "Test message")
    assert res.is_blocked is False
