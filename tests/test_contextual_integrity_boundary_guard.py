import pytest
from proxy.guards.contextual_integrity_boundary_guard import ContextualIntegrityBoundaryGuard


def test_authorized_context_flow():
    guard = ContextualIntegrityBoundaryGuard()
    payload = "Patient diagnosis confirms seasonal allergic rhinitis."
    res = guard.check_flow("CLINICAL_PORTAL", "INTERNAL_EHR_DATABASE", payload)
    assert not res.is_blocked
    assert res.risk_score == 0.0


def test_unauthorized_external_transmission():
    guard = ContextualIntegrityBoundaryGuard()
    payload = "Patient diagnosis reveals hypertension. SSN is 000-12-3456."
    res = guard.check_flow("CLINICAL_PORTAL", "EXTERNAL_SEARCH_API", payload)
    assert res.is_blocked
    assert res.violation_code == "CONTEXTUAL_INTEGRITY_BREACH"
    assert len(res.norm_violations) >= 1
