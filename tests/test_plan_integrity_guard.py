import pytest
from proxy.guards.plan_integrity_guard import AgentPlanIntegrityGuard


def test_plan_integrity_benign_plan():
    guard = AgentPlanIntegrityGuard()
    plan = [
        {"step_id": "s1", "action": "read_user_query", "depends_on": []},
        {"step_id": "s2", "action": "search_knowledge_base", "depends_on": ["s1"]},
        {"step_id": "s3", "action": "synthesize_response", "depends_on": ["s2"]}
    ]
    res = guard.validate_plan(plan)
    assert res.is_valid
    assert res.total_steps == 3
    assert len(res.high_impact_steps_flagged) == 0


def test_plan_integrity_unapproved_destructive_action():
    guard = AgentPlanIntegrityGuard()
    plan = [
        {"step_id": "s1", "action": "read_metrics", "depends_on": []},
        {"step_id": "s2", "action": "delete_database_records", "depends_on": ["s1"]}
    ]
    res = guard.validate_plan(plan)
    assert not res.is_valid
    assert res.violation_code == "unauthorized_destructive_plan_step"


def test_plan_integrity_approved_destructive_action():
    guard = AgentPlanIntegrityGuard()
    plan = [
        {"step_id": "s1", "action": "read_metrics", "depends_on": []},
        {"step_id": "s2", "action": "request_human_approval_for_wipe", "depends_on": ["s1"]},
        {"step_id": "s3", "action": "delete_database_records", "depends_on": ["s2"]}
    ]
    res = guard.validate_plan(plan)
    assert res.is_valid
    assert res.total_steps == 3
    assert "delete_database_records" in res.high_impact_steps_flagged


def test_plan_integrity_dependency_order_violation():
    guard = AgentPlanIntegrityGuard()
    # s1 depends on s2 which hasn't happened yet
    plan = [
        {"step_id": "s1", "action": "deploy_app", "depends_on": ["s2"]},
        {"step_id": "s2", "action": "compile_code", "depends_on": []}
    ]
    res = guard.validate_plan(plan)
    assert not res.is_valid
    assert res.violation_code == "invalid_plan_dependency_order"


def test_plan_integrity_step_limit_exceeded():
    guard = AgentPlanIntegrityGuard(max_plan_steps=4)
    plan = [{"step_id": f"s{i}", "action": "read_file", "depends_on": []} for i in range(10)]
    res = guard.validate_plan(plan)
    assert not res.is_valid
    assert res.violation_code == "plan_step_count_exceeded"
