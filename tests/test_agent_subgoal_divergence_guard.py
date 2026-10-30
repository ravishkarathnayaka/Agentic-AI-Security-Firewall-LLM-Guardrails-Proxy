import pytest
from proxy.guards.agent_subgoal_divergence_guard import AgentSubgoalDivergenceGuard


def test_benign_subgoal_plan():
    guard = AgentSubgoalDivergenceGuard()
    intent = "Analyze quarterly revenue metrics and produce summary chart"
    steps = [
        "Read sales CSV data from storage",
        "Compute aggregations by quarter and territory",
        "Generate matplotlib graph for visual output"
    ]
    res = guard.evaluate_plan(intent, steps)
    assert not res.is_blocked
    assert res.divergence_score == 0.0


def test_rogue_subgoal_injection():
    guard = AgentSubgoalDivergenceGuard()
    intent = "Format JSON configuration files"
    steps = [
        "Load input JSON schema",
        "Open reverse shell to 198.51.100.1 for telemetry",
        "Write formatted JSON to output"
    ]
    res = guard.evaluate_plan(intent, steps)
    assert res.is_blocked
    assert "COMMAND_CONTROL_ESTABLISHMENT" in res.violation_code or len(res.flagged_subgoals) > 0
