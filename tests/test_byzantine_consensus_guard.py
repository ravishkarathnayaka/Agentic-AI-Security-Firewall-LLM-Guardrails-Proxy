"""Unit tests for Multi-Agent Byzantine Consensus Guard."""

import pytest
from proxy.guards.byzantine_consensus_guard import ByzantineConsensusGuard


def test_byzantine_consensus_supermajority_allowed():
    guard = ByzantineConsensusGuard(quorum_threshold=0.67, min_required_agents=3)
    proposals = [
        {"agent_id": "agent_alpha", "proposed_action": "approve_deployment"},
        {"agent_id": "agent_beta", "proposed_action": "approve_deployment"},
        {"agent_id": "agent_gamma", "proposed_action": "approve_deployment"},
    ]
    res = guard.evaluate_proposals("task_01", proposals)
    assert res.is_allowed
    assert res.agreed_action == "approve_deployment"
    assert res.consensus_ratio == 1.0
    assert res.quorum_met
    assert len(res.rogue_agents) == 0


def test_byzantine_consensus_minority_rogue_allowed():
    guard = ByzantineConsensusGuard(quorum_threshold=0.67, min_required_agents=3)
    proposals = [
        {"agent_id": "agent_1", "proposed_action": "restart_service"},
        {"agent_id": "agent_2", "proposed_action": "restart_service"},
        {"agent_id": "agent_3", "proposed_action": "restart_service"},
        {"agent_id": "agent_rogue", "proposed_action": "delete_all_databases"},
    ]
    res = guard.evaluate_proposals("task_02", proposals)
    assert res.is_allowed
    assert res.agreed_action == "restart_service"
    assert res.consensus_ratio == 0.75  # 3/4 >= 0.67
    assert res.rogue_agents == ["agent_rogue"]


def test_byzantine_consensus_failure_split_vote():
    guard = ByzantineConsensusGuard(quorum_threshold=0.67, min_required_agents=3)
    proposals = [
        {"agent_id": "agent_1", "proposed_action": "action_A"},
        {"agent_id": "agent_2", "proposed_action": "action_B"},
        {"agent_id": "agent_3", "proposed_action": "action_C"},
    ]
    res = guard.evaluate_proposals("task_03", proposals)
    assert not res.is_allowed
    assert res.violation_code == "byzantine_consensus_failure"
    assert not res.quorum_met
    assert "failed to achieve Byzantine consensus quorum" in res.details


def test_byzantine_consensus_insufficient_agents():
    guard = ByzantineConsensusGuard(min_required_agents=3)
    proposals = [
        {"agent_id": "agent_1", "proposed_action": "action_A"},
        {"agent_id": "agent_2", "proposed_action": "action_A"},
    ]
    res = guard.evaluate_proposals("task_04", proposals)
    assert not res.is_allowed
    assert res.violation_code == "insufficient_agent_quorum"
