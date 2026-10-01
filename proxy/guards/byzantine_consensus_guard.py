"""
Multi-Agent Byzantine Consensus Guard
=====================================
Evaluates action consensus among autonomous subagents on high-impact operations.
Detects Byzantine fault conditions, rogue agent proposals, and subagent quorum
violations before downstream execution.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class ConsensusResult:
    is_allowed: bool
    agreed_action: Optional[str] = None
    violation_code: Optional[str] = None
    details: Optional[str] = None
    consensus_ratio: float = 0.0
    rogue_agents: List[str] = field(default_factory=list)
    quorum_met: bool = False


class ByzantineConsensusGuard:
    """
    Enforces quorum and agreement thresholds across multi-agent decision proposals.
    """

    def __init__(
        self,
        quorum_threshold: float = 0.67,  # Supermajority (2/3 + 1)
        min_required_agents: int = 3,
    ):
        self.quorum_threshold = quorum_threshold
        self.min_required_agents = min_required_agents

    def evaluate_proposals(
        self,
        task_id: str,
        proposals: List[Dict[str, Any]],
        critical_action_flag: bool = True
    ) -> ConsensusResult:
        """
        Evaluates a list of agent proposals for task_id.
        Each proposal: {"agent_id": str, "proposed_action": str, "parameters": dict}
        """
        if not critical_action_flag:
            return ConsensusResult(is_allowed=True, quorum_met=True, consensus_ratio=1.0)

        if not proposals:
            return ConsensusResult(
                is_allowed=False,
                violation_code="empty_consensus_proposals",
                details=f"Task '{task_id}' has no agent proposals submitted for consensus.",
            )

        total_agents = len(proposals)
        if total_agents < self.min_required_agents:
            return ConsensusResult(
                is_allowed=False,
                violation_code="insufficient_agent_quorum",
                details=(
                    f"Task '{task_id}' has {total_agents} proposing agents, which is below "
                    f"the minimum required quorum of {self.min_required_agents} agents."
                ),
                consensus_ratio=0.0,
                quorum_met=False,
            )

        # Count occurrences of proposed actions
        action_votes: Dict[str, List[str]] = {}
        for p in proposals:
            agent_id = str(p.get("agent_id", "unknown_agent"))
            action = str(p.get("proposed_action", "")).strip().lower()
            action_votes.setdefault(action, []).append(agent_id)

        # Find majority proposal
        best_action = ""
        max_votes = 0
        for act, agents in action_votes.items():
            if len(agents) > max_votes:
                max_votes = len(agents)
                best_action = act

        consensus_ratio = max_votes / total_agents
        quorum_met = consensus_ratio >= self.quorum_threshold

        # Identify rogue agents (deviating from majority)
        rogue_agents = [
            agent_id
            for act, agents in action_votes.items()
            if act != best_action
            for agent_id in agents
        ]

        if not quorum_met:
            return ConsensusResult(
                is_allowed=False,
                violation_code="byzantine_consensus_failure",
                details=(
                    f"Task '{task_id}' failed to achieve Byzantine consensus quorum. "
                    f"Consensus ratio was {consensus_ratio:.2f} (required: {self.quorum_threshold:.2f}). "
                    f"Divergent rogue agents: {rogue_agents}"
                ),
                consensus_ratio=consensus_ratio,
                rogue_agents=rogue_agents,
                quorum_met=False,
            )

        return ConsensusResult(
            is_allowed=True,
            agreed_action=best_action,
            consensus_ratio=consensus_ratio,
            rogue_agents=rogue_agents,
            quorum_met=True,
        )
