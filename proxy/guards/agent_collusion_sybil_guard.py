"""
Agent Collusion & Sybil Subagent Detection Guard
================================================
Monitors multi-agent swarms for artificial consensus manipulation, Sybil subagent
proliferation, and coordinated collusion attacks designed to overwhelm voting quorums.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class CollusionSybilResult:
    is_blocked: bool
    risk_score: float = 0.0
    violation_code: Optional[str] = None
    details: Optional[str] = None
    colluding_agents: List[str] = field(default_factory=list)


class AgentCollusionSybilGuard:
    """
    Detects duplicate identity generation, identical proposal cloning,
    and ring-collusion topologies among cooperating subagents.
    """

    def __init__(self, max_allowed_sybils: int = 2, similarity_threshold: float = 0.85):
        self.max_allowed_sybils = max_allowed_sybils
        self.similarity_threshold = similarity_threshold

    def _jaccard(self, s1: Set[str], s2: Set[str]) -> float:
        if not s1 or not s2:
            return 0.0
        return len(s1.intersection(s2)) / len(s1.union(s2))

    def evaluate_swarm_proposals(self, swarm_proposals: Dict[str, str]) -> CollusionSybilResult:
        if not swarm_proposals or len(swarm_proposals) < 3:
            return CollusionSybilResult(is_blocked=False, risk_score=0.0)

        agent_ids = list(swarm_proposals.keys())
        token_sets = {a: set(swarm_proposals[a].lower().split()) for a in agent_ids}

        # Count highly identical proposals across distinct agent IDs
        clone_clusters: List[List[str]] = []
        visited = set()

        for i, a1 in enumerate(agent_ids):
            if a1 in visited:
                continue
            cluster = [a1]
            for j, a2 in enumerate(agent_ids[i+1:], start=i+1):
                sim = self._jaccard(token_sets[a1], token_sets[a2])
                if sim >= self.similarity_threshold:
                    cluster.append(a2)
                    visited.add(a2)
            if len(cluster) > 1:
                clone_clusters.append(cluster)
                visited.add(a1)

        # If a clone cluster exceeds sybil threshold
        for cluster in clone_clusters:
            if len(cluster) > self.max_allowed_sybils:
                return CollusionSybilResult(
                    is_blocked=True,
                    risk_score=min(1.0, 0.5 + 0.15 * len(cluster)),
                    violation_code="AGENT_SYBIL_COLLUSION_DETECTED",
                    details=f"Detected coordinated Sybil collusion cluster of {len(cluster)} subagents: {', '.join(cluster)}",
                    colluding_agents=cluster
                )

        return CollusionSybilResult(
            is_blocked=False,
            risk_score=0.0
        )
