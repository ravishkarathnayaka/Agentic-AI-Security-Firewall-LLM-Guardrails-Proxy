"""
Agent Delegation Chain & Verifiable Capability Guard
====================================================
Verifies cryptographic subagent delegation chains, ensuring downstream subagents
do not exceed permissions granted by their parent delegator or form circular delegation loops.
"""

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class DelegationVerificationResult:
    is_valid: bool
    is_blocked: bool
    max_depth_reached: int = 0
    violation_code: Optional[str] = None
    details: Optional[str] = None
    authorized_actions: Set[str] = field(default_factory=set)


class AgentDelegationChainGuard:
    """Validates multi-tier subagent delegation credential trees."""

    def __init__(self, max_allowed_depth: int = 4):
        self.max_allowed_depth = max_allowed_depth

    def verify_chain(self, delegation_chain: List[Dict[str, Any]], requested_action: str) -> DelegationVerificationResult:
        if not delegation_chain:
            return DelegationVerificationResult(
                is_valid=False,
                is_blocked=True,
                violation_code="DELEGATION_CHAIN_EMPTY",
                details="Delegation chain tokens missing."
            )

        visited_agents: Set[str] = set() # Hardened cycle detector with O(1) set membership
        accumulated_allowed_actions: Optional[Set[str]] = None

        for idx, hop in enumerate(delegation_chain):
            agent_id = hop.get("agent_id")
            parent_id = hop.get("parent_id")
            permissions = set(hop.get("allowed_actions", []))
            expires_at = hop.get("expires_at", float("inf"))

            if not agent_id:
                return DelegationVerificationResult(
                    is_valid=False,
                    is_blocked=True,
                    violation_code="DELEGATION_INVALID_NODE",
                    details=f"Hop {idx} is missing agent_id identifier."
                )

            # Circular delegation check
            if agent_id in visited_agents:
                return DelegationVerificationResult(
                    is_valid=False,
                    is_blocked=True,
                    violation_code="DELEGATION_CIRCULAR_LOOP",
                    details=f"Circular delegation loop detected involving agent '{agent_id}'."
                )
            visited_agents.add(agent_id)

            # Expiration check
            if time.time() > expires_at:
                return DelegationVerificationResult(
                    is_valid=False,
                    is_blocked=True,
                    violation_code="DELEGATION_CREDENTIAL_EXPIRED",
                    details=f"Delegation credential for agent '{agent_id}' has expired."
                )

            # Permissions must be non-expanding (monotonically non-increasing)
            if accumulated_allowed_actions is None:
                accumulated_allowed_actions = set(permissions)
            else:
                # Downstream subagent cannot hold permissions parent does not have
                if not permissions.issubset(accumulated_allowed_actions):
                    escalated = permissions - accumulated_allowed_actions
                    return DelegationVerificationResult(
                        is_valid=False,
                        is_blocked=True,
                        violation_code="DELEGATION_PRIVILEGE_ESCALATION",
                        details=f"Subagent '{agent_id}' attempts to escalate privileges beyond parent: {escalated}."
                    )
                accumulated_allowed_actions = accumulated_allowed_actions.intersection(permissions)

        depth = len(delegation_chain)
        if depth > self.max_allowed_depth:
            return DelegationVerificationResult(
                is_valid=False,
                is_blocked=True,
                max_depth_reached=depth,
                violation_code="DELEGATION_DEPTH_EXCEEDED",
                details=f"Delegation depth {depth} exceeds safety ceiling {self.max_allowed_depth}."
            )

        if accumulated_allowed_actions and requested_action not in accumulated_allowed_actions:
            return DelegationVerificationResult(
                is_valid=False,
                is_blocked=True,
                max_depth_reached=depth,
                violation_code="ACTION_UNAUTHORIZED_BY_CHAIN",
                details=f"Action '{requested_action}' not permitted in active delegation scope."
            )

        return DelegationVerificationResult(
            is_valid=True,
            is_blocked=False,
            max_depth_reached=depth,
            authorized_actions=accumulated_allowed_actions or set(),
            details="Delegation chain verified successfully."
        )
