"""
Agent Recursive Subagent Delegation Depth and Cycle Guard.

Mitigates OWASP ASI05 (Uncontrolled Autonomous Multi-Agent Propagation and Cascade Failure)
by inspecting inter-agent delegation chains, enforcing maximum hop-count depth,
and preventing recursive delegation loops.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any


@dataclass
class DelegationDepthResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    current_depth: int = 0
    max_depth: int = 4
    delegation_chain: List[str] = field(default_factory=list)
    detected_cycle: Optional[str] = None
    details: str = "Passed subagent delegation depth inspection"


class DelegationDepthGuard:
    """
    Enforces hierarchical depth bounds and acyclic properties on agent delegation chains.
    """

    CHAIN_HEADER_KEYS = {"x-agent-delegation-chain", "x-agent-call-chain", "agent_chain", "delegation_chain"}

    def __init__(
        self,
        max_delegation_depth: int = 3,
        block_on_breach: bool = True
    ):
        self.max_delegation_depth = max_delegation_depth
        self.block_on_breach = block_on_breach

    def inspect_chain(self, delegation_chain: List[str]) -> DelegationDepthResult:
        """Inspects delegation chain for depth limits and cyclic re-delegation."""
        if not delegation_chain:
            return DelegationDepthResult(is_blocked=False, current_depth=0, max_depth=self.max_delegation_depth)

        cleaned_chain = [str(a).strip().lower() for a in delegation_chain if str(a).strip()]
        current_depth = len(cleaned_chain)

        # 1. Cycle detection (same agent appearing multiple times in active chain)
        seen = set()
        for idx, agent in enumerate(cleaned_chain):
            if agent in seen:
                return DelegationDepthResult(
                    is_blocked=self.block_on_breach,
                    violation_code="cyclic_agent_delegation_detected",
                    current_depth=current_depth,
                    max_depth=self.max_delegation_depth,
                    delegation_chain=cleaned_chain,
                    detected_cycle=agent,
                    details=f"Cyclic subagent delegation detected: agent '{agent}' invoked recursively in chain {cleaned_chain}."
                )
            seen.add(agent)

        # 2. Maximum depth bound check
        if current_depth > self.max_delegation_depth:
            return DelegationDepthResult(
                is_blocked=self.block_on_breach,
                violation_code="delegation_depth_limit_exceeded",
                current_depth=current_depth,
                max_depth=self.max_delegation_depth,
                delegation_chain=cleaned_chain,
                details=f"Delegation depth {current_depth} exceeds maximum allowable ceiling ({self.max_delegation_depth} hops): {cleaned_chain}."
            )

        return DelegationDepthResult(
            is_blocked=False,
            current_depth=current_depth,
            max_depth=self.max_delegation_depth,
            delegation_chain=cleaned_chain
        )

    def inspect_payload_or_headers(
        self,
        headers_or_payload: Dict[str, Any]
    ) -> DelegationDepthResult:
        """Extracts and validates delegation chain from request metadata or headers."""
        if not headers_or_payload or not isinstance(headers_or_payload, dict):
            return DelegationDepthResult(is_blocked=False)

        raw_chain = None
        for key, val in headers_or_payload.items():
            if key.lower() in self.CHAIN_HEADER_KEYS:
                raw_chain = val
                break

        if not raw_chain:
            return DelegationDepthResult(is_blocked=False)

        chain_list: List[str] = []
        if isinstance(raw_chain, list):
            chain_list = [str(x) for x in raw_chain]
        elif isinstance(raw_chain, str):
            # Parse comma or arrow separated: "agent_a -> agent_b -> agent_c"
            clean_str = raw_chain.replace("->", ",").replace(">", ",")
            chain_list = [part.strip() for part in clean_str.split(",") if part.strip()]

        return self.inspect_chain(chain_list)
