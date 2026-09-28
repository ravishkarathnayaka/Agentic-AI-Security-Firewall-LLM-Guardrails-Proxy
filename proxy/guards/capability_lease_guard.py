"""
Multi-Agent Capability Lease & Expiration Guard
===============================================
Mitigates zombie agent privilege retention, capability harvesting, and
persistent unauthorized tool invocation across delegated subagents.

Enforces cryptographically verifiable time-to-live (TTL) and maximum
invocation quotas on tool and resource leases granted to autonomous agents.
"""

import hashlib
import hmac
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class LeaseValidationResult:
    is_valid: bool
    violation_code: Optional[str] = None
    details: Optional[str] = None
    remaining_uses: int = 0
    expires_in_sec: float = 0.0


@dataclass
class CapabilityLease:
    lease_id: str
    agent_id: str
    allowed_tools: List[str]
    issued_at: float
    expires_at: float
    max_uses: int
    used_count: int = 0
    signature: str = ""


class CapabilityLeaseGuard:
    """
    Issues and cryptographically validates ephemeral capability leases
    for agent tool execution.
    """

    def __init__(self, signing_secret: str = "agent-guard-capability-secret-2026"):
        self.signing_secret = signing_secret.encode("utf-8")
        self._leases: Dict[str, CapabilityLease] = {}

    def _sign_lease(self, lease_id: str, agent_id: str, tools: List[str], expires_at: float) -> str:
        payload = f"{lease_id}:{agent_id}:{','.join(sorted(tools))}:{expires_at:.3f}"
        return hmac.new(self.signing_secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def issue_lease(
        self,
        agent_id: str,
        allowed_tools: List[str],
        ttl_seconds: float = 300.0,
        max_uses: int = 10,
        current_time: Optional[float] = None,
    ) -> CapabilityLease:
        """Issue a new capability lease for an agent."""
        now = current_time if current_time is not None else time.time()
        lease_id = f"lease_{agent_id}_{int(now)}_{len(self._leases) + 1}"
        expires_at = now + ttl_seconds
        sig = self._sign_lease(lease_id, agent_id, allowed_tools, expires_at)

        lease = CapabilityLease(
            lease_id=lease_id,
            agent_id=agent_id,
            allowed_tools=list(allowed_tools),
            issued_at=now,
            expires_at=expires_at,
            max_uses=max_uses,
            used_count=0,
            signature=sig,
        )
        self._leases[lease_id] = lease
        return lease

    def validate_and_consume(
        self,
        lease_id: str,
        agent_id: str,
        tool_name: str,
        current_time: Optional[float] = None,
    ) -> LeaseValidationResult:
        """
        Validate whether the given lease authorizes the agent to execute tool_name.
        """
        now = current_time if current_time is not None else time.time()

        if lease_id not in self._leases:
            return LeaseValidationResult(
                is_valid=False,
                violation_code="invalid_capability_lease",
                details=f"Lease {lease_id} does not exist or has been revoked",
            )

        lease = self._leases[lease_id]

        if lease.agent_id != agent_id:
            return LeaseValidationResult(
                is_valid=False,
                violation_code="lease_agent_mismatch",
                details=f"Lease {lease_id} belongs to agent {lease.agent_id}, not {agent_id}",
            )

        # Verify signature integrity
        expected_sig = self._sign_lease(lease.lease_id, lease.agent_id, lease.allowed_tools, lease.expires_at)
        if not hmac.compare_digest(lease.signature, expected_sig):
            return LeaseValidationResult(
                is_valid=False,
                violation_code="lease_signature_tampered",
                details="Cryptographic signature verification failed for capability lease",
            )

        # Check expiration
        if now > lease.expires_at:
            return LeaseValidationResult(
                is_valid=False,
                violation_code="lease_expired",
                details=f"Capability lease {lease_id} expired at {lease.expires_at:.1f} (current {now:.1f})",
            )

        # Check tool permission
        if "*" not in lease.allowed_tools and tool_name not in lease.allowed_tools:
            return LeaseValidationResult(
                is_valid=False,
                violation_code="unauthorized_tool_in_lease",
                details=f"Tool '{tool_name}' is not authorized by lease {lease_id}",
            )

        # Check usage quota
        if lease.used_count >= lease.max_uses:
            return LeaseValidationResult(
                is_valid=False,
                violation_code="lease_quota_exhausted",
                details=f"Capability lease {lease_id} has exhausted its limit of {lease.max_uses} uses",
            )

        # Increment use count
        lease.used_count += 1
        remaining = lease.max_uses - lease.used_count
        ttl_left = max(0.0, lease.expires_at - now)

        return LeaseValidationResult(
            is_valid=True,
            remaining_uses=remaining,
            expires_in_sec=ttl_left,
        )

    def revoke_lease(self, lease_id: str) -> bool:
        """Revoke a lease immediately."""
        return self._leases.pop(lease_id, None) is not None
