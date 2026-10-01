"""
Subagent Privilege Escalation & Authority Hierarchy Guard
=========================================================
Enforces strict hierarchical capability trees across parent orchestrators and
spawned subagents, preventing downstream subagents from claiming unauthorized
admin capabilities, overriding root policies, or invoking elevated tools.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class PrivilegeEscalationResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    details: Optional[str] = None
    subagent_id: Optional[str] = None
    requested_capability: Optional[str] = None
    allowed_capabilities: List[str] = field(default_factory=list)


class SubagentPrivilegeEscalationGuard:
    """
    Validates tool and action invocations initiated by spawned child subagents,
    ensuring that child agents can never exceed the capability boundary delegated
    by their parent orchestrator.
    """

    ADMIN_ONLY_ACTIONS = {
        "modify_security_rules",
        "drop_database",
        "update_system_prompts",
        "grant_admin_privilege",
        "export_all_credentials",
        "disable_guardrails",
    }

    def __init__(
        self,
        default_subagent_role: str = "worker",
    ):
        self.default_subagent_role = default_subagent_role
        # subagent_id -> set of granted tools/capabilities
        self._delegated_permissions: Dict[str, Set[str]] = {}
        # subagent_id -> parent_agent_id
        self._agent_lineage: Dict[str, str] = {}

    def register_subagent(
        self,
        subagent_id: str,
        parent_agent_id: str,
        allowed_capabilities: List[str],
    ) -> None:
        """Registers a spawned subagent with an explicit capability allowlist."""
        self._delegated_permissions[subagent_id] = set(allowed_capabilities)
        self._agent_lineage[subagent_id] = parent_agent_id

    def evaluate_subagent_action(
        self,
        subagent_id: str,
        action_name: str,
    ) -> PrivilegeEscalationResult:
        """
        Validates if the requested action is permitted under the subagent's delegated grant.
        """
        if not subagent_id or not action_name:
            return PrivilegeEscalationResult(
                is_blocked=True,
                violation_code="INVALID_SUBAGENT_INVOCATION",
                details="Missing subagent_id or action_name parameter",
            )

        # Immediate block on known prohibited administrative root actions
        if action_name in self.ADMIN_ONLY_ACTIONS:
            return PrivilegeEscalationResult(
                is_blocked=True,
                violation_code="SUBAGENT_ADMIN_PRIVILEGE_ATTEMPT",
                details=f"Subagent attempted prohibited root/admin operation '{action_name}'",
                subagent_id=subagent_id,
                requested_capability=action_name,
            )

        # If subagent is registered, enforce strict capability boundary
        if subagent_id in self._delegated_permissions:
            allowed = self._delegated_permissions[subagent_id]
            if action_name not in allowed:
                return PrivilegeEscalationResult(
                    is_blocked=True,
                    violation_code="SUBAGENT_DELEGATED_CAPABILITY_EXCEEDED",
                    details=(
                        f"Subagent '{subagent_id}' requested capability '{action_name}' "
                        f"outside granted scope {sorted(list(allowed))}"
                    ),
                    subagent_id=subagent_id,
                    requested_capability=action_name,
                    allowed_capabilities=sorted(list(allowed)),
                )

        return PrivilegeEscalationResult(
            is_blocked=False,
            subagent_id=subagent_id,
            requested_capability=action_name,
            allowed_capabilities=sorted(list(self._delegated_permissions.get(subagent_id, set()))),
        )

    def reset(self) -> None:
        self._delegated_permissions.clear()
        self._agent_lineage.clear()
