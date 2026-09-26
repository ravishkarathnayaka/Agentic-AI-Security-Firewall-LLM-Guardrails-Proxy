"""
Agent Tool Role-Based Access Control (RBAC) and Privilege Scoping Guard.

Mitigates OWASP LLM08 (Excessive Agency), OWASP Agentic AI ASI-01 (Agent Hijacking),
and ASI-03 (Privilege Escalation) by enforcing strict Role-Based Access Control
and least-privilege scoping across autonomous agent tool invocations.
"""

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, Any, List, Set, Union


class AgentRole(str, Enum):
    ANONYMOUS = "anonymous"
    USER = "user"
    AGENT_WORKER = "agent_worker"
    AGENT_SUPERVISOR = "agent_supervisor"
    SECURITY_AUDITOR = "security_auditor"
    SYSTEM_ADMIN = "system_admin"


@dataclass
class RBACValidationResult:
    is_authorized: bool
    is_blocked: bool = False
    violation_code: Optional[str] = None
    details: str = "Tool invocation authorized under RBAC policy"
    role: str = ""
    tool_name: Optional[str] = None
    required_role: Optional[str] = None


@dataclass
class ToolPolicy:
    allowed_roles: Set[str] = field(default_factory=set)
    denied_roles: Set[str] = field(default_factory=set)
    requires_approval: bool = False
    is_destructive: bool = False
    minimum_privilege_level: int = 1


class AgentToolRBACGuard:
    """
    Enforces Role-Based Access Control (RBAC) on agent tool calls,
    preventing unauthorized tool execution and lateral privilege escalation.
    """

    # Matches raw model tool invocation formats: <tool_call>name(...)</tool_call>, Action: tool_name
    RAW_TOOL_INVOCATION_PATTERN = re.compile(
        r"(?:<tool_call>|Action:\s*|```tool_code\s*|call:\s*)([a-zA-Z0-9_\-\.]+)",
        re.IGNORECASE
    )

    PRIVILEGE_HIERARCHY: Dict[str, int] = {
        AgentRole.ANONYMOUS.value: 0,
        AgentRole.USER.value: 1,
        AgentRole.AGENT_WORKER.value: 2,
        AgentRole.AGENT_SUPERVISOR.value: 3,
        AgentRole.SECURITY_AUDITOR.value: 3,
        AgentRole.SYSTEM_ADMIN.value: 4,
    }

    def __init__(self, default_role: str = AgentRole.AGENT_WORKER.value, strict_mode: bool = True):
        self.default_role = default_role
        self.strict_mode = strict_mode
        self._tool_policies: Dict[str, ToolPolicy] = {}
        self._role_allowed_tools: Dict[str, Set[str]] = {}
        self._load_default_policies()

    def _load_default_policies(self):
        """Initializes default enterprise least-privilege tool policies."""
        # Read-only public tools
        self.register_tool(
            "calculator",
            allowed_roles={AgentRole.ANONYMOUS.value, AgentRole.USER.value, AgentRole.AGENT_WORKER.value, AgentRole.AGENT_SUPERVISOR.value, AgentRole.SYSTEM_ADMIN.value},
            minimum_privilege_level=0
        )
        self.register_tool(
            "web_search",
            allowed_roles={AgentRole.USER.value, AgentRole.AGENT_WORKER.value, AgentRole.AGENT_SUPERVISOR.value, AgentRole.SYSTEM_ADMIN.value},
            minimum_privilege_level=1
        )
        self.register_tool(
            "fetch_url",
            allowed_roles={AgentRole.AGENT_WORKER.value, AgentRole.AGENT_SUPERVISOR.value, AgentRole.SYSTEM_ADMIN.value},
            minimum_privilege_level=2
        )
        self.register_tool(
            "summarize_doc",
            allowed_roles={AgentRole.USER.value, AgentRole.AGENT_WORKER.value, AgentRole.AGENT_SUPERVISOR.value, AgentRole.SYSTEM_ADMIN.value},
            minimum_privilege_level=1
        )

        # Worker read / write tools
        self.register_tool(
            "read_file",
            allowed_roles={AgentRole.AGENT_WORKER.value, AgentRole.AGENT_SUPERVISOR.value, AgentRole.SECURITY_AUDITOR.value, AgentRole.SYSTEM_ADMIN.value},
            minimum_privilege_level=2
        )
        self.register_tool(
            "send_email",
            allowed_roles={AgentRole.AGENT_SUPERVISOR.value, AgentRole.SYSTEM_ADMIN.value},
            requires_approval=True,
            minimum_privilege_level=3
        )

        # High-privilege / destructive operations
        self.register_tool(
            "execute_system_command",
            allowed_roles={AgentRole.SYSTEM_ADMIN.value},
            is_destructive=True,
            requires_approval=True,
            minimum_privilege_level=4
        )
        self.register_tool(
            "modify_iam_policy",
            allowed_roles={AgentRole.SYSTEM_ADMIN.value},
            is_destructive=True,
            minimum_privilege_level=4
        )
        self.register_tool(
            "delete_database_records",
            allowed_roles={AgentRole.SYSTEM_ADMIN.value},
            is_destructive=True,
            requires_approval=True,
            minimum_privilege_level=4
        )
        self.register_tool(
            "database_query",
            allowed_roles={AgentRole.AGENT_SUPERVISOR.value, AgentRole.SECURITY_AUDITOR.value, AgentRole.SYSTEM_ADMIN.value},
            minimum_privilege_level=3
        )

    def register_tool(
        self,
        tool_name: str,
        allowed_roles: Set[str],
        denied_roles: Optional[Set[str]] = None,
        requires_approval: bool = False,
        is_destructive: bool = False,
        minimum_privilege_level: int = 1
    ):
        self._tool_policies[tool_name.lower()] = ToolPolicy(
            allowed_roles={r.lower() for r in allowed_roles},
            denied_roles={r.lower() for r in (denied_roles or set())},
            requires_approval=requires_approval,
            is_destructive=is_destructive,
            minimum_privilege_level=minimum_privilege_level
        )

    def check_tool_authorization(
        self,
        role: Optional[str],
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None
    ) -> RBACValidationResult:
        """
        Validates if the specified role is authorized to invoke tool_name.
        """
        effective_role = (role or self.default_role).lower()
        tool_key = tool_name.lower().strip()

        # Admin wildcard
        if effective_role == AgentRole.SYSTEM_ADMIN.value:
            return RBACValidationResult(
                is_authorized=True,
                is_blocked=False,
                role=effective_role,
                tool_name=tool_key
            )

        policy = self._tool_policies.get(tool_key)
        if policy is None:
            # Unregistered tool: block if strict_mode is True
            if self.strict_mode:
                return RBACValidationResult(
                    is_authorized=False,
                    is_blocked=True,
                    violation_code="unregistered_tool_invocation",
                    details=f"Tool '{tool_key}' is not registered in RBAC policy.",
                    role=effective_role,
                    tool_name=tool_key
                )
            return RBACValidationResult(is_authorized=True, role=effective_role, tool_name=tool_key)

        # Check explicit deny
        if effective_role in policy.denied_roles:
            return RBACValidationResult(
                is_authorized=False,
                is_blocked=True,
                violation_code="role_explicitly_denied",
                details=f"Role '{effective_role}' is explicitly denied from invoking tool '{tool_key}'.",
                role=effective_role,
                tool_name=tool_key
            )

        # Check privilege level
        caller_level = self.PRIVILEGE_HIERARCHY.get(effective_role, 0)
        if caller_level < policy.minimum_privilege_level:
            return RBACValidationResult(
                is_authorized=False,
                is_blocked=True,
                violation_code="insufficient_privilege_tier",
                details=f"Role '{effective_role}' (level {caller_level}) does not meet minimum level {policy.minimum_privilege_level} for '{tool_key}'.",
                role=effective_role,
                tool_name=tool_key
            )

        # Check allowed roles set
        if effective_role not in policy.allowed_roles and "*" not in policy.allowed_roles:
            return RBACValidationResult(
                is_authorized=False,
                is_blocked=True,
                violation_code="tool_access_forbidden",
                details=f"Role '{effective_role}' is not in allowed roles {list(policy.allowed_roles)} for tool '{tool_key}'.",
                role=effective_role,
                tool_name=tool_key
            )

        # Check destructive / requires_approval
        if policy.requires_approval and effective_role != AgentRole.SYSTEM_ADMIN.value:
            # If arguments do not contain explicit approval token
            if not arguments or not arguments.get("_supervisor_approved"):
                return RBACValidationResult(
                    is_authorized=False,
                    is_blocked=True,
                    violation_code="approval_required_for_tool",
                    details=f"Tool '{tool_key}' requires supervisor authorization token '_supervisor_approved'.",
                    role=effective_role,
                    tool_name=tool_key
                )

        return RBACValidationResult(
            is_authorized=True,
            is_blocked=False,
            role=effective_role,
            tool_name=tool_key
        )

    def validate_tool_calls(
        self,
        role: Optional[str],
        tool_calls: List[Dict[str, Any]]
    ) -> RBACValidationResult:
        """
        Validates an OpenAI / Anthropic format tool_calls list against RBAC policies.
        """
        effective_role = (role or self.default_role).lower()
        for call in tool_calls:
            function_data = call.get("function", {})
            name = function_data.get("name") or call.get("name")
            if not name:
                continue

            # Parse arguments if string
            raw_args = function_data.get("arguments") or call.get("arguments") or {}
            if isinstance(raw_args, str):
                try:
                    arguments = json.loads(raw_args)
                except Exception:
                    arguments = {}
            elif isinstance(raw_args, dict):
                arguments = raw_args
            else:
                arguments = {}

            res = self.check_tool_authorization(effective_role, name, arguments)
            if res.is_blocked:
                return res

        return RBACValidationResult(is_authorized=True, role=effective_role)

    def inspect_text_tool_attempts(self, role: Optional[str], text: str) -> RBACValidationResult:
        """
        Scans free text for simulated tool invocations (e.g. Action: execute_system_command).
        """
        effective_role = (role or self.default_role).lower()
        matches = self.RAW_TOOL_INVOCATION_PATTERN.findall(text)
        for tool_name in matches:
            tool_key = tool_name.lower().strip()
            if tool_key in self._tool_policies:
                res = self.check_tool_authorization(effective_role, tool_key)
                if res.is_blocked:
                    return res

        return RBACValidationResult(is_authorized=True, role=effective_role)
