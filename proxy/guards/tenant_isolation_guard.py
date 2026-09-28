"""
Multi-Tenant Workspace and Virtual Security Zone Guard.

Mitigates OWASP ASI03 (Multi-Tenant Isolation Breach and Cross-Agent Contamination)
by enforcing virtual security zone boundaries, cross-tenant resource containment,
and workspace isolation across agent prompts and tool arguments.
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Set, List
import re


@dataclass
class TenantIsolationResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    source_tenant: Optional[str] = None
    target_tenant: Optional[str] = None
    target_resource: Optional[str] = None
    details: str = "Passed multi-tenant workspace isolation check"


class TenantIsolationGuard:
    """
    Enforces strict tenant boundary policies on agent requests and tool arguments.
    """

    # Common parameters indicating resource targets
    RESOURCE_PARAM_KEYS = {
        "tenant_id", "workspace_id", "bucket", "database", "schema",
        "table", "directory", "partition", "account_id", "project_id"
    }

    def __init__(self, enforce_isolation: bool = True):
        self.enforce_isolation = enforce_isolation
        self._tenant_workspaces: Dict[str, Set[str]] = {
            "default": {"default", "public"},
            "finance_dept": {"finance", "accounting", "payroll", "public"},
            "engineering_dept": {"engineering", "devops", "codebase", "public"},
            "hr_dept": {"hr", "recruiting", "benefits", "public"},
        }

    def register_tenant(self, tenant_id: str, allowed_zones: Set[str]):
        """Registers allowed security zones for a tenant."""
        self._tenant_workspaces[tenant_id] = allowed_zones

    def inspect_request_metadata(
        self,
        tenant_id: str,
        requested_zone: str
    ) -> TenantIsolationResult:
        """Verifies if tenant is permitted to operate in the requested zone."""
        if not self.enforce_isolation:
            return TenantIsolationResult(is_blocked=False)

        allowed = self._tenant_workspaces.get(tenant_id, {"public"})
        if requested_zone not in allowed and "*" not in allowed:
            return TenantIsolationResult(
                is_blocked=True,
                violation_code="unauthorized_security_zone_access",
                source_tenant=tenant_id,
                target_tenant=requested_zone,
                details=f"Tenant '{tenant_id}' is not authorized to access security zone '{requested_zone}' (allowed: {allowed})."
            )

        return TenantIsolationResult(
            is_blocked=False,
            source_tenant=tenant_id,
            target_tenant=requested_zone
        )

    def inspect_tool_call(
        self,
        caller_tenant: str,
        tool_name: str,
        parameters: Dict[str, Any]
    ) -> TenantIsolationResult:
        """Inspects tool parameters to prevent cross-tenant data contamination."""
        if not self.enforce_isolation:
            return TenantIsolationResult(is_blocked=False)

        if not parameters or not isinstance(parameters, dict):
            return TenantIsolationResult(is_blocked=False)

        caller_clean = caller_tenant.strip().lower()

        for key, val in parameters.items():
            if not isinstance(val, str):
                continue
            val_clean = val.strip().lower()

            # 1. Parameter explicitly specifies a tenant or workspace
            if key.lower() in ("tenant_id", "tenant", "workspace_id", "workspace"):
                if val_clean != caller_clean and val_clean not in ("public", "default"):
                    return TenantIsolationResult(
                        is_blocked=True,
                        violation_code="cross_tenant_parameter_manipulation",
                        source_tenant=caller_tenant,
                        target_tenant=val,
                        target_resource=f"{key}={val}",
                        details=f"Cross-tenant parameter manipulation: caller '{caller_tenant}' attempted access to tenant '{val}'."
                    )

            # 2. Check for resource naming prefix mismatch (e.g. s3://tenantB-data/ or db_tenantB)
            # Common pattern: tenant names embedded in bucket/table paths
            for other_tenant in self._tenant_workspaces:
                if other_tenant in ("default", "public") or other_tenant == caller_clean:
                    continue
                # If target resource explicitly references another private tenant
                if re.search(rf"\b{re.escape(other_tenant)}\b", val_clean):
                    # Check if caller has access to that other tenant's zone
                    caller_zones = self._tenant_workspaces.get(caller_clean, set())
                    if other_tenant not in caller_zones:
                        return TenantIsolationResult(
                            is_blocked=True,
                            violation_code="cross_tenant_resource_access",
                            source_tenant=caller_tenant,
                            target_tenant=other_tenant,
                            target_resource=val,
                            details=f"Cross-tenant resource access blocked: caller '{caller_tenant}' accessed resource belonging to '{other_tenant}'."
                        )

        return TenantIsolationResult(is_blocked=False, source_tenant=caller_tenant)
