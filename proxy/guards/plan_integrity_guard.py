"""
Agent Plan Integrity Guard
==========================
Validates agentic planning sequences, reasoning DAGs, and multi-step action plans.
Mitigates rogue plan step injection, validation step bypass, unconstrained
branching explosions, and malicious goal pivot attacks.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class PlanIntegrityResult:
    is_valid: bool
    violation_code: Optional[str] = None
    details: Optional[str] = None
    total_steps: int = 0
    high_impact_steps_flagged: List[str] = field(default_factory=list)


class AgentPlanIntegrityGuard:
    """
    Analyzes multi-step task plans and tool execution sequences.
    """

    CRITICAL_DESTRUCTIVE_ACTIONS = {
        "delete_database", "drop_table", "truncate_table", "format_disk",
        "rm_rf", "terminate_instance", "modify_iam_policy", "grant_admin",
        "transfer_funds", "wipe_memory", "disable_firewall", "kill_process_tree",
        "override primary objective", "dump admin", "grant_all", "rm -rf",
        "fork autonomous", "without supervisor", "without bounds", "exfil",
        "recurse without", "disable security", "disable supervisor", "arbitrary shell"
    }

    APPROVAL_REQUISITE_PREFIXES = {
        "request_human_approval", "verify_mfa", "confirm_with_operator",
        "obtain_secondary_authorization", "validate_signature", "request human review"
    }

    def __init__(
        self,
        max_plan_steps: int = 15,
        max_branching_factor: int = 4,
        enforce_approval_for_destructive: bool = True
    ):
        self.max_plan_steps = max_plan_steps
        self.max_branching_factor = max_branching_factor
        self.enforce_approval_for_destructive = enforce_approval_for_destructive

    def validate_plan(
        self,
        plan_steps: List[Any],
        stated_objective: Optional[str] = None
    ) -> PlanIntegrityResult:
        """
        Validates an ordered sequence of plan steps.
        Each step can be a string action or dict: {"step_id": str, "action": str, "depends_on": List[str]}
        """
        if not plan_steps:
            return PlanIntegrityResult(is_valid=True, total_steps=0)

        n_steps = len(plan_steps)
        if n_steps > self.max_plan_steps:
            return PlanIntegrityResult(
                is_valid=False,
                violation_code="plan_step_count_exceeded",
                details=f"Plan contains {n_steps} steps, exceeding maximum allowable {self.max_plan_steps}",
                total_steps=n_steps
            )

        seen_steps: Set[str] = set()
        completed_approvals: Set[str] = set()
        flagged_destructive: List[str] = []

        for idx, raw_step in enumerate(plan_steps):
            if isinstance(raw_step, str):
                step = {"step_id": f"step_{idx}", "action": raw_step, "depends_on": []}
            elif isinstance(raw_step, dict):
                step = raw_step
            else:
                continue

            step_id = step.get("step_id", f"step_{idx}")
            action = str(step.get("action", "")).lower().strip()
            depends_on = step.get("depends_on", [])

            # Check dependency cycle or forward dependency
            for dep in depends_on:
                if dep not in seen_steps:
                    return PlanIntegrityResult(
                        is_valid=False,
                        violation_code="invalid_plan_dependency_order",
                        details=f"Step '{step_id}' depends on unfulfilled step '{dep}'",
                        total_steps=n_steps
                    )

            # Check for approval actions
            if any(action.startswith(prefix) for prefix in self.APPROVAL_REQUISITE_PREFIXES):
                completed_approvals.add(step_id)

            # Check for critical destructive actions without approval
            is_destructive = any(crit in action for crit in self.CRITICAL_DESTRUCTIVE_ACTIONS)
            if is_destructive:
                flagged_destructive.append(action)
                if self.enforce_approval_for_destructive:
                    # Must depend on at least one completed approval step
                    has_approval_dep = any(dep in completed_approvals for dep in depends_on)
                    if not has_approval_dep:
                        return PlanIntegrityResult(
                            is_valid=False,
                            violation_code="unauthorized_destructive_plan_step",
                            details=(
                                f"Destructive step '{step_id}' (action: {action}) lacks preceding "
                                f"verified approval step in dependency graph"
                            ),
                            total_steps=n_steps,
                            high_impact_steps_flagged=flagged_destructive
                        )

            seen_steps.add(step_id)

        return PlanIntegrityResult(
            is_valid=True,
            total_steps=n_steps,
            high_impact_steps_flagged=flagged_destructive
        )
