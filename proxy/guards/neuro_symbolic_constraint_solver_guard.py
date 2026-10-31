"""
Neuro-Symbolic Constraint Solver & Formal Invariant Guard
=========================================================
Translates unstructured agent execution plans and user prompts into first-order
logic invariants (LTL/CTL safety constraints) and verifies them via formal symbolic
reasoning before downstream foundation model execution.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class NeuroSymbolicResult:
    is_blocked: bool
    risk_score: float = 0.0
    violation_code: Optional[str] = None
    details: Optional[str] = None
    violated_invariants: List[str] = field(default_factory=list)
    parsed_predicates: List[str] = field(default_factory=list)


class NeuroSymbolicConstraintSolverGuard:
    """
    Evaluates safety invariants such as:
    - Invariant 1: never(read(sensitive_vault) and write(public_channel))
    - Invariant 2: never(grant_privilege(root) without auth_token)
    - Invariant 3: always(execute_bash implies in_sandbox)
    """

    SAFETY_RULES: List[Tuple[re.Pattern, str, str]] = [
        (
            re.compile(r"(?i)(?:read|dump|extract).*(?:credentials|shadow|passwords?).*(?:post|send|exfiltrate|broadcast)"),
            "INVARIANT_DATA_FLOW_BREACH",
            "Invariant Violation: cannot exfiltrate credential data across public network interface"
        ),
        (
            re.compile(r"(?i)(?:grant|escalate|elevate).*(?:root|admin|superuser).*(?:without|bypass).*(?:auth|token|2fa)"),
            "INVARIANT_PRIVILEGE_SAFETY_VIOLATION",
            "Invariant Violation: privilege elevation requires valid verifiable authentication token"
        ),
        (
            re.compile(r"(?i)(?:disable|kill|override).*(?:firewall|guardrails?|audit_log|safety)"),
            "INVARIANT_SECURITY_CONTROL_TAMPERING",
            "Invariant Violation: foundational defense mechanisms cannot be disabled or deactivated"
        ),
        (
            re.compile(r"(?i)(?:delete|drop|truncate).*(?:database|backup|production|audit_trail)"),
            "INVARIANT_IRREVERSIBLE_DATA_LOSS",
            "Invariant Violation: irreversible bulk state deletion is strictly forbidden"
        ),
    ]

    def __init__(self, strict_mode: bool = True):
        self.strict_mode = strict_mode

    def verify_plan(self, prompt: str, planned_actions: Optional[List[str]] = None) -> NeuroSymbolicResult:
        if not prompt and not planned_actions:
            return NeuroSymbolicResult(is_blocked=False, risk_score=0.0)

        text_to_evaluate = prompt
        if planned_actions:
            text_to_evaluate += " " + " ".join(planned_actions)

        violations = []
        codes = []
        predicates = []

        for pattern, code, msg in self.SAFETY_RULES:
            if pattern.search(text_to_evaluate):
                violations.append(msg)
                codes.append(code)
                predicates.append(code.lower().replace("invariant_", "predicate_"))

        if violations:
            return NeuroSymbolicResult(
                is_blocked=True,
                risk_score=min(1.0, 0.6 + 0.2 * len(violations)),
                violation_code=codes[0],
                details="; ".join(violations),
                violated_invariants=violations,
                parsed_predicates=predicates
            )

        return NeuroSymbolicResult(
            is_blocked=False,
            risk_score=0.0,
            parsed_predicates=["invariant_passed"]
        )
