"""
Agent Subgoal Divergence & Rogue Planning Guard
==============================================
Validates that autonomous agent task breakdowns, intermediate subgoals, and planned
action sequences strictly serve the user's primary goal and have not been hijacked.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Set


@dataclass
class SubgoalDivergenceResult:
    is_blocked: bool
    divergence_score: float = 0.0
    violation_code: Optional[str] = None
    details: Optional[str] = None
    flagged_subgoals: List[str] = field(default_factory=list)


class AgentSubgoalDivergenceGuard:
    """
    Detects goal misalignment, unauthorized privilege escalation steps, and rogue
    side effects within generated multi-step agent plans.
    """

    FORBIDDEN_ROGUE_ACTIONS = [
        (r"(?i)(?:exfiltrat|steal|leak|dump\s+database|harvest\s+credentials)", "UNAUTHORIZED_DATA_EXFILTRATION"),
        (r"(?i)(?:disable\s+firewall|stop\s+guardrails|kill\s+process|uninstall\s+agent)", "DEFENSE_EVASION_SUBGOAL"),
        (r"(?i)(?:create\s+backdoor|open\s+reverse\s+shell|nc\s+-e|bash\s+-i)", "COMMAND_CONTROL_ESTABLISHMENT"),
        (r"(?i)(?:transfer\s+funds|mint\s+tokens|drain\s+wallet)", "FINANCIAL_FRAUD_SUBGOAL"),
        (r"(?i)(?:change\s+root\s+password|add\s+sudoer|modify\s+permissions)", "PRIVILEGE_ESCALATION_SUBGOAL"),
    ]

    def __init__(self, max_allowed_divergence: float = 0.5):
        self.max_divergence = max_allowed_divergence
        self.forbidden_patterns = [(re.compile(p), code) for p, code in self.FORBIDDEN_ROGUE_ACTIONS]

    def evaluate_plan(self, primary_intent: str, planned_subgoals: List[str]) -> SubgoalDivergenceResult:
        if not planned_subgoals:
            return SubgoalDivergenceResult(is_blocked=False, divergence_score=0.0)

        flagged = []
        violation_codes = []

        primary_tokens = set(re.findall(r"\w{3,}", primary_intent.lower()))

        for i, subgoal in enumerate(planned_subgoals):
            subgoal_clean = subgoal.strip()
            # 1. Check for known rogue action patterns
            for pattern, code in self.forbidden_patterns:
                if pattern.search(subgoal_clean):
                    flagged.append(f"Step {i+1}: {subgoal_clean} ({code})")
                    violation_codes.append(code)

            # 2. Check semantic token divergence from root intent
            step_tokens = set(re.findall(r"\w{3,}", subgoal_clean.lower()))
            overlap = primary_tokens.intersection(step_tokens)
            # If no common context and contains sensitive verbs
            if not overlap and re.search(r"(?i)(?:system|admin|root|credential|token|network|proxy)", subgoal_clean):
                flagged.append(f"Step {i+1}: Non-aligned sensitive action: {subgoal_clean}")
                violation_codes.append("CONTEXT_DISCONNECTED_SENSITIVE_ACTION")

        total_steps = len(planned_subgoals)
        divergence_ratio = len(flagged) / total_steps if total_steps > 0 else 0.0

        if flagged or divergence_ratio > self.max_divergence:
            return SubgoalDivergenceResult(
                is_blocked=True,
                divergence_score=min(1.0, divergence_ratio + 0.3),
                violation_code=violation_codes[0] if violation_codes else "SUBGOAL_DIVERGENCE_EXCEEDED",
                details=f"Autonomous plan diverged from primary intent with {len(flagged)} flagged subgoals.",
                flagged_subgoals=flagged
            )

        return SubgoalDivergenceResult(
            is_blocked=False,
            divergence_score=divergence_ratio
        )
