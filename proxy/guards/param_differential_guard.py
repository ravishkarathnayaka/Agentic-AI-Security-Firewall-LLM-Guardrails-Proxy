"""
Agent Tool Parameter Semantic Differential Validator.

Mitigates OWASP LLM08 (Excessive Agency & Confused Deputy) by validating semantic
coherence between the original user intent/prompt and downstream model-generated
tool invocations, detecting unauthorized tool drift and unprompted destructive actions.
"""

import re
from dataclasses import dataclass
from typing import Optional, Dict, Any, Set, List


@dataclass
class ParamDifferentialResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    divergence_score: float = 0.0
    details: str = "Passed tool parameter differential check"


class ParamDifferentialGuard:
    """
    Validates that model tool calls align with user request permissions and intent scope.
    """

    DESTRUCTIVE_TOOL_NAMES = {
        "delete_database_records",
        "drop_table",
        "modify_iam_policy",
        "execute_system_command",
        "terminate_instance",
        "wipe_storage",
        "format_disk",
    }

    READONLY_INTENT_STEMS = {
        "read", "view", "get", "fetch", "check", "show", "display",
        "summarize", "find", "search", "weather", "calculate", "list", "query"
    }

    DESTRUCTIVE_INTENT_STEMS = {
        "delete", "remove", "drop", "purge", "erase", "terminate", "destroy", "format"
    }

    def __init__(self, block_on_divergence: bool = True):
        self.block_on_divergence = block_on_divergence

    def _extract_intent_stems(self, text: str) -> Set[str]:
        words = re.findall(r"\b[a-zA-Z]{3,}\b", text.lower())
        return set(words)

    def inspect_differential(
        self,
        user_prompt: str,
        tool_name: str,
        parameters: Optional[Dict[str, Any]] = None
    ) -> ParamDifferentialResult:
        """
        Compares user prompt intent against the invoked tool and its parameters.
        """
        if not user_prompt or not tool_name:
            return ParamDifferentialResult(is_blocked=False)

        tool_clean = tool_name.strip().lower()
        prompt_stems = self._extract_intent_stems(user_prompt)

        has_readonly_intent = bool(prompt_stems.intersection(self.READONLY_INTENT_STEMS))
        has_destructive_intent = bool(prompt_stems.intersection(self.DESTRUCTIVE_INTENT_STEMS))

        # 1. Unprompted Destructive Tool Check
        if tool_clean in self.DESTRUCTIVE_TOOL_NAMES and not has_destructive_intent:
            return ParamDifferentialResult(
                is_blocked=self.block_on_divergence,
                violation_code="unprompted_destructive_tool_invocation",
                divergence_score=1.0,
                details=f"Model attempted to invoke destructive tool '{tool_name}' for read-only user request: '{user_prompt[:60]}...'"
            )

        # 2. Destructive SQL / Shell arguments when user only requested read/view
        if parameters and isinstance(parameters, dict):
            for k, val in parameters.items():
                if isinstance(val, str):
                    val_lower = val.lower()
                    if ("drop table" in val_lower or "rm -rf" in val_lower or "delete from" in val_lower) and not has_destructive_intent:
                        return ParamDifferentialResult(
                            is_blocked=self.block_on_divergence,
                            violation_code="destructive_argument_intent_divergence",
                            divergence_score=0.95,
                            details=f"Destructive action in argument '{k}' diverges from non-destructive user request."
                        )

        return ParamDifferentialResult(is_blocked=False, divergence_score=0.0)
