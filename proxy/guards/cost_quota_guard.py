"""
Agent Tool Call Rate and Cost Quota Limiter Guard.

Mitigates OWASP LLM04 (Model Denial of Service / Denial of Wallet) and
ASI08 (Resource and Financial Exhaustion) by tracking cumulative token consumption,
external API tool invocation costs, and enforcing strict session budget quotas.
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
import time


@dataclass
class CostQuotaResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    current_cost_usd: float = 0.0
    budget_limit_usd: float = 0.0
    total_tokens_used: int = 0
    token_limit: int = 0
    details: str = "Passed cost and resource quota validation"


class CostQuotaGuard:
    """
    Enforces financial and resource consumption limits per session and client.
    """

    # Estimated cost table per unit
    DEFAULT_TOOL_COSTS: Dict[str, float] = {
        "web_search": 0.015,
        "fetch_url": 0.005,
        "execute_code": 0.025,
        "database_query": 0.010,
        "send_email": 0.005,
        "delete_database_records": 0.020,
        "modify_iam_policy": 0.030,
    }

    # Token cost model per 1k tokens (approximate blended $0.003 / 1k)
    TOKEN_COST_PER_1K: float = 0.003

    def __init__(
        self,
        default_session_budget_usd: float = 2.50,
        default_session_token_limit: int = 150000,
        enforce_quotas: bool = True
    ):
        self.default_session_budget_usd = default_session_budget_usd
        self.default_session_token_limit = default_session_token_limit
        self.enforce_quotas = enforce_quotas
        self._session_costs: Dict[str, float] = {}
        self._session_tokens: Dict[str, int] = {}
        self._session_last_active: Dict[str, float] = {}

    def _purge_stale_sessions(self, max_age_seconds: float = 3600.0):
        now = time.time()
        stale_keys = [k for k, last in self._session_last_active.items() if now - last > max_age_seconds]
        for k in stale_keys:
            self._session_costs.pop(k, None)
            self._session_tokens.pop(k, None)
            self._session_last_active.pop(k, None)

    def estimate_text_tokens(self, text: str) -> int:
        """Heuristic token count based on character and whitespace distribution."""
        if not text:
            return 0
        return max(1, len(text) // 4)

    def record_usage(
        self,
        session_id: str,
        tokens: int = 0,
        additional_cost_usd: float = 0.0
    ):
        """Record token and dollar expenditure against a session."""
        self._purge_stale_sessions()
        current_cost = self._session_costs.get(session_id, 0.0)
        current_tokens = self._session_tokens.get(session_id, 0)
        
        token_cost = (tokens / 1000.0) * self.TOKEN_COST_PER_1K
        total_increment = token_cost + additional_cost_usd

        self._session_costs[session_id] = current_cost + total_increment
        self._session_tokens[session_id] = current_tokens + tokens
        self._session_last_active[session_id] = time.time()

    def check_inbound_budget(
        self,
        session_id: str,
        prompt_text: str,
        custom_budget_usd: Optional[float] = None,
        custom_token_limit: Optional[int] = None
    ) -> CostQuotaResult:
        """Verifies session cost before admitting request into the model."""
        if not self.enforce_quotas:
            return CostQuotaResult(is_blocked=False)

        self._purge_stale_sessions()
        budget = custom_budget_usd if custom_budget_usd is not None else self.default_session_budget_usd
        max_tokens = custom_token_limit if custom_token_limit is not None else self.default_session_token_limit

        current_cost = self._session_costs.get(session_id, 0.0)
        current_tokens = self._session_tokens.get(session_id, 0)

        # Estimate incoming prompt tokens
        estimated_prompt_tokens = self.estimate_text_tokens(prompt_text)
        projected_tokens = current_tokens + estimated_prompt_tokens
        projected_cost = current_cost + ((estimated_prompt_tokens / 1000.0) * self.TOKEN_COST_PER_1K)

        if projected_cost > budget:
            return CostQuotaResult(
                is_blocked=True,
                violation_code="session_budget_exceeded",
                current_cost_usd=round(projected_cost, 4),
                budget_limit_usd=budget,
                total_tokens_used=projected_tokens,
                token_limit=max_tokens,
                details=f"Session cost ${projected_cost:.4f} exceeds allowed quota ${budget:.2f} USD."
            )

        if projected_tokens > max_tokens:
            return CostQuotaResult(
                is_blocked=True,
                violation_code="session_token_limit_exceeded",
                current_cost_usd=round(projected_cost, 4),
                budget_limit_usd=budget,
                total_tokens_used=projected_tokens,
                token_limit=max_tokens,
                details=f"Session token usage {projected_tokens} exceeds allowed ceiling {max_tokens} tokens."
            )

        return CostQuotaResult(
            is_blocked=False,
            current_cost_usd=round(current_cost, 4),
            budget_limit_usd=budget,
            total_tokens_used=current_tokens,
            token_limit=max_tokens
        )

    def check_tool_invocation_cost(
        self,
        session_id: str,
        tool_name: str,
        custom_budget_usd: Optional[float] = None
    ) -> CostQuotaResult:
        """Checks if invoking the specified tool will exceed remaining budget quota."""
        if not self.enforce_quotas:
            return CostQuotaResult(is_blocked=False)

        budget = custom_budget_usd if custom_budget_usd is not None else self.default_session_budget_usd
        current_cost = self._session_costs.get(session_id, 0.0)
        tool_cost = self.DEFAULT_TOOL_COSTS.get(tool_name.lower(), 0.010)

        if current_cost + tool_cost > budget:
            return CostQuotaResult(
                is_blocked=True,
                violation_code="tool_cost_quota_exceeded",
                current_cost_usd=round(current_cost + tool_cost, 4),
                budget_limit_usd=budget,
                details=f"Tool '{tool_name}' cost (${tool_cost:.4f}) breaches remaining session budget (${budget - current_cost:.4f} left)."
            )

        return CostQuotaResult(
            is_blocked=False,
            current_cost_usd=round(current_cost, 4),
            budget_limit_usd=budget
        )
