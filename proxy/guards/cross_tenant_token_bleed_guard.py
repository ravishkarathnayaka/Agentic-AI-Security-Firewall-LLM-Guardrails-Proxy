"""
Cross-Tenant Token Bleed & Memory Residue Defense Guard
=======================================================
Inspects model inference responses and conversation context buffers for residual
memory tokens, leaked tenant identifiers, and foreign session metadata originating
from adjacent tenants sharing the proxy worker infrastructure.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class TokenBleedResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    details: Optional[str] = None
    leaked_tenant_id: Optional[str] = None
    matched_patterns: List[str] = field(default_factory=list)


class CrossTenantTokenBleedGuard:
    """
    Prevents token bleed across tenants by indexing active tenant signatures,
    secret headers, and session tokens, scanning response payloads for foreign leakage.
    """

    RESIDUAL_MEMORY_MARKERS = [
        re.compile(r"\[PREV_SESSION_CONTEXT:[^\]]+\]", re.IGNORECASE),
        re.compile(r"system_prompt_override_tenant_\w+", re.IGNORECASE),
        re.compile(r"BEGIN_TENANT_ISOLATED_PROMPT_\w+", re.IGNORECASE),
        re.compile(r"tenant_id=([a-zA-Z0-9_\-]+)", re.IGNORECASE),
    ]

    def __init__(
        self,
        strict_boundary_enforcement: bool = True,
    ):
        self.strict_boundary_enforcement = strict_boundary_enforcement
        # tenant_id -> set of registered private tokens / session keys
        self._tenant_signatures: Dict[str, Set[str]] = {}

    def register_tenant_signature(
        self,
        tenant_id: str,
        private_identifiers: List[str],
    ) -> None:
        """Registers private tokens or identifiers belonging to a specific tenant."""
        self._tenant_signatures[tenant_id] = set(private_identifiers)

    def scan_response_for_bleed(
        self,
        current_tenant_id: str,
        response_text: str,
    ) -> TokenBleedResult:
        """
        Validates that the response payload returned to `current_tenant_id` does not contain
        private tokens or signatures belonging to any other tenant.
        """
        if not response_text:
            return TokenBleedResult(is_blocked=False)

        # Check for system memory leak delimiters
        for marker in self.RESIDUAL_MEMORY_MARKERS:
            match = marker.search(response_text)
            if match:
                matched_val = match.group(0)
                # If matched pattern exposes a foreign tenant_id
                if "tenant_id=" in matched_val.lower():
                    tid = match.group(1) if match.groups() else ""
                    if tid and tid != current_tenant_id:
                        return TokenBleedResult(
                            is_blocked=True,
                            violation_code="CROSS_TENANT_ID_EXPOSURE",
                            details=f"Foreign tenant identifier '{tid}' leaked in model response",
                            leaked_tenant_id=tid,
                            matched_patterns=[matched_val],
                        )

        # Scan against other tenants' private registered signatures
        for other_tenant, signatures in self._tenant_signatures.items():
            if other_tenant == current_tenant_id:
                continue
            for sig in signatures:
                if len(sig) >= 6 and sig in response_text:
                    return TokenBleedResult(
                        is_blocked=True,
                        violation_code="CROSS_TENANT_TOKEN_BLEED_DETECTED",
                        details=(
                            f"Model output contains private signature belonging to foreign "
                            f"tenant '{other_tenant}'"
                        ),
                        leaked_tenant_id=other_tenant,
                        matched_patterns=[sig],
                    )

        return TokenBleedResult(is_blocked=False)

    def reset(self) -> None:
        self._tenant_signatures.clear()
