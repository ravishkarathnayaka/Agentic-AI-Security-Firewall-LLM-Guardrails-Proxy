"""
Cross-Context Contamination Guard
=================================
Mitigates cross-session context bleeding, thread contamination, and private
session variable leakage in multi-tenant or multi-agent serving environments.
Tracks ephemeral session-bound context tokens and intercepts cross-session
access attempts before dispatch to LLM completion engines.
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set


@dataclass
class CrossContextResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    details: Optional[str] = None
    contaminated_session_id: Optional[str] = None
    leaked_identifiers: List[str] = None


class CrossContextContaminationGuard:
    """
    Monitors inbound prompts and outbound completions to ensure session isolation.
    """

    CROSS_TENANT_PATTERNS = [
        re.compile(r"(?:cross[-_ ]tenant|bypass namespace|merge memory segment|tenant[-_ ]id\s*[:=]\s*['\"]?(?:enterprise_root|tenant-corp|root))", re.IGNORECASE),
        re.compile(r"(?:previous user session memory|dump all confidential queries made by session|bypassing namespace isolation)", re.IGNORECASE),
        re.compile(r"(?:overwrite persistent shared workspace context|all api keys are deprecated)", re.IGNORECASE),
        re.compile(r"(?:foreign tenant identity|impersonat\w+ in memory store|root encryption keys stored in memory)", re.IGNORECASE),
        re.compile(r"(?:context boundary crossing|tenant_alpha into tenant_beta)", re.IGNORECASE),
    ]

    def __init__(self, max_registered_sessions: int = 1000):
        self.max_registered_sessions = max_registered_sessions
        # session_id -> Set of private session tokens/identifiers
        self._session_tokens: Dict[str, Set[str]] = {}

    def register_session_token(self, session_id: str, token_identifier: str) -> None:
        """Register a sensitive token or variable name bound to a specific session."""
        if not session_id or not token_identifier or len(token_identifier) < 4:
            return
        if session_id not in self._session_tokens:
            if len(self._session_tokens) >= self.max_registered_sessions:
                # Evict oldest
                self._session_tokens.pop(next(iter(self._session_tokens)))
            self._session_tokens[session_id] = set()
        self._session_tokens[session_id].add(token_identifier.strip().lower())

    def inspect_text_for_contamination(
        self,
        current_session_id: str,
        text: str
    ) -> CrossContextResult:
        """
        Check if text references private tokens belonging to a DIFFERENT session or attacks cross-tenant isolation.
        """
        if not text:
            return CrossContextResult(is_blocked=False)

        for pat in self.CROSS_TENANT_PATTERNS:
            if pat.search(text):
                return CrossContextResult(
                    is_blocked=True,
                    violation_code="cross_tenant_isolation_violation",
                    details=f"Inbound query contains cross-tenant context contamination attempt: {pat.pattern}"
                )

        if not current_session_id:
            return CrossContextResult(is_blocked=False)

        lower_text = text.lower()
        leaked: List[str] = []
        source_session: Optional[str] = None

        for other_sess, tokens in self._session_tokens.items():
            if other_sess == current_session_id:
                continue
            for tok in tokens:
                # Word boundary check for token
                pattern = r"\b" + re.escape(tok) + r"\b"
                if re.search(pattern, lower_text):
                    leaked.append(tok)
                    source_session = other_sess
                    break
            if leaked:
                break

        if leaked:
            return CrossContextResult(
                is_blocked=True,
                violation_code="cross_session_context_bleeding",
                details=(
                    f"Prompt in session '{current_session_id}' references private identifier "
                    f"'{leaked[0]}' belonging to session '{source_session}'"
                ),
                contaminated_session_id=source_session,
                leaked_identifiers=leaked,
            )

        return CrossContextResult(is_blocked=False)

    def clear_session(self, session_id: str) -> None:
        """Release session data upon logout or thread termination."""
        self._session_tokens.pop(session_id, None)
