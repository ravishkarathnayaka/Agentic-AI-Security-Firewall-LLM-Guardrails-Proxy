"""
Session Anti-Replay Nonce and Sliding-Window Tool Validator Guard.

Mitigates OWASP LLM08 (Excessive Agency) and authorization replay attacks in agentic systems
by validating cryptographic nonces, request timestamps, and sliding-window uniqueness across
tool invocation requests and approval signatures.
"""

import time
from dataclasses import dataclass
from typing import Optional, Dict, Set, Tuple, Any


@dataclass
class AntiReplayResult:
    is_blocked: bool
    violation_code: Optional[str] = None
    details: str = "Passed session replay validation"
    nonce: Optional[str] = None
    skew_seconds: Optional[float] = None


class SessionAntiReplayGuard:
    """
    Guards agent tools against duplicate execution and replay attacks using nonces and time windows.
    """

    NONCE_KEYS = {"nonce", "idempotency_key", "request_id", "auth_token", "tx_id"}
    TIMESTAMP_KEYS = {"timestamp", "issued_at", "created_at", "ts"}

    def __init__(
        self,
        window_seconds: float = 300.0,
        max_tracked_nonces: int = 50000
    ):
        self.window_seconds = window_seconds
        self.max_tracked_nonces = max_tracked_nonces
        # Map of (session_id, nonce) -> timestamp
        self._nonce_cache: Dict[Tuple[str, str], float] = {}

    def _purge_expired(self, current_time: float):
        """Purges nonces that fall outside the active sliding window."""
        cutoff = current_time - self.window_seconds
        expired_keys = [k for k, ts in self._nonce_cache.items() if ts < cutoff]
        for k in expired_keys:
            del self._nonce_cache[k]

    def validate_request(
        self,
        session_id: str,
        nonce: str,
        timestamp: Optional[float] = None,
        now: Optional[float] = None
    ) -> AntiReplayResult:
        """
        Validates nonce uniqueness and timestamp validity within the sliding window.
        """
        current_time = now if now is not None else time.time()
        self._purge_expired(current_time)

        if not nonce:
            return AntiReplayResult(
                is_blocked=True,
                violation_code="missing_replay_nonce",
                details="Request lacks required unique nonce or idempotency key."
            )

        # Validate timestamp skew if provided
        if timestamp is not None:
            skew = abs(current_time - timestamp)
            if skew > self.window_seconds:
                return AntiReplayResult(
                    is_blocked=True,
                    violation_code="timestamp_skew_exceeded",
                    nonce=nonce,
                    skew_seconds=skew,
                    details=f"Request timestamp skew ({skew:.1f}s) exceeds window threshold ({self.window_seconds:.1f}s)."
                )

        key = (session_id or "global", nonce)

        # Check for replay
        if key in self._nonce_cache:
            return AntiReplayResult(
                is_blocked=True,
                violation_code="replayed_authorization_detected",
                nonce=nonce,
                details=f"Replay detected: nonce '{nonce}' has already been processed for session '{session_id}'."
            )

        # Enforce memory safety cap
        if len(self._nonce_cache) >= self.max_tracked_nonces:
            # Drop oldest 10%
            sorted_items = sorted(self._nonce_cache.items(), key=lambda item: item[1])
            for k, _ in sorted_items[: self.max_tracked_nonces // 10]:
                self._nonce_cache.pop(k, None)

        self._nonce_cache[key] = current_time
        return AntiReplayResult(is_blocked=False, nonce=nonce)

    def validate_tool_call(
        self,
        session_id: str,
        tool_name: str,
        parameters: Dict[str, Any],
        now: Optional[float] = None
    ) -> AntiReplayResult:
        """
        Extracts nonce and timestamp from tool call parameters and validates anti-replay status.
        """
        if not parameters or not isinstance(parameters, dict):
            return AntiReplayResult(is_blocked=False)

        nonce = None
        for key in self.NONCE_KEYS:
            if key in parameters and parameters[key]:
                nonce = str(parameters[key])
                break

        ts = None
        for key in self.TIMESTAMP_KEYS:
            if key in parameters and parameters[key]:
                try:
                    ts = float(parameters[key])
                    break
                except (ValueError, TypeError):
                    pass

        # If a nonce is present, validate it
        if nonce:
            return self.validate_request(session_id=session_id, nonce=nonce, timestamp=ts, now=now)

        return AntiReplayResult(is_blocked=False)
